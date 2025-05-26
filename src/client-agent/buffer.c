/*
 * Anti-flooding mechanism
 * Copyright (C) 2015, Wazuh Inc.
 * July 4, 2017
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include <pthread.h>
#include <stdlib.h> // For realloc, free
#include <string.h> // For strdup, strerror
#include <errno.h>  // For errno
#include <time.h>   // For time()

#include "shared.h"
#include "agentd.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

// --- Global/Static Variables for Buffer Management ---
STATIC volatile int i = 0; // Head index (where new messages are added)
STATIC volatile int j = 0; // Tail index (where messages are read/removed)
STATIC volatile unsigned int message_count = 0; // NEW: Tracks actual number of messages in buffer

static volatile int state = NORMAL; // Buffer state (NORMAL, WARNING, FULL, FLOOD)

// Configuration levels (read from agentd.h or config)
unsigned int warn_level;
unsigned int normal_level;
unsigned int tolerance;

// Buffer status flags
struct{
  unsigned int full:1;
  unsigned int warn:1;
  unsigned int flood:1;
  unsigned int normal:1; // Already exists, tracks return to normal
} buff;

// The actual buffer (array of char pointers)
static char ** buffer = NULL; // Initialize to NULL for dynamic allocation
static unsigned int current_capacity = 0; // NEW: Tracks the current allocated size of 'buffer'

// Mutex and Condition Variable for thread safety
static pthread_mutex_t mutex_lock;
static pthread_cond_t cond_no_empty;

static time_t start, end; // Timestamps for flood control

// --- Helper Functions (Updated for Dynamic Buffer) ---

/**
 * @brief Checks if the buffer is logically full.
 * Assumes one slot is always left empty to distinguish full from empty in circular buffer.
 * @param count Current number of messages in the buffer.
 * @param capacity The total allocated capacity of the buffer.
 * @return 1 if full, 0 otherwise.
 */
int full(unsigned int count, unsigned int capacity) {
    return (count == (capacity - 1));
}

/**
 * @brief Checks if the buffer is logically empty.
 * @param count Current number of messages in the buffer.
 * @return 1 if empty, 0 otherwise.
 */
int empty(unsigned int count) {
    return (count == 0);
}

/**
 * @brief Checks if the buffer is at a warning level.
 * @param count Current number of messages in the buffer.
 * @param capacity The total allocated capacity of the buffer.
 * @return 1 if at warning level, 0 otherwise.
 */
int warn(unsigned int count, unsigned int capacity) {
    if (capacity <= 1) return 0; // Avoid division by zero
    return (count * 100 / (capacity - 1) >= warn_level);
}

/**
 * @brief Checks if the buffer is no longer at a warning level (i.e., below).
 * @param count Current number of messages in the buffer.
 * @param capacity The total allocated capacity of the buffer.
 * @return 1 if below warning level, 0 otherwise.
 */
int nowarn(unsigned int count, unsigned int capacity) {
    if (capacity <= 1) return 1; // Considered no-warn if capacity is too small
    return (count * 100 / (capacity - 1) < warn_level);
}

/**
 * @brief Checks if the buffer has returned to a normal level.
 * @param count Current number of messages in the buffer.
 * @param capacity The total allocated capacity of the buffer.
 * @return 1 if at normal level, 0 otherwise.
 */
int normal(unsigned int count, unsigned int capacity) {
    if (capacity <= 1) return 1; // Considered normal if capacity is too small
    return (count * 100 / (capacity - 1) <= normal_level);
}

/**
 * @brief Advances a circular buffer index.
 * @param idx Pointer to the index to advance.
 * @param capacity The total allocated capacity of the buffer.
 */
void forward(volatile int *idx, unsigned int capacity) {
    *idx = (*idx + 1) % capacity;
}


/**
 * @brief Dynamically resizes the internal buffer.
 * This function should only be called while the mutex is locked.
 * @param new_capacity The desired new total allocated capacity.
 * @return 0 on success, -1 on failure.
 */
STATIC int resize_internal_buffer(unsigned int new_capacity) {
    if (new_capacity == 0 || new_capacity > MAX_BUFFER_CAPACITY) { // Define MAX_BUFFER_CAPACITY in buffer.h or similar
        merror("%s: Invalid or excessive new buffer capacity requested: %u.", __func__, new_capacity);
        return -1;
    }

    // Attempt to reallocate the buffer
    char **new_buffer_ptr = (char **)realloc(buffer, new_capacity * sizeof(char *));
    if (new_buffer_ptr == NULL) {
        merror("%s: Failed to reallocate client buffer to %u elements. Error: %s", __func__, new_capacity, strerror(errno));
        return -1;
    }

    buffer = new_buffer_ptr; // Update the global pointer

    // If capacity increased, initialize new pointers to NULL to prevent dangling
    if (new_capacity > current_capacity) {
        for (unsigned int k = current_capacity; k < new_capacity; k++) {
            buffer[k] = NULL;
        }
    }
    // Note: If capacity decreased, elements might be truncated.
    // For a circular buffer, it's safer to only grow, or to implement
    // a more complex "shrink" that copies elements if needed.

    mdebug1("%s: Client buffer resized from %u to %u elements.", __func__, current_capacity, new_capacity);
    current_capacity = new_capacity;
    return 0;
}

/**
 * @brief Sleep according to max_eps parameter
 *
 * Sleep (1 / max_eps) - ts_loop
 *
 * @param ts_loop Loop time.
 */
static void delay(struct timespec * ts_loop); // Keep declaration here, definition below

/* Create agent buffer */
void buffer_init(){
    // Use agt->buflength for initial capacity + 1 (for circular buffer empty slot)
    // The configured buffer length (agt->buflength) determines the *usable* slots,
    // so the actual allocated array size needs to be +1 for circular buffer logic.
    unsigned int desired_capacity = agt->buflength + 1;

    // Initialize mutex and condition variable (ensure they are only initialized once)
    // The w_mutex_init and w_cond_init typically handle re-initialization safely,
    // but in some pthreads implementations, re-initializing an already locked mutex can deadlock.
    // Assuming Wazuh's wrappers are robust for this.
    w_mutex_init(&mutex_lock, NULL);
    w_cond_init(&cond_no_empty, NULL);

    w_mutex_lock(&mutex_lock); // Lock before modifying shared buffer state

    // Only reallocate if buffer is not initialized or desired capacity has changed
    if (buffer == NULL || desired_capacity != current_capacity) {
        // Free existing buffer content if re-initializing with different size
        if (buffer != NULL) {
            // Free all strings in the old buffer before reallocating/freeing the buffer itself
            for (unsigned int k = 0; k < current_capacity; k++) {
                if (buffer[k] != NULL) {
                    free(buffer[k]);
                    buffer[k] = NULL;
                }
            }
        }
        // Resize will handle the allocation and setting current_capacity
        if (resize_internal_buffer(desired_capacity) != 0) {
            merror("%s: FATAL: Failed to initialize client buffer. Exiting.", __func__);
            w_mutex_unlock(&mutex_lock);
            exit(1); // Fatal error, cannot proceed without buffer
        }
    }

    // Reset indices and count for new buffer or re-initialization
    i = 0; // Head index
    j = 0; // Tail index
    message_count = 0; // Current number of messages
    state = NORMAL; // Reset buffer state

    // Reset buffer flags
    buff.full = 0;
    buff.warn = 0;
    buff.flood = 0;
    buff.normal = 0;

    /* Read internal configuration */
    warn_level = getDefine_Int("agent", "warn_level", 1, 100);
    normal_level = getDefine_Int("agent", "normal_level", 0, warn_level - 1);
    tolerance = getDefine_Int("agent", "tolerance", 0, 600);

    if (tolerance == 0) {
        mwarn(TOLERANCE_TIME); // Assuming TOLERANCE_TIME is a defined warning string
    }

    mdebug1("Agent buffer created/re-initialized with capacity: %u (usable: %u).", current_capacity, agt->buflength);
    w_mutex_unlock(&mutex_lock); // Unlock after initialization
}

int buffer_is_full() {
    w_mutex_lock(&mutex_lock);
    int status = full(message_count, current_capacity);
    w_mutex_unlock(&mutex_lock);
    return status;
}


int buffer_is_empty() {
    w_mutex_lock(&mutex_lock);
    int status = empty(message_count);
    w_mutex_unlock(&mutex_lock);
    return status;
}

/* Send messages to buffer. */
int buffer_append(const char *msg){

    w_mutex_lock(&mutex_lock); // Lock for thread safety
    // ---  Dynamic Resizing Logic 
    // Attempt to resize when in WARNING state and not yet at max capacity.
    // This is the best place to prevent entering FULL state.
    if (state == WARNING || (state == NORMAL && warn(message_count, current_capacity))) {
        // Calculate the new desired capacity. Example: double, but cap at MAX.
        unsigned int new_desired_capacity = current_capacity * 2;
        if (new_desired_capacity < MIN_BUFFER_CAPACITY) { // Ensure a minimum to avoid shrinking too small
             new_desired_capacity = MIN_BUFFER_CAPACITY;
        }
        if (new_desired_capacity > MAX_BUFFER_CAPACITY) {
            new_desired_capacity = MAX_BUFFER_CAPACITY;
        }

        // Only attempt resize if there's actual growth potential
        if (new_desired_capacity > current_capacity) {
            minfo("Client buffer nearing capacity (%u/%u). Attempting to resize to %u.",
                  message_count, current_capacity, new_desired_capacity);
            if (resize_internal_buffer(new_desired_capacity) != 0) {
                // Resize failed. Log a warning, but don't exit.
                mwarn("Failed to dynamically resize client buffer to %u. Check memory or MAX_BUFFER_CAPACITY. Messages might be dropped.", new_desired_capacity);
                // The buffer might still be functional at its old capacity, so we continue.
            } else {
                // Successfully resized, current_capacity is updated by resize_internal_buffer
                minfo("Client buffer successfully resized to %u (message count: %u).", current_capacity, message_count);
                // After successful resize, the state might change. Re-evaluate.
                // The state machine below will handle the state transition based on new capacity.
            }
        } else if (current_capacity >= MAX_BUFFER_CAPACITY && full(message_count, current_capacity)) {
            // Already at max capacity and full, cannot resize further.
            mwarn("Client buffer is at MAX_BUFFER_CAPACITY (%u) and full. Messages will be dropped.", MAX_BUFFER_CAPACITY);
        }
    }

    /* Check if buffer usage reaches any higher level */
    switch (state) {
        case NORMAL:
            if (full(message_count, current_capacity)){
                buff.full = 1;
                state = FULL;
                start = time(NULL); // Use time(NULL) for current time
            }else if (warn(message_count, current_capacity)){
                state = WARNING;
                buff.warn = 1;
            }
            break;

        case WARNING:
            if (full(message_count, current_capacity)){
                buff.full = 1;
                state = FULL;
                start = time(NULL);
            } else if (normal(message_count, current_capacity)) { // Back to NORMAL from WARNING
                state = NORMAL;
                buff.warn = 0; // Clear warning flag
                buff.normal = 1; // Signal return to normal
            }
            break;

        case FULL:
            end = time(NULL);
            if (end - start >= tolerance){
                state = FLOOD;
                buff.flood = 1;
            } else if (normal(message_count, current_capacity)) { // Back to NORMAL from FULL
                state = NORMAL;
                buff.full = 0; // Clear full flag
                buff.normal = 1; // Signal return to normal
                start = 0; // Reset flood timer
            } else if (nowarn(message_count, current_capacity) && !full(message_count, current_capacity)) {
                // If it's no longer full but still above normal, transition to WARNING
                state = WARNING;
                buff.full = 0;
                buff.warn = 1;
            }
            break;

        case FLOOD:
            // Remain in FLOOD state until conditions return to normal
            if (normal(message_count, current_capacity)) {
                state = NORMAL;
                buff.flood = 0; // Clear flood flag
                buff.full = 0; // Ensure full flag is also cleared
                buff.normal = 1; // Signal return to normal
                start = 0; // Reset flood timer
            } else if (nowarn(message_count, current_capacity) && !full(message_count, current_capacity)) {
                // If it's no longer full but still above normal, transition to WARNING
                state = WARNING;
                buff.flood = 0;
                buff.full = 0;
                buff.warn = 1;
            }
            break;
    }

    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL); // Assuming this increments a global counter

    /* When buffer is full, event is dropped */
    if (full(message_count, current_capacity)){
        w_mutex_unlock(&mutex_lock); // Unlock before returning
        mdebug2("Unable to store new packet: Buffer is full (count: %u, capacity: %u).", message_count, current_capacity);
        return(-1); // Indicate failure to append
    }else{
        // Free the old string if this slot is being overwritten (crucial for circular buffers)
        // This ensures no memory leaks if the buffer wraps around before old messages are read/freed.
        if (buffer[i] != NULL) {
            free(buffer[i]);
            buffer[i] = NULL;
        }

        buffer[i] = strdup(msg); // strdup allocates memory
        if (buffer[i] == NULL) {
            merror("%s: Failed to duplicate message for buffer. Out of memory? Error: %s", __func__, strerror(errno));
            w_mutex_unlock(&mutex_lock);
            return -1; // Allocation failed
        }

        forward(&i, current_capacity); // Advance head index
        message_count++; // Increment message count

        w_cond_signal(&cond_no_empty); // Signal a consumer that buffer is not empty
        w_mutex_unlock(&mutex_lock); // Unlock

        return(0); // Indicate success
    }
}

/* Send messages from buffer to the server */
#ifdef WIN32
DWORD WINAPI dispatch_buffer(__attribute__((unused)) LPVOID arg) {
#else
void *dispatch_buffer(__attribute__((unused)) void * arg){
#endif
    char flood_msg[OS_MAXSTR];
    char full_msg[OS_MAXSTR];
    char warn_msg[OS_MAXSTR];
    char normal_msg[OS_MAXSTR];

    char warn_str[OS_SIZE_2048];
    struct timespec ts0;
    struct timespec ts1;
    char * msg_output = NULL; // Initialize to NULL

    while(1){
        gettime(&ts0);

        w_mutex_lock(&mutex_lock); // Lock for thread safety

        // Wait until there are messages in the buffer
        while(empty(message_count)){ // Use new empty check with message_count
            w_cond_wait(&cond_no_empty, &mutex_lock);
        }

        /* Check if buffer usage reaches any lower level (from consumer perspective) */
        // These checks ensure that state flags are updated as messages are consumed.
        switch (state) {
            case NORMAL:
                // No action needed if already normal
                break;

            case WARNING:
                if (normal(message_count, current_capacity)){ // Check if it went below normal_level
                    state = NORMAL;
                    buff.normal = 1; // Signal return to normal
                    buff.warn = 0;   // Clear warning flag
                }
                break;

            case FULL: // Renamed from FULL to FULL_STATE in typedef, but using original 'FULL' here for consistency with local 'state' var
                if (normal(message_count, current_capacity)){ // Check if it went below normal_level
                    state = NORMAL;
                    buff.normal = 1;
                    buff.full = 0;   // Clear full flag
                    buff.warn = 0;   // Also clear warn if coming from FULL
                    start = 0;       // Reset flood timer
                } else if (nowarn(message_count, current_capacity)) { // Back to WARNING from FULL
                    state = WARNING;
                    buff.full = 0;
                    buff.warn = 1;
                }
                break;

            case FLOOD: // Renamed from FLOOD to FLOOD_STATE
                if (normal(message_count, current_capacity)){ // Check if it went below normal_level
                    state = NORMAL;
                    buff.normal = 1;
                    buff.flood = 0;  // Clear flood flag
                    buff.full = 0;   // Also clear full
                    buff.warn = 0;   // Also clear warn
                    start = 0;       // Reset flood timer
                } else if (nowarn(message_count, current_capacity)) { // Back to WARNING from FLOOD
                    state = WARNING;
                    buff.flood = 0;
                    buff.full = 0;
                    buff.warn = 1;
                }
                break;
        }

        // Get the message from the tail
        msg_output = buffer[j];
        buffer[j] = NULL; // Clear the pointer in the buffer after reading (good practice)
        forward(&j, current_capacity); // Advance tail index
        message_count--; // Decrement message count

        w_mutex_unlock(&mutex_lock); // Unlock before sending message (long operation)

        // --- Handle buffer state messages to manager ---
        // This logic remains the same, but the buff flags are set by buffer_append/buffer_read now.
        if (buff.warn){
            buff.warn = 0; // Clear flag after reporting
            mwarn(WARN_BUFFER, warn_level);
            snprintf(warn_str, OS_SIZE_2048, OS_WARN_BUFFER, warn_level);
            snprintf(warn_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", warn_str);
            send_msg(warn_msg, -1);
        }

        if (buff.full){
            buff.full = 0; // Clear flag after reporting
            mwarn(FULL_BUFFER);
            snprintf(full_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FULL_BUFFER);
            send_msg(full_msg, -1);
        }

        if (buff.flood){
            buff.flood = 0; // Clear flag after reporting
            mwarn(FLOODED_BUFFER);
            snprintf(flood_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_FLOOD_BUFFER);
            send_msg(flood_msg, -1);
        }

        if (buff.normal){
            buff.normal = 0; // Clear flag after reporting
            minfo(NORMAL_BUFFER, normal_level);
            snprintf(normal_msg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ, "wazuh-agent", OS_NORMAL_BUFFER);
            send_msg(normal_msg, -1);
        }

        os_wait(); // This seems to be a mechanism for rate limiting or general wait

        if (msg_output != NULL) { // Ensure msg_output is not NULL before sending
            send_msg(msg_output, -1);
            free(msg_output); // Free the dynamically allocated string
        } else {
            mdebug1("%s: Skipped sending NULL message from buffer.", __func__);
        }


        gettime(&ts1);
        time_sub(&ts1, &ts0);

        if (ts1.tv_sec >= 0) {
            delay(&ts1);
        }
    }
}

void delay(struct timespec * ts_loop) {
    long interval_ns = 1000000000 / agt->events_persec;
    struct timespec ts_timeout = { interval_ns / 1000000000, interval_ns % 1000000000 };
    time_sub(&ts_timeout, ts_loop);

    if (ts_timeout.tv_sec >= 0) {
        nanosleep(&ts_timeout, NULL);
    }
}

// --- New: Buffer Cleanup Function ---
// This should be called on agent shutdown to free all buffer memory.
void buffer_destroy() {
    w_mutex_lock(&mutex_lock); // Lock before destruction

    if (buffer != NULL) {
        // Free all individual message strings still in the buffer
        for (unsigned int k = 0; k < current_capacity; k++) {
            if (buffer[k] != NULL) {
                free(buffer[k]);
                buffer[k] = NULL;
            }
        }
        free(buffer); // Free the array of char pointers itself
        buffer = NULL;
    }

    // Reset all buffer state variables
    current_capacity = 0;
    i = 0;
    j = 0;
    message_count = 0;
    state = NORMAL;
    buff.full = 0;
    buff.warn = 0;
    buff.flood = 0;
    buff.normal = 0;
    start = 0;
    end = 0;

    // Destroy mutex and condition variable
    w_mutex_destroy(&mutex_lock);
    w_cond_destroy(&cond_no_empty);

    mdebug1("Agent buffer destroyed and all memory freed.");
    w_mutex_unlock(&mutex_lock); // Unlock (though likely not strictly needed if process exits)
}

// --- Modified: w_agentd_get_buffer_lenght ---
// This function needs to return the actual number of messages (message_count)
// not the modulo calculation based on i and j, as message_count is the true size.
int w_agentd_get_buffer_lenght() {
    int retval = -1;

    // The current capacity should be > 0 if buffer is active.
    // If agt->buffer is a separate flag, ensure it's checked.
    if (current_capacity > 0) { // Check actual capacity rather than agt->buffer
        w_mutex_lock(&mutex_lock);
        retval = message_count; // Direct count of messages
        w_mutex_unlock(&mutex_lock);
    }

    return retval;
}