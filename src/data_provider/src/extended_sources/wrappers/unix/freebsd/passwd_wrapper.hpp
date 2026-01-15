/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ipasswd_wrapper.hpp"

/// @brief Wrapper class for FreeBSD-specific passwd database access.
///
/// Encapsulates system calls used to retrieve user information on FreeBSD,
/// allowing for dependency injection and easier testing.
class PasswdWrapperFreeBSD : public IPasswdWrapperFreeBSD
{
    public:
        /// @brief Retrieves the passwd entry for the given username.
        /// @param name The username to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        struct passwd* getpwnam(const char* name) override
        {
            return ::getpwnam(name);
        }

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid The user ID to search for.
        /// @return A pointer to the passwd structure, or nullptr if not found.
        struct passwd* getpwuid(uid_t uid) override
        {
            return ::getpwuid(uid);
        }

        /// @brief Retrieves the passwd entry for the given user ID.
        /// @param uid User ID to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwuid_r(uid_t uid, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        /// @brief Retrieves the passwd entry for the given username.
        /// @param name Username to search.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwnam_r(const char* name, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwnam_r(name, pwd, buf, buflen, result);
        }

        /// @brief Rewinds the passwd database to the beginning.
        void setpwent() override
        {
            ::setpwent();
        }

        /// @brief Retrieves the next entry from the passwd database.
        /// @return A pointer to the passwd structure, or nullptr if no more entries.
        struct passwd* getpwent() override
        {
            return ::getpwent();
        }

        /// @brief Retrieves the next entry from the passwd database.
        /// @param pwd Pointer to a passwd structure to fill.
        /// @param buf Buffer used to store string fields.
        /// @param buflen Size of the buffer.
        /// @param result Pointer to store the result (null if not found).
        /// @return 0 on success, or an error number on failure.
        int getpwent_r(struct passwd* pwd, char* buf,
                       size_t buflen, struct passwd** result) override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }

        /// @brief Closes the passwd database.
        void endpwent() override
        {
            ::endpwent();
        }
};
