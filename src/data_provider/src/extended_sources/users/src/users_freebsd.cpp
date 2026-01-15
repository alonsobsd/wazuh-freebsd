/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <err.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <set>
#include <string>
#include <map>
#include <memory>

#include "users_freebsd.hpp"
#include "passwd_wrapper.hpp"

const char *    get_password_hash_algorithm(const char *pw_passwd);

constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

UsersProvider::UsersProvider(
    std::shared_ptr<IPasswdWrapperFreeBSD> passwdWrapper)
    : m_passwdWrapper(std::move(passwdWrapper)) {}

UsersProvider::UsersProvider()
    : m_passwdWrapper(std::make_shared<PasswdWrapperFreeBSD>()) {}

nlohmann::json UsersProvider::collect(bool include_remote)
{
    return collectWithConstraints({}, {}, include_remote);
}

nlohmann::json UsersProvider::collectWithConstraints(const std::set<std::string>& usernames,
                                                     const std::set<uid_t>& uids,
                                                     bool include_remote)
{
//    if (include_remote)
//    {
//        return collectRemoteUsers(usernames, uids);
//    }

    return collectUsers(usernames, uids);
}

nlohmann::json UsersProvider::genUserJson(const struct passwd* pwd, bool include_remote)
{
    nlohmann::json r;
    r["uid"] = pwd->pw_uid;
    r["gid"] = pwd->pw_gid;
    r["uid_signed"] = static_cast<int32_t>(pwd->pw_uid);
    r["gid_signed"] = static_cast<int32_t>(pwd->pw_gid);

    r["username"] = (pwd->pw_name != nullptr) ? pwd->pw_name : "";
    r["description"] = (pwd->pw_gecos != nullptr) ? pwd->pw_gecos : "";
    r["directory"] = (pwd->pw_dir != nullptr) ? pwd->pw_dir : "";
    r["shell"] = (pwd->pw_shell != nullptr) ? pwd->pw_shell : "";

    const char *hash_alg;
    if ((hash_alg = get_password_hash_algorithm(pwd->pw_passwd)) != NULL)
        r["hash_alg"] = hash_alg;
    else
        r["hash_alg"] = "";

    r["pid_with_namespace"] = "0";
    r["include_remote"] = static_cast<int>(include_remote);
    /*
     * Linux uses sp_expire from spwd, which is not specifically for the
     * password, but for the entire account.
     */
    r["expire"] = pwd->pw_change;

    return r;
}

nlohmann::json UsersProvider::collectUsers(const std::set<std::string>& usernames,
                                                 const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();

    size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);

    if (bufsize > MAX_GETPW_R_BUF_SIZE)
    {
        bufsize = MAX_GETPW_R_BUF_SIZE;
    }

    auto buf = std::make_unique<char[]>(bufsize);

    struct passwd pwd;
    struct passwd* pwd_results
    {
        nullptr
    };

    m_passwdWrapper->setpwent();

    while (m_passwdWrapper->getpwent_r(&pwd, buf.get(), bufsize, &pwd_results) == 0 && pwd_results != nullptr)
    {
        if (!usernames.empty() && usernames.find(pwd_results->pw_name) == usernames.end())
        {
            continue;
        }
        else if (!uids.empty() && uids.find(pwd_results->pw_uid) == uids.end())
        {
            continue;
        }

        results.push_back(genUserJson(pwd_results, true));
    }

    m_passwdWrapper->endpwent();

    return results;
}

const char *
get_password_hash_algorithm(const char *pw_passwd)
{
    /* Doesn't make much sense to read from insecure DB. */
    if (getuid() != 0)
        return NULL;

    /* Password is empty. */
    if (pw_passwd[0] == 0)
        return NULL;

    char *pptr, *pptr_aux;

    if ((pptr = strdup(pw_passwd)) == NULL) {
        warn("strdup");
        return NULL;
    }

    const char *locked_str = "*LOCKED*";

    pptr_aux = pptr;

    /* A locked account can still have a password. */
    if (strstr(pptr_aux, locked_str) != NULL)
        pptr_aux += strlen(locked_str);

    /* Auth locked. */
    if (pptr_aux[0] == '*' && pptr_aux[1] == '\0') {
        free(pptr);

        return NULL;
    }

    /* Password is empty (again). */
    if (pptr_aux[0] == 0) {
        free(pptr);

        return NULL;
    }

    if (pptr_aux[0] == '_') {
        free(pptr);

        return "DES-Extended";
    } else if (pptr_aux[0] == '$') {
        const char *hash_algorithm = NULL;

        if (pptr_aux[1] == '\0') {
            free(pptr);

            return hash_algorithm;
        }

        switch (pptr_aux[1]) {
        case '1':
            hash_algorithm = "MD5";
            break;
        case '2':
            hash_algorithm = "Blowfish";
            break;
        case '3':
            hash_algorithm = "NT-Hash";
            break;
        case '5':
            hash_algorithm = "SHA-256";
            break;
        case '6':
            hash_algorithm = "SHA-512";
            break;
        }

        /* Basic check before returning. */
        if (pptr_aux[2] != '$') {
            free(pptr);

            return NULL;
        }

        free(pptr);

        return hash_algorithm;
    } else {
        free(pptr);

        return "DES";
    }
}
