/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include <lsdb.h>

int lc_db_open(lsdb_env **env, char *dbpath);
int lc_db_get(lsdb_env *env, const char *db, void *key, size_t klen, void **val, size_t *vlen);
int lc_db_set(lsdb_env *env, const char *db, void *key, size_t klen, void *val, size_t vlen);
int lc_db_del(lsdb_env *env, const char *db, void *key, size_t klen, void *val, size_t vlen);
