/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net> */

#include "lcdb.h"
#include "../src/log.h"
#include <stdlib.h>
#include <string.h>

int lc_db_open(lsdb_env **env, char *dbpath)
{
	int rc = 0;
	if ((rc = lsdb_env_create(env)) != MDB_SUCCESS) {
		ERROR("Error creating environment: %s", lsdb_strerror(rc));
	}
	else if ((rc = lsdb_env_set_maxdbs(*env, LC_DATABASE_COUNT)) != MDB_SUCCESS) {
		ERROR("lsdb_env_set_maxdbs: %s", lsdb_strerror(rc));
	}
	else if ((rc = lsdb_env_open(*env, dbpath, 0, 0600)) != MDB_SUCCESS) {
		ERROR("Error opening environment: %s", lsdb_strerror(rc));
	}
	return (rc == MDB_SUCCESS) ? 0 : 1;
}

int lc_db_get(lsdb_env *env, const char *db, void *key, size_t klen, void **val, size_t *vlen)
{
	int rc = 0;
	lsdb_txn *txn;
	lsdb_dbi dbi;
	lsdb_val k, v;

	k.mv_data = key;
	k.mv_size = klen;

	if (((rc = lsdb_txn_begin(env, NULL, 0, &txn)) != MDB_SUCCESS)
	|| ((rc = lsdb_dbi_open(txn, db, MDB_CREATE, &dbi)) != MDB_SUCCESS)
	|| ((rc = lsdb_get(txn, dbi, &k, &v)) != MDB_SUCCESS))
	{
		ERROR("%s", lsdb_strerror(rc));
	}
	else {
		*val = malloc(v.mv_size);
		if (*val) {
			memcpy(*val, v.mv_data, v.mv_size);
			*vlen = v.mv_size;
		}
		else rc = -ENOMEM;
	}
	lsdb_txn_abort(txn);

	return rc;
}

int lc_db_set(lsdb_env *env, const char *db, void *key, size_t klen, void *val, size_t vlen)
{
	int rc = 0;
	lsdb_txn *txn;
	lsdb_dbi dbi;
	lsdb_val k, v;

	k.mv_data = key;
	k.mv_size = klen;
	v.mv_data = val;
	v.mv_size = vlen;

	if (((rc = lsdb_txn_begin(env, NULL, 0, &txn)) != MDB_SUCCESS)
	|| ((rc = lsdb_dbi_open(txn, db, MDB_CREATE, &dbi)) != MDB_SUCCESS)
	|| ((rc = lsdb_put(txn, dbi, &k, &v, 0)) != MDB_SUCCESS))
	{
		ERROR("%s", lsdb_strerror(rc));
		lsdb_txn_abort(txn);
	}
	else {
		lsdb_txn_commit(txn);
	}

	return rc;
}

int lc_db_del(lsdb_env *env, const char *db, void *key, size_t klen, void *val, size_t vlen)
{
	int rc = 0;
	lsdb_txn *txn;
	lsdb_dbi dbi;
	lsdb_val k, v;

	k.mv_data = key;
	k.mv_size = klen;
	v.mv_data = val;
	v.mv_size = vlen;

	if (((rc = lsdb_txn_begin(env, NULL, 0, &txn)) != MDB_SUCCESS)
	|| ((rc = lsdb_dbi_open(txn, db, MDB_CREATE, &dbi)) != MDB_SUCCESS)
	|| ((rc = lsdb_del(txn, dbi, &k, &v)) != MDB_SUCCESS))
	{
		ERROR("%s", lsdb_strerror(rc));
		lsdb_txn_abort(txn);
	}
	else {
		lsdb_txn_commit(txn);
	}

	return rc;
}
