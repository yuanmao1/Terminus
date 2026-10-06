/* SQLITE_TRANSIENT is `(sqlite3_destructor_type)-1`. Zig cannot spell that
 * constant on targets where function pointers must be aligned (aarch64), so
 * the C compiler produces it and Zig links against it (src/core/store/Db.zig). */
#include "sqlite/sqlite3.h"

const sqlite3_destructor_type terminus_sqlite_transient = SQLITE_TRANSIENT;
