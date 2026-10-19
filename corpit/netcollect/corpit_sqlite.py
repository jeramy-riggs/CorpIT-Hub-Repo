"""Checked SQLite durability for both WAL and rollback-journal connections."""
import sqlite3


def connect_durable(*args, **kwargs):
    conn = sqlite3.connect(*args, **kwargs)
    try:
        # EXTRA equals FULL for WAL, and also syncs DELETE-journal removal.
        # Do not change the caller's journal mode, transaction mode or timeout.
        conn.execute("PRAGMA synchronous=EXTRA")
        if conn.execute("PRAGMA synchronous").fetchone()[0] != 3:
            raise RuntimeError("SQLite writer requires synchronous=EXTRA")
        return conn
    except BaseException:
        conn.close()
        raise
