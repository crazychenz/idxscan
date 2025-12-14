#!/usr/bin/env python3

'''
    Plan:

    - Run over X path inclusions minus Y path exclusions for paths only
        - If there is a conflict, check if its different content via meta only.
            - Compare ctime, mtime, sizes, isdir, isregular, islink, ismount, symlink (optionally hash)
            - On change, add to update entry table.
        - No conflict means its a new file, add to new entry table.

    - Update entry thread / New entry thread
        - Perform magic_mime detection (e.g. libmagic)
        - Perform digest/hash generation (SHA1, SHA256, SHA512, CRC32, MD5)
        - Perform deep identification (reasoning and summary)
        - Fetch extended attributes into K/V store

    - Once all (initial) data is gathered, the sqlite3 database is the object for the target system.
      - The sqlite3 database is "loaded" into central database with system entry (with unique name).
      - Additional system specific metadata can be stored:
        - Serial number
        - Barcode
        - Service Tag?
        - BIOS ID?
        - /proc/mounts
        - /etc/machine-id
        - /etc/os-release
        - stat.vfsid
        - blkid
        - volid
        - volname
        - network interfaces
      - Central file index has primary key of (systemId, pathId) for anything that used pathId on target system.
'''


import os
import stat
import sqlite3

from dataclasses import dataclass, fields

# apt-get install python3-magic
#import magic


def walk_follow_symlinks(top, visited=None):
    """
    Recursively yield every file/directory starting at `top`,
    following symlinks without looping.
    """
    if visited is None:
        visited = set()

    try:
        st = os.stat(top)  # follow symlinks
    except FileNotFoundError:
        return
    except PermissionError:
        return

    # Note: st_dev is not reboot stable, do not use as persistent file source.
    key = (st.st_dev, st.st_ino)

    # Already visited? Then entering this directory again would cause a loop.
    if key in visited:
        return

    # Mark as visited *before* recursion.
    visited.add(key)

    yield top

    # If it's not a directory, stop.
    if not stat.S_ISDIR(st.st_mode):
        return

    try:
        entries = os.listdir(top)
    except PermissionError:
        return

    for name in entries:
        path = os.path.join(top, name)
        yield from walk_follow_symlinks(path, visited)


# class SQLiteConnection():
#     def __init__(self, db_path):
#         self.conn = sqlite3.connect(db_path)
#         self.default_cursor = self.conn.cursor()

#     def execute(self, *args):
#         self.default_cursor.execute(*args)

#     def commit(self):
#         self.conn.commit()

#     def commit_execute(self, *args):
#         self.execute(*args)
#         self.commit()

#     def lastrowid(self):
#         return self.default_cursor.lastrowid

#     def fetchone(self):
#         return self.default_cursor.fetchone()


#     def prepare_database(self):

#         # Content specific data.
#         self.execute("""
#             CREATE TABLE IF NOT EXISTS contents (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 size INTEGER,
#                 mime TEXT,
#                 sha1 TEXT,
#                 sha224 TEXT,
#                 sha256 TEXT,
#                 sha384 TEXT,
#                 sha512 TEXT,
#                 md5 TEXT,
#                 crc32 TEXT,
#                 header BLOB,
#                 footer BLOB,
#                 thumbnail_mime TEXT,
#                 thumbnail BLOB,

#                 UNIQUE(size, sha256)
#             );
#         """)

#         self.execute("""
#             CREATE INDEX IF NOT EXISTS idx_contents_sha256 ON contents(sha256);
#         """)

#         self.execute("""
#             CREATE TABLE IF NOT EXISTS fileinfo (
#                 id INTEGER PRIMARY KEY AUTOINCREMENT,
#                 path TEXT UNIQUE,
#                 mode INTEGER,
#                 ctime TIMESTAMP,
#                 mtime TIMESTAMP,
#                 isdir INTEGER,
#                 islink INTEGER,
#                 ismount INTEGER,
#                 isregular INTEGER,
#                 symlink TEXT,
#                 content_id INTEGER
#             );
#         """)

#         return self
    
    
#     def close(self):
#         self.conn.close()


class FileInfo():
    @dataclass(slots=True)
    class _FileInfo():
        id: int = -1
        path: str = ''
        mode: int = 0
        ctime: int = 0
        mtime: int = 0
        size: int = 0
        isdir: int = 0
        islink: int = 0
        ismount: int = 0
        isregular: int = 0
        symlink: int = ''


    def __init__(self, conn, from_path=None, data={}):
        self.conn = conn
        
        self.cursor = self.conn.cursor()
        self.data = FileInfo._FileInfo(**data)

        if from_path:
            self.load_from_path(from_path)


    def commit(self):
        if self.data.id == -1:
            rowid, conflict = self._insert_fileinfo()
            if not conflict:
                return

        self._update_fileinfo()


    def _insert_fileinfo(self):
        data = self.data

        # Try inserting the filename.
        self.cursor.execute("""
                INSERT INTO fileinfo (
                path,
                mode,
                ctime,
                mtime,
                size,
                isdir,
                islink,
                ismount,
                isregular,
                symlink
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO NOTHING
            """,
            (
                data.path,
                data.mode,
                data.ctime,
                data.mtime,
                data.size,
                data.isdir,
                data.islink,
                data.ismount,
                data.isregular,
                data.symlink,
            )
        )
        self.conn.commit()

        # If row was inserted, lastrowid is nonzero.
        return self.cursor.lastrowid, self.cursor.lastrowid == 0


    def _update_fileinfo(self):
        data = self.data

        self.cursor.execute(\
            """
                UPDATE fileinfo
                SET 
                    mode = ?,
                    ctime = ?,
                    mtime = ?,
                    size = ?,
                    isdir = ?,
                    islink = ?,
                    ismount = ?,
                    isregular = ?,
                    symlink = ?
                WHERE path = ?
            """,
            (
                data.mode,
                data.ctime,
                data.mtime,
                data.size,
                data.isdir,
                data.islink,
                data.ismount,
                data.isregular,
                data.symlink,
                data.path
            )
        )
        self.conn.commit()

        if self.cursor.rowcount != 1:
            raise Exception(f'Bad fileinfo update rowcount: rowcount {self.cursor.rowcount} id {self.data.id} path {self.data.path}')


    def load_vfs_info(self):
        st = os.lstat(self.data.path)
        self.data.mode = st.st_mode
        self.data.ctime = st.st_ctime 
        self.data.mtime = st.st_mtime
        self.data.size = st.st_size
        self.data.isdir = stat.S_ISDIR(st.st_mode)
        self.data.islink = stat.S_ISLNK(st.st_mode)
        self.data.ismount = os.path.ismount(self.data.path)
        self.data.isregular = not (os.path.exists(self.data.path) and not os.path.isfile(self.data.path) and not self.data.isdir)
        self.data.symlink = os.readlink(self.data.path) if self.data.islink else ''


    def load_from_path(self, from_path):
        row = self.cursor.execute("""
            SELECT id, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink
            FROM fileinfo WHERE path = ?
        """, (from_path,)).fetchone()

        if row is None:
            raise Exception(f'Path not found: {from_path}')
        else:
            self.data = FileInfo._FileInfo(**row)


# def try_insert_file(db, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink):
#     # Try inserting the filename.
#     db.execute("""
#         INSERT INTO fileinfo (path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#         ON CONFLICT(path) DO NOTHING
#     """, (path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink))

#     # If row was inserted, lastrowid is nonzero.
#     return db.lastrowid(), db.lastrowid() == 0


# def try_insert_content(db, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink):
#     # Try inserting the filename.
#     db.execute("""
#         INSERT INTO fileinfo (path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink)
#         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#         ON CONFLICT(path) DO NOTHING
#     """, (path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink))

#     # If row was inserted, lastrowid is nonzero.
#     return db.lastrowid(), db.lastrowid() == 0



# def fetch_file(db, path):

#     ## Otherwise, file already exists, fetch current entry.
#     db.execute("""
#         SELECT id, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink
#         FROM paths WHERE path = ?
#     """, (path,))
#     return db.fetchone()


# def update_file(db, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink):
#     db.commit_execute("""
#         UPDATE paths SET mode = ?, ctime = ?, mtime = ?, size = ?, isdir = ?, islink = ?, ismount = ?, isregular = ?, symlink = ?
#         WHERE path = ?
#     """, (mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink, path))


# def update_file_content(db, fileinfo_id, content_id):
    
#     db.commit_execute("UPDATE fileinfo SET content_id = ? WHERE id = ?", (content_id, fileinfo_id))

#     return mime


# def update_file_mime(db, path):
#     mime = "undefined"
#     try:
#         mime = ms.from_file(path)
#     except:
#         pass

#     db.commit_execute("UPDATE paths SET mime = ? WHERE path = ?", (mime, path))

#     return mime


# def hash_file(path, chunk_size=8192):
#     import hashlib
#     import zlib

#     """Compute SHA1, SHA256, SHA512, MD5, and CRC32 in a single pass."""
#     sha1 = hashlib.sha1()
#     sha256 = hashlib.sha256()
#     sha512 = hashlib.sha512()
#     md5 = hashlib.md5()
#     crc32 = 0

#     with open(path, "rb") as f:
#         while chunk := f.read(chunk_size):
#             sha1.update(chunk)
#             sha256.update(chunk)
#             sha512.update(chunk)
#             md5.update(chunk)
#             crc32 = zlib.crc32(chunk, crc32)  # update crc32 incrementally

#     # Return hex digests
#     return {
#         "sha1": sha1.hexdigest(),
#         "sha256": sha256.hexdigest(),
#         "sha512": sha512.hexdigest(),
#         "md5": md5.hexdigest(),
#         "crc32": format(crc32 & 0xFFFFFFFF, "08x")  # zero-padded hex
#     }


# def store_paths_in_sqlite(db, start_path):
#     count = 0
#     for path in walk_follow_symlinks(start_path):
#         st = os.lstat(path)
#         mode = st.st_mode
#         ctime = st.st_ctime 
#         mtime = st.st_mtime
#         size = st.st_size
#         isdir = stat.S_ISDIR(st.st_mode)
#         islink = stat.S_ISLNK(st.st_mode)
#         ismount = os.path.ismount(path)
#         isregular = not (os.path.exists(path) and not os.path.isfile(path) and not isdir)
#         symlink = os.readlink(path) if islink else ''
        
#         count += 1
#         if count % 1000 == 0:
#             print(f"PROCESSED {count} PATHS.")
#             db.commit()
        
#         rowid, conflict = try_insert_file(db, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink)

#         if conflict:
#             # Check if something changed
#             db_entry = fetch_file(db, path)
#             current = (path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink)
#             if current != db_entry[1:]:
#                 # There have been updates, update the database.
#                 print(f"UPDATING PATH: {path}")
#                 update_file(db, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink)
#                 print(f"MIME: {update_file_mime(db, path)}")

#         else:
#             print(f"NEW PATH: {path}")
#             try:
#                 print(f"MIME: {update_file_mime(db, path)}")
#             except:
#                 pass

#             try:
#                 hashes = hash_file(path)
#                 # TODO: Add hashes to database
#             except:
#                 pass



conn = sqlite3.connect("paths.db")
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS contents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        size INTEGER,
        mime TEXT,
        sha1 TEXT,
        sha224 TEXT,
        sha256 TEXT,
        sha384 TEXT,
        sha512 TEXT,
        md5 TEXT,
        crc32 TEXT,
        header BLOB,
        footer BLOB,
        thumbnail_mime TEXT,
        thumbnail BLOB,

        UNIQUE(size, sha256)
    );
""")

cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_contents_sha256 ON contents(sha256);
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS fileinfo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT UNIQUE,
        mode INTEGER,
        ctime TIMESTAMP,
        mtime TIMESTAMP,
        size INTEGER,
        isdir INTEGER,
        islink INTEGER,
        ismount INTEGER,
        isregular INTEGER,
        symlink TEXT,
        content_id INTEGER
    );
""")

conn.commit()



count = 0
for path in walk_follow_symlinks('/home/chenz/idxscan/ignored'):

    fi = FileInfo(conn, data={'path': path})
    # TODO: Only do these if needed.
    fi.load_vfs_info()
    fi.commit()
    
    count += 1
    if count % 1000 == 0:
        print(f"PROCESSED {count} PATHS.")
        conn.commit()
    



#db = SQLiteConnection("paths.db").prepare_database()
#ms = magic.Magic(mime=True)
#store_paths_in_sqlite(db, "/home/chenz/ml")
#db.close()


'''
With MIME:

real    10m34.308s
user    3m48.595s
sys     1m25.163s

Without MIME:

real    6m47.411s
user    0m37.957s
sys     0m58.443s

With less stat calls.



'''