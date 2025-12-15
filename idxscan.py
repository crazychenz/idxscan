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
import magic


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


def hash_file(path, chunk_size=8192):
    import hashlib
    import zlib

    """Compute SHA1, SHA256, SHA512, MD5, and CRC32 in a single pass."""
    sha1 = hashlib.sha1()
    sha224 = hashlib.sha224()
    sha256 = hashlib.sha256()
    sha384 = hashlib.sha384()
    sha512 = hashlib.sha512()
    md5 = hashlib.md5()
    crc32 = 0
    size = 0

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            size += len(chunk)
            sha1.update(chunk)
            sha224.update(chunk)
            sha256.update(chunk)
            sha384.update(chunk)
            sha512.update(chunk)
            md5.update(chunk)
            crc32 = zlib.crc32(chunk, crc32)

    return {
        "sha1": sha1.hexdigest(),
        "sha224": sha224.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha384": sha384.hexdigest(),
        "sha512": sha512.hexdigest(),
        "md5": md5.hexdigest(),
        "crc32": format(crc32 & 0xFFFFFFFF, "08x"),
        "size": size,
    }


@dataclass(slots=True)
class FileInfo():
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
    content_id: int = 0


    @classmethod
    def create(cls, conn, path):
        # Note: Intentionally not falling back to load().
        cursor = conn.cursor()

        # Try inserting the filename.
        cursor.execute("""
                INSERT INTO fileinfo (path) VALUES (?)
                ON CONFLICT(path) DO NOTHING
            """, (path,))
        conn.commit()

        # Create object ref to return
        obj = None
        if cursor.lastrowid != 0:
            # If we had no conflict, create the object.
            obj = cls(id=cursor.lastrowid, path=path)

        # Return the object reference and if there was a conflict.
        return obj, cursor.lastrowid == 0


    @classmethod
    def load(cls, conn, path):
        # Assumption: conn.row_factory = sqlite3.Row
        # Note: Intentionally not falling back to create().
        cursor = conn.cursor()

        row = cursor.execute("""
            SELECT id, path, mode, ctime, mtime, size, isdir, islink, ismount, isregular, symlink, content_id
            FROM fileinfo WHERE path = ?
        """, (path,)).fetchone()

        if row is None:
            raise KeyError(f'Path not found: {path}')
        
        return cls(**row)


    def save(self, conn):
        # Assumption: Path is set.
        cursor = conn.cursor()
        cursor.execute(\
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
                    symlink = ?,
                    content_id = ?
                WHERE path = ?
            """,
            (
                self.mode,
                self.ctime,
                self.mtime,
                self.size,
                self.isdir,
                self.islink,
                self.ismount,
                self.isregular,
                self.symlink,
                self.content_id,
                self.path
            )
        )
        conn.commit()

        if cursor.rowcount != 1:
            raise Exception(f'Bad fileinfo update rowcount: rowcount {cursor.rowcount} id {self.id} path {self.data.path}')

        return self

    
    def update(self, **attrs):
        field_names = {f.name for f in fields(self)}
        for key, value in attrs.items():
            if key in field_names:
                setattr(self, key, value)
            else:
                raise AttributeError(f"{key} is not a valid field")
      
        return self


    def sync_vfs_info(self, conn):
        # Assumption: Path is set.
        st = os.lstat(self.path)
        dirty = False

        if self.mode != st.st_mode:
            dirty = True
            self.mode = st.st_mode

        if self.ctime != st.st_ctime:
            dirty = True
            self.ctime = st.st_ctime

        if self.mtime != st.st_mtime:
            dirty = True
            self.mtime = st.st_mtime
        
        if self.size != st.st_size:
            dirty = True
            self.size = st.st_size

        if self.isdir != stat.S_ISDIR(st.st_mode):
            dirty = True
            self.isdir = stat.S_ISDIR(st.st_mode)

        if self.islink != stat.S_ISLNK(st.st_mode):
            dirty = True
            self.islink = stat.S_ISLNK(st.st_mode)
        
        if self.ismount != os.path.ismount(self.path):
            dirty = True
            self.ismount = os.path.ismount(self.path)

        # TODO: I've lost the point here.
        isregular = not (os.path.exists(self.path) and not os.path.isfile(self.path) and not self.isdir)
        if self.isregular != isregular:
            dirty = True
            self.isregular = isregular

        symlink = os.readlink(self.path) if self.islink else ''
        if self.symlink != symlink:
            dirty = True
            self.symlink = symlink

        if dirty:
            self.save(conn)

        return dirty


@dataclass(slots=True)
class Content():
    id: int = -1
    size: int = 0
    mime: str = ''
    sha1: str = ''
    sha224: str = ''
    sha256: str = ''
    sha384: str = ''
    sha512: str = ''
    md5: str = ''
    crc32: str = ''
    header: bytes = bytes()
    footer: bytes = bytes()
    thumbnail_mime: str = ''
    thumbnail: bytes = bytes()


    @classmethod
    def create(cls, conn, size, sha256):
        # Note: Intentionally not falling back to load().
        cursor = conn.cursor()

        # Try inserting the filename.
        cursor.execute("""
                INSERT INTO contents (size, sha256) VALUES (?, ?)
                ON CONFLICT(size, sha256) DO NOTHING
            """, (size, sha256))
        conn.commit()

        # Create object ref to return
        obj = None
        if cursor.lastrowid != 0:
            # If we had no conflict, create the object.
            obj = cls(id=cursor.lastrowid, size=size, sha256=sha256)

        # Return the object reference and if there was a conflict.
        return obj, cursor.lastrowid == 0


    @classmethod
    def load(cls, conn, size, sha256):
        # Assumption: conn.row_factory = sqlite3.Row
        # Note: Intentionally not falling back to create().
        cursor = conn.cursor()

        row = cursor.execute("""
            SELECT
                id,
                size,
                mime,
                sha1,
                sha224,
                sha256,
                sha384,
                sha512,
                md5,
                crc32,
                header,
                footer,
                thumbnail_mime,
                thumbnail
            FROM contents WHERE size = ? AND sha256 = ?
        """, (size, sha256)).fetchone()

        if row is None:
            raise KeyError(f'Content not found: size {size} sha256 {sha256}')
        
        return cls(**row)


    def save(self, conn):
        # Assumption: Path is set.
        cursor = conn.cursor()

        params = (
            self.mime,
            self.sha1,
            self.sha224,
            self.sha384,
            self.sha512,
            self.md5,
            self.crc32,
            self.header,
            self.footer,
            self.thumbnail_mime,
            self.thumbnail,
            self.size,
            self.sha256
        )

        cursor.execute(\
            """
                UPDATE contents
                SET 
                    mime = ?,
                    sha1 = ?,
                    sha224 = ?,
                    sha384 = ?,
                    sha512 = ?,
                    md5 = ?,
                    crc32 = ?,
                    header = ?,
                    footer = ?,
                    thumbnail_mime = ?,
                    thumbnail = ?
                WHERE size = ? AND sha256 = ?
            """, params
        )
        conn.commit()

        if cursor.rowcount != 1:
            raise Exception(f'Bad contents update rowcount: rowcount {cursor.rowcount} sha256 {self.sha256}')

        return self


    def update(self, **attrs):
        field_names = {f.name for f in fields(self)}
        for key, value in attrs.items():
            if key in field_names:
                setattr(self, key, value)
            else:
                raise AttributeError(f"{key} is not a valid field")
      
        return self


conn = sqlite3.connect("paths.db")
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS contents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        size INTEGER NOT NULL,
        mime TEXT DEFAULT '',
        sha1 TEXT DEFAULT '',
        sha224 TEXT DEFAULT '',
        sha256 TEXT NOT NULL DEFAULT '',
        sha384 TEXT DEFAULT '',
        sha512 TEXT DEFAULT '',
        md5 TEXT DEFAULT '',
        crc32 TEXT DEFAULT '',
        header BLOB,
        footer BLOB,
        thumbnail_mime TEXT DEFAULT '',
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
        path TEXT NOT NULL UNIQUE,
        mode INTEGER DEFAULT 0,
        ctime TIMESTAMP DEFAULT 0,
        mtime TIMESTAMP DEFAULT 0,
        size INTEGER DEFAULT 0,
        isdir INTEGER DEFAULT 0,
        islink INTEGER DEFAULT 0,
        ismount INTEGER DEFAULT 0,
        isregular INTEGER DEFAULT 0,
        symlink TEXT DEFAULT '',
        content_id INTEGER DEFAULT 0
    );
""")

conn.commit()


libmagic = magic.Magic(mime=True)
def calculate_content(conn, path):
    hashes = hash_file(path)
    content, content_conflict = Content.create(conn, hashes['size'], hashes['sha256'])
    if content_conflict:
        content = Content.load(conn, hashes['size'], hashes['sha256'])
    
    hashes['mime'] = libmagic.from_file(path)
    content.update(**hashes).save(conn)
    # TODO: Update mime type
    # TODO: map content to fileinfo
    # TODO: If mime type is thumbnail-able, generate thumbnail

    return content


# Get image mime types:
#   select mime from contents where mime LIKE 'image%';


count = 0
for path in walk_follow_symlinks('/home/chenz/idxscan/ignored'):

    fi, fileinfo_conflict = FileInfo.create(conn, path)
    if fileinfo_conflict:
        fi = FileInfo.load(conn, path)
        if fi.sync_vfs_info(conn):
            print(f'DIRTY: {fi.path}')
            if fi.isregular and not fi.isdir:
                # If readable file (not folder or device), calculate content
                content = calculate_content(conn, fi.path)
                fi.update(content_id=content.id).save(conn)
            else:
                # Ensure there is no content_id for folder path or device path
                fi.update(content_id=0).save(conn)
    else:
        print(f'NEW: {fi.path}')
        fi.sync_vfs_info(conn)
        if fi.isregular and not fi.isdir:
            # If readable file (not folder or device), calculate content
            content = calculate_content(conn, fi.path)
            fi.update(content_id=content.id).save(conn)
        else:
            # Ensure there is no content_id for folder path or device path
            fi.update(content_id=0).save(conn)

    count += 1
    if count % 100 == 0:
        print(f"PROCESSED {count} PATHS.")

print(f"PROCESSED {count} PATHS.")
