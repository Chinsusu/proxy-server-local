#!/usr/bin/python3
"""Restore one authenticated snapshot object with atomic, metadata-exact staging."""

import contextlib
import ctypes
import errno
import hashlib
import json
import os
import posixpath
import stat
import sys

try:
    import resource
except ImportError:  # Windows-only development fixtures never retain POSIX fds.
    resource = None


METADATA_VERSION = 3
RESOURCE_LIMITS = {
    "max_records": 4096,
    "max_depth": 32,
    "max_path_bytes": 4096,
    "max_member_bytes": 255,
    "max_total_path_bytes": 8 * 1024 * 1024,
    "max_total_member_bytes": 512 * 1024,
    "max_file_bytes": 16 * 1024 * 1024 * 1024,
    "max_aggregate_file_bytes": 64 * 1024 * 1024 * 1024,
    "max_symlink_target_bytes": 4096,
    "max_manifest_bytes": 1024 * 1024,
    "max_metadata_bytes": 16 * 1024 * 1024,
    "max_retained_fds": 4096,
    "fd_safety_headroom": 32,
}
MAX_MANIFEST_BYTES = RESOURCE_LIMITS["max_manifest_bytes"]
MAX_METADATA_BYTES = RESOURCE_LIMITS["max_metadata_bytes"]


class RecordMap(dict):
    """Metadata records plus an O(1) authenticated parent/child index."""

    def __init__(self, *args, children=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.children = children or {}


class ResourceBudget:
    def __init__(self):
        self.records = 0
        self.total_path_bytes = 0
        self.total_member_bytes = 0
        self.aggregate_file_bytes = 0

    def add_path(self, path):
        if not isinstance(path, str) or "\x00" in path:
            fail("snapshot path is not canonical")
        try:
            encoded = path.encode("utf-8")
            members = path.split("/")
            member_sizes = [len(member.encode("utf-8")) for member in members]
        except UnicodeError:
            fail("resource_limit: path_encoding")
        depth = len(members)
        if depth > RESOURCE_LIMITS["max_depth"]:
            fail("resource_limit: max_depth")
        if len(encoded) > RESOURCE_LIMITS["max_path_bytes"]:
            fail("resource_limit: max_path_bytes")
        if any(size == 0 or size > RESOURCE_LIMITS["max_member_bytes"] for size in member_sizes):
            fail("resource_limit: max_member_bytes")
        self.records += 1
        self.total_path_bytes += len(encoded)
        self.total_member_bytes += member_sizes[-1]
        if self.records > RESOURCE_LIMITS["max_records"]:
            fail("resource_limit: max_records")
        if self.total_path_bytes > RESOURCE_LIMITS["max_total_path_bytes"]:
            fail("resource_limit: max_total_path_bytes")
        if self.total_member_bytes > RESOURCE_LIMITS["max_total_member_bytes"]:
            fail("resource_limit: max_total_member_bytes")

    def add_file(self, size):
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            fail("resource_limit: invalid_file_size")
        if size > RESOURCE_LIMITS["max_file_bytes"]:
            fail("resource_limit: max_file_bytes")
        self.aggregate_file_bytes += size
        if self.aggregate_file_bytes > RESOURCE_LIMITS["max_aggregate_file_bytes"]:
            fail("resource_limit: max_aggregate_file_bytes")


def fail(message):
    raise SystemExit(message)


def clean_logical_path(value):
    if not isinstance(value, str) or not value.startswith("/") or value == "/":
        fail("snapshot logical root must be an absolute non-root path")
    if posixpath.normpath(value) != value or "\x00" in value:
        fail("snapshot logical root is not canonical")
    return value


def load_manifest(manifest_path):
    entries = []
    seen = set()
    budget = ResourceBudget()
    try:
        manifest_size = os.stat(manifest_path, follow_symlinks=False).st_size
    except OSError:
        fail("invalid snapshot manifest")
    if manifest_size > MAX_MANIFEST_BYTES:
        fail("resource_limit: manifest_bytes")
    with open(manifest_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if len(line.encode("utf-8")) > RESOURCE_LIMITS["max_path_bytes"] + 16:
                fail("resource_limit: manifest_line_bytes")
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 2 or fields[0] not in ("present", "absent"):
                fail("invalid snapshot manifest record")
            state, logical = fields[0], clean_logical_path(fields[1])
            budget.add_path(logical.lstrip("/"))
            if logical in seen:
                fail("duplicate snapshot logical root")
            seen.add(logical)
            entries.append((state, logical))
    for logical in seen:
        parts = logical.lstrip("/").split("/")
        for index in range(1, len(parts)):
            if "/" + "/".join(parts[:index]) in seen:
                fail("overlapping snapshot logical roots")
    return entries


def load_metadata(metadata_path):
    try:
        metadata_size = os.stat(metadata_path, follow_symlinks=False).st_size
    except OSError:
        fail("invalid snapshot metadata")
    if metadata_size > MAX_METADATA_BYTES:
        fail("resource_limit: metadata_bytes")
    with open(metadata_path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if (not isinstance(raw, dict) or set(raw) != {"version", "limits", "roots", "records"}
            or raw.get("version") != METADATA_VERSION):
        fail("unsupported snapshot metadata schema")
    if raw.get("limits") != RESOURCE_LIMITS:
        fail("snapshot resource contract mismatch")
    roots = raw.get("roots")
    records_raw = raw.get("records")
    if not isinstance(roots, list) or not isinstance(records_raw, list):
        fail("invalid snapshot metadata structure")
    roots = [clean_logical_path(value) for value in roots]
    root_budget = ResourceBudget()
    for root in roots:
        root_budget.add_path(root.lstrip("/"))
    if len(set(roots)) != len(roots):
        fail("duplicate snapshot metadata root")
    root_set = set(roots)
    for logical in roots:
        parts = logical.lstrip("/").split("/")
        for index in range(1, len(parts)):
            if "/" + "/".join(parts[:index]) in root_set:
                fail("overlapping snapshot metadata roots")
    records = RecordMap()
    budget = ResourceBudget()
    root_prefixes = {root.lstrip("/") for root in roots}
    for item in records_raw:
        if not isinstance(item, dict):
            fail("invalid snapshot metadata record")
        kind = item.get("type")
        allowed = {"path", "mode", "uid", "gid", "type"}
        if kind == "file":
            allowed.update(("sha256", "size"))
        elif kind == "symlink":
            allowed.add("target")
        elif kind != "dir":
            fail("invalid snapshot metadata object type")
        if set(item) != allowed:
            fail("invalid snapshot metadata record fields")
        path = item.get("path")
        if (not isinstance(path, str) or not path or path.startswith("/")
                or "\x00" in path or posixpath.normpath(path) != path):
            fail("snapshot metadata path is not canonical")
        budget.add_path(path)
        if path in records:
            fail("duplicate snapshot metadata path")
        cursor = path
        owner = None
        while cursor:
            if cursor in root_prefixes:
                owner = cursor
                break
            cursor = cursor.rpartition("/")[0]
        if owner is None:
            fail("snapshot metadata record is outside its logical root")
        mode, uid, gid = item.get("mode"), item.get("uid"), item.get("gid")
        if (not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode > 0o7777
                or not isinstance(uid, int) or isinstance(uid, bool) or uid < 0 or uid > 0xffffffff
                or not isinstance(gid, int) or isinstance(gid, bool) or gid < 0 or gid > 0xffffffff):
            fail("invalid snapshot metadata ownership")
        if kind == "file":
            digest = item.get("sha256")
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)):
                fail("invalid snapshot metadata digest")
            budget.add_file(item.get("size"))
        elif kind == "symlink":
            target = item.get("target")
            if not isinstance(target, str) or "\x00" in target:
                fail("invalid snapshot symlink target")
            try:
                target_bytes = len(target.encode("utf-8"))
            except UnicodeError:
                fail("resource_limit: symlink_target_encoding")
            if target_bytes > RESOURCE_LIMITS["max_symlink_target_bytes"]:
                fail("resource_limit: max_symlink_target_bytes")
        records[path] = item
    for root in roots:
        if root.lstrip("/") not in records:
            fail("snapshot metadata omitted logical root")
    children = {}
    for path, item in records.items():
        if path in root_prefixes:
            continue
        parent, separator, member = path.rpartition("/")
        if not separator or parent not in records or records[parent].get("type") != "dir":
            fail("snapshot metadata has an orphan record")
        children.setdefault(parent, []).append(member)
    records.children = {parent: tuple(sorted(members)) for parent, members in children.items()}
    return roots, records


def load_records(metadata_path, logical):
    logical = clean_logical_path(logical)
    roots, all_records = load_metadata(metadata_path)
    if logical not in roots:
        fail("snapshot metadata omitted requested logical root")
    prefix = logical.lstrip("/")
    selected = RecordMap()
    for path, item in all_records.items():
        if path == prefix or path.startswith(prefix + "/"):
            selected[path] = item
    selected.children = {
        parent: members
        for parent, members in all_records.children.items()
        if parent == prefix or parent.startswith(prefix + "/")
    }
    return prefix, selected


def record_node(path, relative, records, budget):
    budget.add_path(relative)
    info = os.lstat(path)
    item = {
        "path": relative,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
    }
    if stat.S_ISREG(info.st_mode):
        budget.add_file(info.st_size)
        item["type"] = "file"
        item["size"] = info.st_size
        digest = hashlib.sha256()
        binary = getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, os.O_RDONLY | binary)
        try:
            opened = os.fstat(descriptor)
            if _capture_identity(opened) != _capture_identity(info):
                fail("snapshot payload changed during metadata capture")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            if _capture_identity(os.fstat(descriptor)) != _capture_identity(opened):
                fail("snapshot payload changed during metadata capture")
        finally:
            os.close(descriptor)
        item["sha256"] = digest.hexdigest()
    elif stat.S_ISDIR(info.st_mode):
        item["type"] = "dir"
    elif stat.S_ISLNK(info.st_mode):
        item["type"] = "symlink"
        item["target"] = os.readlink(path)
        try:
            target_bytes = len(item["target"].encode("utf-8"))
        except UnicodeError:
            fail("resource_limit: symlink_target_encoding")
        if target_bytes > RESOURCE_LIMITS["max_symlink_target_bytes"]:
            fail("resource_limit: max_symlink_target_bytes")
    else:
        fail("unsupported snapshot payload object")
    records.append(item)
    if item["type"] == "dir":
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                name = entry.name
                if not name or name in (".", "..") or "/" in name or "\x00" in name:
                    fail("invalid snapshot payload entry")
                try:
                    member_bytes = len(name.encode("utf-8"))
                except UnicodeError:
                    fail("resource_limit: path_encoding")
                if member_bytes > RESOURCE_LIMITS["max_member_bytes"]:
                    fail("resource_limit: max_member_bytes")
                names.append(name)
                if len(names) + budget.records > RESOURCE_LIMITS["max_records"]:
                    fail("resource_limit: max_records")
        for name in sorted(names):
            if not name or name in (".", "..") or "/" in name or "\x00" in name:
                fail("invalid snapshot payload entry")
            record_node(os.path.join(path, name), relative + "/" + name, records, budget)


def write_metadata(snapshot_root):
    entries = load_manifest(os.path.join(snapshot_root, "manifest"))
    roots = [logical for state, logical in entries if state == "present"]
    records = []
    budget = ResourceBudget()
    payload = os.path.join(snapshot_root, "files")
    for logical in roots:
        source = os.path.join(payload, *logical.lstrip("/").split("/"))
        if not os.path.lexists(source):
            fail("present snapshot root is missing from payload")
        record_node(source, logical.lstrip("/"), records, budget)
    document = {
        "version": METADATA_VERSION,
        "limits": RESOURCE_LIMITS,
        "roots": roots,
        "records": records,
    }
    target = os.path.join(snapshot_root, "metadata.json")
    temporary = target + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    completed = False
    try:
        payload_bytes = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(payload_bytes) > MAX_METADATA_BYTES:
            fail("resource_limit: metadata_bytes")
        view = memoryview(payload_bytes)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    os.replace(temporary, target)


def verify_metadata(snapshot_root, mode, system_root):
    entries = load_manifest(os.path.join(snapshot_root, "manifest"))
    roots, records = load_metadata(os.path.join(snapshot_root, "metadata.json"))
    if roots != [logical for state, logical in entries if state == "present"]:
        fail("snapshot manifest and metadata roots differ")
    payload = os.path.join(snapshot_root, "files")
    if os.name != "posix":
        # The Windows-only development fixture has no dirfd/O_NOFOLLOW API.  It
        # never runs in the privileged installer; Linux verification below is
        # entirely descriptor-bound.
        if mode == "restored":
            for state, logical in entries:
                target = os.path.join(system_root, *logical.lstrip("/").split("/"))
                if state == "absent" and os.path.lexists(target):
                    fail("absent snapshot logical root still exists after restore")
        for relative, item in records.items():
            base = payload if mode == "payload" else system_root
            target = os.path.join(base, *relative.split("/"))
            info = os.lstat(target)
            if (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) != (
                    int(item["mode"]), int(item["uid"]), int(item["gid"])):
                fail("snapshot managed-root metadata mismatch")
            kind = item.get("type")
            if kind == "file":
                if not stat.S_ISREG(info.st_mode) or info.st_size != int(item["size"]):
                    fail("snapshot managed file type mismatch")
                digest = hashlib.sha256()
                with open(target, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != item.get("sha256"):
                    fail("snapshot managed file digest mismatch")
            elif kind == "symlink":
                if not stat.S_ISLNK(info.st_mode) or os.readlink(target) != item.get("target"):
                    fail("snapshot managed symlink mismatch")
            elif kind == "dir":
                if not stat.S_ISDIR(info.st_mode):
                    fail("snapshot managed directory type mismatch")
                if sorted(os.listdir(target)) != direct_children(records, relative):
                    fail("snapshot managed directory entries mismatch")
            else:
                fail("invalid snapshot managed object type")
        return

    expected_uid = os.geteuid()
    if mode == "restored":
        for state, logical in entries:
            if state != "absent":
                continue
            target = os.path.join(system_root, *logical.lstrip("/").split("/"))
            parent = secure_parent(target, expected_uid)
            try:
                if exists_at(parent, os.path.basename(target)):
                    fail("absent snapshot logical root still exists after restore")
            finally:
                os.close(parent)
    for logical in roots:
        relative = logical.lstrip("/")
        base = payload if mode == "payload" else system_root
        target = os.path.join(base, *relative.split("/"))
        parent = secure_parent(target, expected_uid)
        try:
            if not node_matches(parent, os.path.basename(target), relative, records):
                fail("snapshot managed tree failed descriptor-bound verification")
        finally:
            os.close(parent)


def secure_parent(path, expected_uid):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        fail("restore path must be clean and absolute")
    parts = [part for part in os.path.dirname(path).split(os.sep) if part]
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(nxt)
            if info.st_uid not in (0, expected_uid) or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
                os.close(nxt)
                fail("unsafe restore path ancestor")
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def direct_children(records, relative):
    if isinstance(records, RecordMap):
        return list(records.children.get(relative, ()))
    # Test-only compatibility for small hand-built record maps.
    prefix = relative + "/"
    return sorted(path[len(prefix):] for path in records
                  if path.startswith(prefix) and "/" not in path[len(prefix):])


def apply_open_directory_metadata(descriptor, item):
    """Apply and verify authenticated metadata on an already-open directory."""
    mode, uid, gid = int(item["mode"]), int(item["uid"]), int(item["gid"])
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode):
        fail("restore metadata target is not a directory")
    # chown can clear special permission bits, so ownership must precede mode.
    os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, mode)
    os.fsync(descriptor)
    applied = os.fstat(descriptor)
    if (stat.S_IMODE(applied.st_mode), applied.st_uid, applied.st_gid) != (mode, uid, gid):
        fail("restored directory metadata did not persist")


def copy_node(source_parent, source_name, target_parent, target_name, relative, records):
    item = records.get(relative)
    if not item:
        fail("snapshot metadata omitted object")
    kind, mode, uid, gid = item["type"], int(item["mode"]), int(item["uid"]), int(item["gid"])
    source_info = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
    if stat.S_IMODE(source_info.st_mode) != mode or source_info.st_uid != uid or source_info.st_gid != gid:
        fail("snapshot source metadata changed")
    if kind == "file":
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size != int(item["size"]):
            fail("snapshot file type changed")
        source_fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_parent)
        target_fd = os.open(target_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target_parent)
        try:
            opened = os.fstat(source_fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_size != int(item["size"]) or
                    stat.S_IMODE(opened.st_mode) != mode or
                    opened.st_uid != uid or opened.st_gid != gid):
                fail("opened snapshot file metadata changed")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(target_fd, view):]
            if digest.hexdigest() != item.get("sha256"):
                fail("opened snapshot file content changed")
            os.fchown(target_fd, uid, gid)
            os.fchmod(target_fd, mode)
            os.fsync(target_fd)
        finally:
            os.close(source_fd)
            os.close(target_fd)
    elif kind == "symlink":
        if not stat.S_ISLNK(source_info.st_mode):
            fail("snapshot symlink type changed")
        link = os.readlink(source_name, dir_fd=source_parent)
        if link != item.get("target"):
            fail("snapshot symlink target changed")
        os.symlink(link, target_name, dir_fd=target_parent)
        os.chown(target_name, uid, gid, dir_fd=target_parent, follow_symlinks=False)
    elif kind == "dir":
        if not stat.S_ISDIR(source_info.st_mode):
            fail("snapshot directory type changed")
        source_fd = os.open(source_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_parent)
        os.mkdir(target_name, 0o700, dir_fd=target_parent)
        target_fd = os.open(target_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target_parent)
        try:
            opened = os.fstat(source_fd)
            if (not stat.S_ISDIR(opened.st_mode) or stat.S_IMODE(opened.st_mode) != mode or
                    opened.st_uid != uid or opened.st_gid != gid):
                fail("opened snapshot directory metadata changed")
            children = direct_children(records, relative)
            if sorted(os.listdir(source_fd)) != children:
                fail("snapshot directory entries changed")
            # Apply metadata immediately after creation.  The staging mkdir is
            # deliberately 0700 and must never leak through as the logical-root
            # mode, even under a restrictive or permissive process umask.
            apply_open_directory_metadata(target_fd, item)
            for child in children:
                copy_node(source_fd, child, target_fd, child, relative + "/" + child, records)
            # Reapply after population because child creation and ownership
            # changes can alter setgid or inherited directory mode semantics.
            apply_open_directory_metadata(target_fd, item)
        finally:
            os.close(source_fd)
            os.close(target_fd)
    else:
        fail("unsupported snapshot object type")


def capture_node(source_parent, source_name, target_parent, target_name, relative, budget):
    """Copy one live object from opened trusted parents without path re-resolution."""
    budget.add_path(relative)
    before = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
    mode = stat.S_IMODE(before.st_mode)
    if stat.S_ISREG(before.st_mode):
        source_fd = os.open(
            source_name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=source_parent,
        )
        target_fd = -1
        completed = False
        try:
            opened = os.fstat(source_fd)
            if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
                fail("snapshot source changed while opening file")
            # Charge the complete expected file globally before allocating or
            # writing its first byte.
            budget.add_file(opened.st_size)
            target_fd = os.open(
                target_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=target_parent,
            )
            remaining = opened.st_size
            while remaining:
                chunk = os.read(source_fd, min(1024 * 1024, remaining))
                if not chunk:
                    fail("snapshot source shrank while copying file")
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        fail("short snapshot write")
                    view = view[written:]
                remaining -= len(chunk)
            if os.read(source_fd, 1):
                fail("snapshot source grew while copying file")
            finished = os.fstat(source_fd)
            rebound = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
            if (_stat_identity(finished) != _stat_identity(opened)
                    or _stat_identity(rebound) != _stat_identity(opened)):
                fail("snapshot source changed while copying file")
            os.fchown(target_fd, opened.st_uid, opened.st_gid)
            os.fchmod(target_fd, mode)
            os.fsync(target_fd)
            completed = True
        finally:
            if target_fd >= 0:
                os.close(target_fd)
            os.close(source_fd)
            if not completed and exists_at(target_parent, target_name):
                remove_at(target_parent, target_name)
                os.fsync(target_parent)
        return
    if stat.S_ISDIR(before.st_mode):
        source_fd = os.open(
            source_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=source_parent,
        )
        completed = False
        try:
            opened = os.fstat(source_fd)
            if not stat.S_ISDIR(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
                fail("snapshot source changed while opening directory")
            os.mkdir(target_name, 0o700, dir_fd=target_parent)
            target_fd = os.open(target_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=target_parent)
            try:
                children = sorted(os.listdir(source_fd))
                if len(children) + budget.records > RESOURCE_LIMITS["max_records"]:
                    fail("resource_limit: max_records")
                for child in children:
                    if not child or child in (".", "..") or "/" in child:
                        fail("invalid snapshot source entry")
                    try:
                        member_bytes = len(child.encode("utf-8"))
                    except UnicodeError:
                        fail("resource_limit: path_encoding")
                    if member_bytes > RESOURCE_LIMITS["max_member_bytes"]:
                        fail("resource_limit: max_member_bytes")
                    capture_node(
                        source_fd, child, target_fd, child,
                        relative + "/" + child, budget,
                    )
                finished = os.fstat(source_fd)
                rebound = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
                if (sorted(os.listdir(source_fd)) != children
                        or _stat_identity(finished) != _stat_identity(opened)
                        or _stat_identity(rebound) != _stat_identity(opened)):
                    fail("snapshot source changed while copying directory")
                os.fchown(target_fd, opened.st_uid, opened.st_gid)
                os.fchmod(target_fd, mode)
                os.fsync(target_fd)
                completed = True
            finally:
                os.close(target_fd)
        finally:
            os.close(source_fd)
            if not completed and exists_at(target_parent, target_name):
                remove_at(target_parent, target_name)
                os.fsync(target_parent)
        return
    if stat.S_ISLNK(before.st_mode):
        link_target = os.readlink(source_name, dir_fd=source_parent)
        if "\x00" in link_target:
            fail("snapshot symlink target is not canonical")
        try:
            target_bytes = len(link_target.encode("utf-8"))
        except UnicodeError:
            fail("resource_limit: symlink_target_encoding")
        if target_bytes > RESOURCE_LIMITS["max_symlink_target_bytes"]:
            fail("resource_limit: max_symlink_target_bytes")
        after = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
        if _stat_identity(after) != _stat_identity(before):
            fail("snapshot source changed while reading symlink")
        os.symlink(link_target, target_name, dir_fd=target_parent)
        os.chown(target_name, before.st_uid, before.st_gid, dir_fd=target_parent, follow_symlinks=False)
        os.fsync(target_parent)
        return
    fail("unsupported live snapshot object type")


def preflight_capture_node(source_parent, source_name, relative, budget):
    """Validate and globally charge one source subtree without creating output."""
    budget.add_path(relative)
    before = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
    if stat.S_ISREG(before.st_mode):
        descriptor = os.open(
            source_name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=source_parent,
        )
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
                fail("snapshot source changed during resource preflight")
            budget.add_file(opened.st_size)
            rebound = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
            if (_stat_identity(os.fstat(descriptor)) != _stat_identity(opened)
                    or _stat_identity(rebound) != _stat_identity(opened)):
                fail("snapshot source changed during resource preflight")
        finally:
            os.close(descriptor)
    elif stat.S_ISDIR(before.st_mode):
        descriptor = os.open(
            source_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            dir_fd=source_parent,
        )
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISDIR(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
                fail("snapshot source changed during resource preflight")
            children = sorted(os.listdir(descriptor))
            if len(children) + budget.records > RESOURCE_LIMITS["max_records"]:
                fail("resource_limit: max_records")
            for child in children:
                if not child or child in (".", "..") or "/" in child or "\x00" in child:
                    fail("invalid snapshot source entry")
                preflight_capture_node(descriptor, child, relative + "/" + child, budget)
            rebound = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
            if (sorted(os.listdir(descriptor)) != children
                    or _stat_identity(os.fstat(descriptor)) != _stat_identity(opened)
                    or _stat_identity(rebound) != _stat_identity(opened)):
                fail("snapshot source changed during resource preflight")
        finally:
            os.close(descriptor)
    elif stat.S_ISLNK(before.st_mode):
        target = os.readlink(source_name, dir_fd=source_parent)
        if "\x00" in target:
            fail("snapshot symlink target is not canonical")
        try:
            target_bytes = len(target.encode("utf-8"))
        except UnicodeError:
            fail("resource_limit: symlink_target_encoding")
        if target_bytes > RESOURCE_LIMITS["max_symlink_target_bytes"]:
            fail("resource_limit: max_symlink_target_bytes")
        if _stat_identity(os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)) != _stat_identity(before):
            fail("snapshot source changed during resource preflight")
    else:
        fail("unsupported live snapshot object type")


def ensure_capture_parent(files_fd, components, expected_uid):
    descriptor = os.dup(files_fd)
    try:
        for component in components:
            try:
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_mode & 0o022):
                os.close(child)
                fail("unsafe snapshot capture scaffold")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def capture_all_posix(snapshot_root, system_root, expected_uid):
    entries = load_manifest(os.path.join(snapshot_root, "manifest"))
    present = [(logical, clean_logical_path(logical).lstrip("/"))
               for state, logical in entries if state == "present"]
    preflight_budget = ResourceBudget()
    for logical, relative in present:
        source = os.path.join(system_root, *relative.split("/"))
        source_parent = secure_parent(source, expected_uid)
        try:
            preflight_capture_node(source_parent, os.path.basename(source), relative, preflight_budget)
        finally:
            os.close(source_parent)

    files_path = os.path.join(snapshot_root, "files")
    files_parent = secure_parent(files_path, expected_uid)
    files_fd = -1
    try:
        files_fd = os.open(
            os.path.basename(files_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=files_parent,
        )
        files_info = os.fstat(files_fd)
        if (not stat.S_ISDIR(files_info.st_mode) or files_info.st_uid != expected_uid
                or files_info.st_mode & 0o022):
            fail("unsafe snapshot capture payload root")
        copy_budget = ResourceBudget()
        try:
            for logical, relative in present:
                components = relative.split("/")
                source = os.path.join(system_root, *components)
                source_parent = secure_parent(source, expected_uid)
                target_parent = ensure_capture_parent(files_fd, components[:-1], expected_uid)
                try:
                    if exists_at(target_parent, components[-1]):
                        fail("snapshot destination already exists")
                    capture_node(
                        source_parent, os.path.basename(source), target_parent,
                        components[-1], relative, copy_budget,
                    )
                    os.fsync(target_parent)
                finally:
                    os.close(target_parent)
                    os.close(source_parent)
            if (copy_budget.records != preflight_budget.records
                    or copy_budget.total_path_bytes != preflight_budget.total_path_bytes
                    or copy_budget.total_member_bytes != preflight_budget.total_member_bytes
                    or copy_budget.aggregate_file_bytes != preflight_budget.aggregate_file_bytes):
                fail("snapshot source resources changed after preflight")
        except BaseException:
            for child in os.listdir(files_fd):
                remove_at(files_fd, child)
            os.fsync(files_fd)
            raise
        os.fsync(files_fd)
    finally:
        if files_fd >= 0:
            os.close(files_fd)
        os.close(files_parent)


def remove_at(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            for child in os.listdir(child_fd):
                remove_at(child_fd, child)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent)
    else:
        os.unlink(name, dir_fd=parent)


def exists_at(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def exchange(parent, stage, target):
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None or renameat2(parent, stage.encode(), parent, target.encode(), 2) != 0:
        error = ctypes.get_errno()
        fail("atomic restore exchange unavailable: " + os.strerror(error or errno.ENOSYS))


def deterministic_restore_name(metadata, logical, kind):
    digest = hashlib.sha256()
    with open(metadata, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    digest.update(b"\x00")
    digest.update(logical.encode())
    return ".pgw-restore-" + kind + "-" + digest.hexdigest()[:24]


def restore_operation_id(metadata, logical, state):
    digest = hashlib.sha256()
    with open(metadata, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    digest.update(b"\x00")
    digest.update(clean_logical_path(logical).encode())
    digest.update(b"\x00")
    digest.update(state.encode())
    return digest.hexdigest()


def _metadata_matches(info, item):
    return (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) == (
        int(item["mode"]), int(item["uid"]), int(item["gid"])
    )


def _stat_identity(info):
    """Return every stable inode field used by the recursive verifier."""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_nlink,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _capture_identity(info):
    """Bind metadata hashing to a stable opened object on each platform.

    Linux (the privileged production platform) uses the complete identity.
    Windows exposes creation time as ``st_ctime`` and can round it differently
    between path and descriptor queries, so the non-privileged development
    fixture omits only that unstable field.
    """
    identity = _stat_identity(info)
    if os.name == "posix":
        return identity
    return identity[:-1]


def _name_still_binds(parent, name, result):
    """Prove the parent entry still has the child's full finished identity."""
    try:
        bound = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if _stat_identity(bound) != result["stat"]:
        return False
    if result["kind"] == "symlink":
        try:
            target = os.readlink(name, dir_fd=parent)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except (FileNotFoundError, OSError):
            return False
        return target == result["target"] and _stat_identity(after) == result["stat"]
    return True


def _opened_node_matches(parent, name, relative, records, held=None):
    """Verify one tree node through O_NOFOLLOW dirfds.

    The returned identity lets a directory verify every child binding again
    after recursive reads.  Thus a rename swap cannot make a verified old inode
    stand in for the name that will subsequently be exchanged or trusted.
    """
    item = records.get(relative)
    if not item:
        return None
    kind = item.get("type")
    if kind == "symlink":
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode) or not _metadata_matches(before, item):
                return None
            link = os.readlink(name, dir_fd=parent)
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except (FileNotFoundError, OSError):
            return None
        if _stat_identity(before) != _stat_identity(after):
            return None
        if not _metadata_matches(after, item) or link != item.get("target"):
            return None
        result = {"kind": "symlink", "stat": _stat_identity(after), "target": link}
        if not _name_still_binds(parent, name, result):
            return None
        return result

    flags = os.O_RDONLY | os.O_NOFOLLOW
    if kind == "dir":
        flags |= os.O_DIRECTORY
    elif kind == "file":
        # Avoid blocking if an attacker substitutes a FIFO/device immediately
        # before open; fstat below still requires a regular file.
        flags |= getattr(os, "O_NONBLOCK", 0)
    else:
        return None
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except (FileNotFoundError, OSError):
        return None
    if held is not None:
        held.callback(os.close, descriptor)
    try:
        opened = os.fstat(descriptor)
        if not _metadata_matches(opened, item):
            return None
        if kind == "file":
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != int(item["size"]):
                return None
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            finished = os.fstat(descriptor)
            if _stat_identity(finished) != _stat_identity(opened):
                return None
            digest_hex = digest.hexdigest()
            if digest_hex != item.get("sha256"):
                return None
            result = {"kind": "file", "stat": _stat_identity(finished), "digest": digest_hex}
        else:
            if not stat.S_ISDIR(opened.st_mode):
                return None
            children = direct_children(records, relative)
            if sorted(os.listdir(descriptor)) != children:
                return None
            identities = {}
            for child in children:
                identity = _opened_node_matches(
                    descriptor, child, relative + "/" + child, records, held
                )
                if identity is None:
                    return None
                identities[child] = identity
            if sorted(os.listdir(descriptor)) != children:
                return None
            for child, identity in identities.items():
                try:
                    current = os.stat(child, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    return None
                if _stat_identity(current) != identity["stat"]:
                    return None
                if identity["kind"] == "symlink":
                    try:
                        current_target = os.readlink(child, dir_fd=descriptor)
                    except OSError:
                        return None
                    if current_target != identity["target"]:
                        return None
                if not _name_still_binds(descriptor, child, identity):
                    return None
            finished = os.fstat(descriptor)
            if _stat_identity(finished) != _stat_identity(opened):
                return None
            result = {
                "kind": "dir",
                "stat": _stat_identity(finished),
                "children": tuple((child, identities[child]) for child in children),
            }
        if held is not None:
            result["descriptor"] = descriptor
        if not _name_still_binds(parent, name, result):
            return None
        return result
    finally:
        if held is None:
            os.close(descriptor)


def _held_tree_still_binds(parent, name, result):
    """Second fence while every opened regular-file/directory fd is alive."""
    if not _name_still_binds(parent, name, result):
        return False
    descriptor = result.get("descriptor")
    if descriptor is not None and _stat_identity(os.fstat(descriptor)) != result["stat"]:
        return False
    if result["kind"] == "dir":
        if descriptor is None:
            return False
        for child, child_result in result["children"]:
            if not _held_tree_still_binds(descriptor, child, child_result):
                return False
    return True


def _preflight_retained_fds(relative, records):
    if os.name != "posix" or resource is None:
        return
    prefix = relative + "/"
    required = sum(
        1 for path, item in records.items()
        if (path == relative or path.startswith(prefix)) and item.get("type") in ("file", "dir")
    )
    hard_max = RESOURCE_LIMITS["max_retained_fds"]
    if required > hard_max:
        fail("resource_limit: retained_fds_hard")
    try:
        current_open = len(os.listdir("/proc/self/fd"))
    except OSError:
        # Linux production exposes procfs; refusing without an exact count is
        # safer than guessing around a privileged restore.
        fail("resource_limit: open_fd_count_unavailable")
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY:
        soft_limit = current_open + hard_max + RESOURCE_LIMITS["fd_safety_headroom"]
    available = max(0, int(soft_limit) - current_open - RESOURCE_LIMITS["fd_safety_headroom"])
    if required > available:
        fail("resource_limit: nofile")


def node_matches(parent, name, relative, records):
    try:
        _preflight_retained_fds(relative, records)
        with contextlib.ExitStack() as held:
            result = _opened_node_matches(parent, name, relative, records, held)
            return result is not None and _held_tree_still_binds(parent, name, result)
    except (FileNotFoundError, OSError):
        return False


def validate_restore_operation(metadata, state, logical):
    entries = load_manifest(os.path.join(os.path.dirname(metadata), "manifest"))
    matches = [entry_state for entry_state, entry_logical in entries if entry_logical == logical]
    if matches != [state]:
        fail("restore operation is not authenticated by snapshot manifest")


def restore_posix(state, source, target, metadata, logical, expected_uid):
    logical = clean_logical_path(logical)
    validate_restore_operation(metadata, state, logical)
    target_parent = secure_parent(target, expected_uid)
    target_name = os.path.basename(target)
    try:
        if state == "absent":
            tombstone = deterministic_restore_name(metadata, logical, "tomb")
            if exists_at(target_parent, tombstone):
                if exists_at(target_parent, target_name):
                    fail("ambiguous absent restore residue")
                remove_at(target_parent, tombstone)
                os.fsync(target_parent)
            if exists_at(target_parent, target_name):
                os.rename(target_name, tombstone, src_dir_fd=target_parent, dst_dir_fd=target_parent)
                os.fsync(target_parent)
                remove_at(target_parent, tombstone)
                os.fsync(target_parent)
            return
        if state != "present":
            fail("invalid restore state")
        prefix, records = load_records(metadata, logical)
        if prefix not in records:
            fail("snapshot metadata omitted restore root")
        source_parent = secure_parent(source, expected_uid)
        stage = deterministic_restore_name(metadata, logical, "stage")
        if exists_at(target_parent, stage):
            if exists_at(target_parent, target_name) and node_matches(target_parent, target_name, prefix, records):
                remove_at(target_parent, stage)
                os.fsync(target_parent)
                return
            remove_at(target_parent, stage)
            os.fsync(target_parent)
        try:
            try:
                copy_node(source_parent, os.path.basename(source), target_parent, stage, prefix, records)
            except BaseException:
                if exists_at(target_parent, stage):
                    remove_at(target_parent, stage)
                    os.fsync(target_parent)
                raise
        finally:
            os.close(source_parent)
        if not node_matches(target_parent, stage, prefix, records):
            remove_at(target_parent, stage)
            os.fsync(target_parent)
            fail("staged restore tree failed authenticated metadata verification")
        exchanged_old_tree = False
        if exists_at(target_parent, target_name):
            exchange(target_parent, stage, target_name)
            os.fsync(target_parent)
            exchanged_old_tree = True
        else:
            os.rename(stage, target_name, src_dir_fd=target_parent, dst_dir_fd=target_parent)
            os.fsync(target_parent)
        if not node_matches(target_parent, target_name, prefix, records):
            # If this was an exchange, `stage` is the authenticated previous
            # runtime tree.  Keep it intact for journal-driven recovery rather
            # than destroying the only rollback point after a failed verify.
            fail("exchanged restore tree failed authenticated metadata verification")
        if exchanged_old_tree:
            remove_at(target_parent, stage)
        os.fsync(target_parent)
    finally:
        os.close(target_parent)


def restore_portable(state, source, target, budget=None, relative=None):
    # Non-production Windows fixture path. It deliberately uses the same
    # authenticated payload and explicit per-node copying; Linux production and CI
    # exercise descriptor-bound ownership restoration above.
    def remove(path):
        if os.path.isdir(path) and not os.path.islink(path):
            for entry in os.scandir(path):
                remove(entry.path)
            os.rmdir(path)
        else:
            os.unlink(path)

    def copy(source_path, target_path, current_relative):
        info = os.lstat(source_path)
        if budget is not None:
            budget.add_path(current_relative)
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(target_path)
            entries = list(os.scandir(source_path))
            if budget is not None and len(entries) + budget.records > RESOURCE_LIMITS["max_records"]:
                fail("resource_limit: max_records")
            for entry in entries:
                copy(entry.path, os.path.join(target_path, entry.name),
                     current_relative + "/" + entry.name)
            os.chmod(target_path, stat.S_IMODE(info.st_mode))
        elif stat.S_ISLNK(info.st_mode):
            link_target = os.readlink(source_path)
            if "\x00" in link_target:
                fail("snapshot symlink target is not canonical")
            if budget is not None and len(link_target.encode("utf-8")) > RESOURCE_LIMITS["max_symlink_target_bytes"]:
                fail("resource_limit: max_symlink_target_bytes")
            os.symlink(link_target, target_path)
        elif stat.S_ISREG(info.st_mode):
            binary = getattr(os, "O_BINARY", 0)
            source_fd = os.open(source_path, os.O_RDONLY | binary | getattr(os, "O_NONBLOCK", 0))
            target_fd = -1
            completed = False
            try:
                opened = os.fstat(source_fd)
                if not stat.S_ISREG(opened.st_mode) or _capture_identity(opened) != _capture_identity(info):
                    fail("snapshot source changed while opening file")
                if budget is not None:
                    budget.add_file(opened.st_size)
                target_fd = os.open(
                    target_path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary,
                    stat.S_IMODE(opened.st_mode),
                )
                remaining = opened.st_size
                while remaining:
                    chunk = os.read(source_fd, min(1024 * 1024, remaining))
                    if not chunk:
                        fail("snapshot source shrank while copying file")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(target_fd, view):]
                    remaining -= len(chunk)
                if os.read(source_fd, 1):
                    fail("snapshot source grew while copying file")
                if _capture_identity(os.fstat(source_fd)) != _capture_identity(opened):
                    fail("snapshot source changed while copying file")
                os.fsync(target_fd)
                completed = True
            finally:
                os.close(source_fd)
                if target_fd >= 0:
                    os.close(target_fd)
                if not completed and os.path.lexists(target_path):
                    remove(target_path)
        else:
            fail("unsupported portable snapshot object")

    if os.path.lexists(target):
        remove(target)
    if state == "absent":
        return
    copy(source, target, relative or os.path.basename(source))


def preflight_portable_node(path, relative, budget):
    budget.add_path(relative)
    info = os.lstat(path)
    if stat.S_ISREG(info.st_mode):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) |
                             getattr(os, "O_NONBLOCK", 0))
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or _capture_identity(opened) != _capture_identity(info):
                fail("snapshot source changed during resource preflight")
            budget.add_file(opened.st_size)
        finally:
            os.close(descriptor)
    elif stat.S_ISDIR(info.st_mode):
        entries = sorted(os.scandir(path), key=lambda entry: entry.name)
        if len(entries) + budget.records > RESOURCE_LIMITS["max_records"]:
            fail("resource_limit: max_records")
        for entry in entries:
            preflight_portable_node(entry.path, relative + "/" + entry.name, budget)
    elif stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        if "\x00" in target:
            fail("snapshot symlink target is not canonical")
        if len(target.encode("utf-8")) > RESOURCE_LIMITS["max_symlink_target_bytes"]:
            fail("resource_limit: max_symlink_target_bytes")
    else:
        fail("unsupported live snapshot object type")


def capture_all_portable(snapshot_root, system_root):
    entries = load_manifest(os.path.join(snapshot_root, "manifest"))
    present = [(logical, clean_logical_path(logical).lstrip("/"))
               for state, logical in entries if state == "present"]
    preflight_budget = ResourceBudget()
    for _, relative in present:
        preflight_portable_node(
            os.path.join(system_root, *relative.split("/")), relative, preflight_budget,
        )
    files_root = os.path.join(snapshot_root, "files")
    copy_budget = ResourceBudget()
    try:
        for _, relative in present:
            source = os.path.join(system_root, *relative.split("/"))
            target = os.path.join(files_root, *relative.split("/"))
            os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
            restore_portable("present", source, target, copy_budget, relative)
        if (copy_budget.records != preflight_budget.records
                or copy_budget.total_path_bytes != preflight_budget.total_path_bytes
                or copy_budget.total_member_bytes != preflight_budget.total_member_bytes
                or copy_budget.aggregate_file_bytes != preflight_budget.aggregate_file_bytes):
            fail("snapshot source resources changed after preflight")
    except BaseException:
        for entry in list(os.scandir(files_root)):
            restore_portable("absent", "", entry.path)
        raise


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "operation-id":
        _, metadata, logical, state = sys.argv[1:]
        if state not in ("present", "absent"):
            fail("invalid restore operation state")
        print(restore_operation_id(metadata, logical, state))
        return
    if len(sys.argv) == 3 and sys.argv[1] == "metadata":
        write_metadata(sys.argv[2])
        return
    if len(sys.argv) == 5 and sys.argv[1] == "verify":
        _, snapshot_root, mode, system_root = sys.argv[1:]
        if mode not in ("payload", "restored"):
            fail("invalid snapshot verification mode")
        verify_metadata(snapshot_root, mode, system_root)
        return
    if len(sys.argv) == 5 and sys.argv[1] == "capture-all":
        _, snapshot_root, system_root, expected = sys.argv[1:]
        if os.name == "posix":
            capture_all_posix(snapshot_root, system_root, int(expected))
        else:
            capture_all_portable(snapshot_root, system_root)
        return
    if len(sys.argv) != 7:
        fail("usage: restore_snapshot.py metadata SNAPSHOT | verify SNAPSHOT MODE SYSTEM_ROOT | operation-id METADATA LOGICAL STATE | capture-all SNAPSHOT SYSTEM_ROOT EXPECTED_UID | STATE SOURCE TARGET METADATA LOGICAL EXPECTED_UID")
    state, source, target, metadata, logical, expected = sys.argv[1:]
    if os.name == "posix":
        restore_posix(state, source, target, metadata, logical, int(expected))
    else:
        restore_portable(state, source, target)


if __name__ == "__main__":
    main()
