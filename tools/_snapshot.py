"""Safe freeze and snapshot primitive for ha-pseg release and mutation tooling.

Reuses and adapts the safe freeze and descriptor-based atomic copy algorithm from
~/ai-tools/scripts/pseg-candidate-snapshot.py (with attribution) for repo-wide release freeze
and snapshot creation.

Guarantees:
- Hash sorted relative path + NUL + exact bytes + NUL.
- Record HEAD, included paths/per-file hashes, and aggregate hash.
- Tracked regular suite source/config/docs plus explicitly included, reviewed new suite paths.
- Rejection of arbitrary untracked inputs.
- Exclusion of .git, .venv, caches, captures, local storage, logs, and credentials.
- Rejection of escaping paths, symlinks, non-regular files, source/output aliases.
- Independent atomic copy via descriptor chains (O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK).
- Validation on readback and second look at source before return.
- Support for git worktrees as well as validated snapshot-manifest inputs.
- Metadata file snapshot-manifest.json is outside the hashed source-file set.

Threat model / non-goals:
ha-pseg snapshot and freeze are local release and test helpers, NOT a security
boundary against a concurrent malicious process running as the same UID (which
already possesses direct read/write permissions to the source tree).
Protection against concurrent same-UID directory tampering is anchored by three
generic end-of-run invariants:
A. Final containment check: resolves the held destination root fd real path as the
   final step before returning success, verifying it equals caller-requested destination
   and is not inside the source tree.
B. Source-tree no-new-entries check: walks the source tree at start (recording relative
   path, type, dev, ino, skipping excluded directories/paths via is_excluded_path) and re-walks
   at completion and in failure paths; any new entry fails the run with source_tree_changed naming the paths.
C. Inode-scoped cleanup: records (dev, ino) of all created directories/files and removes
   only entries reached fd-relatively without following symlinks whose identity matches
   the record; foreign or relocated entries are left in place and report cleanup failure naming
   the retained owned paths.
Concurrent same-UID tampering beyond these generic invariants is an explicit non-goal.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
from typing import Any

MANIFEST_NAME = "snapshot-manifest.json"
MANIFEST_TOOL = "release_check"
MANIFEST_VERSION = 1

MAX_MANIFEST_BYTES = 1 << 20  # 1 MiB
MAX_FILE_BYTES = 16 << 20  # 16 MiB
MAX_TOTAL_BYTES = 64 << 20  # 64 MiB

_UNMERGED = frozenset({"DD", "AU", "UD", "UA", "DU", "AA", "UU"})
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

ALLOWED_ADDITION_SUFFIXES = (
    ".py",
    ".txt",
    ".json",
    ".md",
    ".cjs",
    ".js",
    ".toml",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
)


class SnapshotError(Exception):
    """Failure with a fixed public code and context."""

    def __init__(self, code: str, **context: Any) -> None:
        super().__init__(code)
        self.code = code
        self.context = context

    def __str__(self) -> str:
        if self.context:
            details = ", ".join(f"{k}={v!r}" for k, v in sorted(self.context.items()))
            return f"{self.code}: {details}"
        return self.code


class CleanupRefused(Exception):
    """The created directory is no longer provably ours; cleanup deleted nothing."""


_ACTIVE_ARCHIVES: dict[int, _OwnedArchive] = {}


class _OwnedArchive:
    """Open descriptors and typed identities for exactly what this run created."""

    def __init__(
        self,
        parent_fd: int,
        name: str,
        root_fd: int,
        source_real: str | None = None,
    ) -> None:
        self.parent_fd = parent_fd
        self.name = name
        self.root_fd = root_fd
        self.source_real = source_real
        # rel path -> (st_dev, st_ino, "file"|"dir"), recorded at creation/fstat time.
        self.files: dict[str, tuple[int, int, str]] = {}
        self.dirs: dict[str, tuple[int, int, str]] = {}
        self.retained_locations: dict[str, str] = {}
        _ACTIVE_ARCHIVES[self.root_fd] = self

    def record_file(self, rel: str, info: os.stat_result) -> None:
        self.files[rel] = (info.st_dev, info.st_ino, "file")

    def record_dir(self, rel: str, info: os.stat_result) -> None:
        self.dirs[rel] = (info.st_dev, info.st_ino, "dir")

    def record_location(self, rel: str, path: str) -> None:
        self.retained_locations[rel] = path

    def close(self) -> None:
        _ACTIVE_ARCHIVES.pop(self.root_fd, None)
        for descriptor in (self.root_fd, self.parent_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _identity(self) -> tuple[int, int]:
        info = os.fstat(self.root_fd)
        return info.st_dev, info.st_ino

    def _named_identity(self) -> tuple[int, int]:
        try:
            entry = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        except OSError:
            raise CleanupRefused from None
        if not stat.S_ISDIR(entry.st_mode):
            raise CleanupRefused
        return entry.st_dev, entry.st_ino

    def is_still_named(self) -> bool:
        try:
            return self._named_identity() == self._identity()
        except CleanupRefused:
            return False

    def cleanup(self) -> bool:
        identity = self._identity()
        if self._named_identity() != identity:
            raise CleanupRefused

        root_real = _fd_real_path(self.root_fd)
        parent_real = _fd_real_path(self.parent_fd)
        if root_real is None or parent_real is None:
            raise CleanupRefused
        if os.path.dirname(root_real) != parent_real:
            raise CleanupRefused

        if self.source_real is not None and (
            root_real == self.source_real
            or root_real.startswith(self.source_real + os.sep)
        ):
            raise CleanupRefused

        try:
            inventory = _inventory_fd(self.root_fd)
        except RecursionError:
            raise CleanupRefused from None
        if inventory != {**self.files, **self.dirs}:
            raise CleanupRefused

        try:
            for rel in sorted(list(self.files), reverse=True):
                _unlink_at(self.root_fd, rel)
                self.files.pop(rel, None)
            for rel in sorted(
                list(self.dirs), key=lambda path: (path.count("/"), path), reverse=True
            ):
                _rmdir_at(self.root_fd, rel)
                self.dirs.pop(rel, None)
            if self._named_identity() != identity:
                raise CleanupRefused
            current_root_real = _fd_real_path(self.root_fd)
            current_parent_real = _fd_real_path(self.parent_fd)
            if current_root_real is None or current_parent_real is None:
                raise CleanupRefused
            if os.path.dirname(current_root_real) != current_parent_real:
                raise CleanupRefused
            os.rmdir(self.name, dir_fd=self.parent_fd)
            return True
        except (OSError, SnapshotError):
            raise CleanupRefused from None

    def retained_paths(self) -> list[str]:
        retained: list[str] = []
        root_real = _fd_real_path(self.root_fd)
        for rel, info in list(self.files.items()):
            retained.append(rel)
            if rel in self.retained_locations:
                loc = self.retained_locations[rel]
                if loc not in retained:
                    retained.append(loc)
            elif root_real:
                candidate = os.path.join(root_real, rel)
                try:
                    st = os.stat(candidate, follow_symlinks=False)
                    if (st.st_dev, st.st_ino) == info[:2] and candidate not in retained:
                        retained.append(candidate)
                except OSError:
                    pass
        for rel, info in list(self.dirs.items()):
            retained.append(rel)
            if rel in self.retained_locations:
                loc = self.retained_locations[rel]
                if loc not in retained:
                    retained.append(loc)
            elif root_real:
                candidate = os.path.join(root_real, rel)
                try:
                    st = os.stat(candidate, follow_symlinks=False)
                    if (st.st_dev, st.st_ino) == info[:2] and candidate not in retained:
                        retained.append(candidate)
                except OSError:
                    pass
        return sorted(set(retained))


def _fail(code: str, **context: Any) -> None:
    raise SnapshotError(code, **context)


def _close_all(descriptors: list[int]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _open_dir_chain(path: str, code: str) -> int:
    """Open an absolute directory by walking every component without following symlinks."""
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != "/":
        _fail(code)
    descriptor = os.open("/", os.O_RDONLY | _O_DIRECTORY)
    for part in parts[1:]:
        try:
            child = os.open(
                part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=descriptor
            )
        except OSError:
            os.close(descriptor)
            _fail(code)
        os.close(descriptor)
        descriptor = child
    return descriptor


def _open_rel_parent(root_fd: int, rel: str, code: str) -> tuple[int, list[int]]:
    descriptor = root_fd
    opened: list[int] = []
    for part in rel.split("/")[:-1]:
        try:
            child = os.open(
                part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=descriptor
            )
        except OSError:
            _close_all(opened)
            _fail(code)
        opened.append(child)
        descriptor = child
    return descriptor, opened


def _open_regular_at(parent_fd: int, name: str, code: str) -> int:
    """Open one regular file without following symlinks or blocking on special files."""
    flags = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError:
        _fail(code)
    try:
        info = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        _fail(code)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        _fail(code)
    return descriptor


def _read_all_fd(descriptor: int, limit: int, code: str) -> bytes:
    chunks: list[bytes] = []
    budget = limit + 1
    try:
        while budget > 0:
            chunk = os.read(descriptor, min(budget, 1 << 16))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
    except OSError:
        _fail(code)
    return b"".join(chunks)


def _read_rel(root_fd: int, rel: str, code: str, limit: int) -> bytes:
    parent_fd, opened = _open_rel_parent(root_fd, rel, code)
    try:
        descriptor = _open_regular_at(parent_fd, rel.split("/")[-1], code)
        try:
            return _read_all_fd(descriptor, limit, code)
        finally:
            os.close(descriptor)
    finally:
        _close_all(opened)


def _ensure_dirs(root_fd: int, rel: str, owned: _OwnedArchive) -> None:
    descriptor = root_fd
    opened: list[int] = []
    prefix: list[str] = []
    for part in rel.split("/")[:-1]:
        prefix.append(part)
        rel_dir = "/".join(prefix)
        try:
            child = os.open(
                part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=descriptor
            )
        except FileNotFoundError:
            try:
                os.mkdir(part, 0o700, dir_fd=descriptor)
            except OSError:
                _close_all(opened)
                _fail("write_failed")
            try:
                child = os.open(
                    part, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=descriptor
                )
            except OSError:
                _close_all(opened)
                _fail("write_failed")
            try:
                info = os.fstat(child)
            except OSError:
                os.close(child)
                _close_all(opened)
                _fail("write_failed")
            owned.record_dir(rel_dir, info)
        except OSError:
            _close_all(opened)
            _fail("write_failed")
        try:
            mode = stat.S_IMODE(os.fstat(child).st_mode)
        except OSError:
            os.close(child)
            _close_all(opened)
            _fail("write_failed")
        if mode & 0o077:
            os.close(child)
            _close_all(opened)
            _fail("write_failed")
        opened.append(child)
        descriptor = child
    _close_all(opened)


def _write_file(
    root_fd: int, rel: str, data: bytes, owned: _OwnedArchive | None = None
) -> None:
    parent_fd, opened = _open_rel_parent(root_fd, rel, "write_failed")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
        try:
            descriptor = os.open(rel.split("/")[-1], flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            _fail("out_exists")
        except OSError:
            _fail("write_failed")
        try:
            info = os.fstat(descriptor)
        except OSError:
            os.close(descriptor)
            _fail("write_failed")
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(descriptor)
            _fail("write_failed")
        if owned is not None:
            owned.record_file(rel, info)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            _fail("write_failed")
    finally:
        _close_all(opened)


def _inventory_fd(descriptor: int) -> dict[str, tuple[int, int, str]]:
    """Typed FD-relative inventory: rel path -> (dev, ino, kind). Any surprise refuses."""
    try:
        names = os.listdir(descriptor)
    except OSError:
        raise CleanupRefused from None
    found: dict[str, tuple[int, int, str]] = {}
    for name in names:
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError:
            raise CleanupRefused from None
        if stat.S_ISDIR(info.st_mode):
            kind = "dir"
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
        else:
            raise CleanupRefused
        found[name] = (info.st_dev, info.st_ino, kind)
        if kind != "dir":
            continue
        try:
            child = os.open(
                name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=descriptor
            )
        except OSError:
            raise CleanupRefused from None
        try:
            for entry, typed in _inventory_fd(child).items():
                found[f"{name}/{entry}"] = typed
        finally:
            os.close(child)
    return found


def _scan_source_tree(source_real: str) -> dict[str, tuple[str, int, int]]:
    """Record all entries in the source tree (skipping excluded directories/paths)."""
    entries: dict[str, tuple[str, int, int]] = {}
    stack = [source_real]
    while stack:
        curr = stack.pop()
        try:
            with os.scandir(curr) as it:
                for entry in it:
                    rel = os.path.relpath(entry.path, source_real).replace(os.sep, "/")
                    if is_excluded_path(rel):
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    kind = (
                        "dir"
                        if stat.S_ISDIR(st.st_mode)
                        else ("link" if stat.S_ISLNK(st.st_mode) else "file")
                    )
                    entries[rel] = (kind, st.st_dev, st.st_ino)
                    if kind == "dir":
                        stack.append(entry.path)
        except OSError:
            pass
    return entries


def _find_new_source_entries(
    source_real: str, initial_entries: dict[str, tuple[str, int, int]]
) -> list[str]:
    """Find any entry in the source tree not present at start or whose identity changed."""
    current = _scan_source_tree(source_real)
    new_entries: list[str] = []
    for rel, info in current.items():
        if rel not in initial_entries or initial_entries[rel] != info:
            new_entries.append(rel)
    return sorted(new_entries)


def _unlink_at(
    root_fd: int, rel: str, owned: _OwnedArchive | None = None
) -> None:
    if owned is None:
        owned = _ACTIVE_ARCHIVES.get(root_fd)
    if owned is None:
        raise CleanupRefused

    parent_fd, opened = _open_rel_parent(root_fd, rel, "cleanup_failed")
    try:
        filename = rel.split("/")[-1]

        # Invariant C check 1: Verify parent_fd is contained within root_fd
        root_real = _fd_real_path(root_fd)
        parent_real = _fd_real_path(parent_fd)
        if root_real is None or parent_real is None:
            raise CleanupRefused
        if not (parent_real == root_real or parent_real.startswith(root_real + os.sep)):
            if parent_real:
                candidate = os.path.join(parent_real, filename)
                try:
                    st = os.stat(candidate, follow_symlinks=False)
                    if (st.st_dev, st.st_ino) == owned.files[rel][:2]:
                        owned.record_location(rel, candidate)
                except OSError:
                    pass
            raise CleanupRefused

        # Invariant C check 2: Verify parent directory inode
        parent_rel = "/".join(rel.split("/")[:-1])
        if parent_rel:
            expected_parent = owned.dirs.get(parent_rel)
            if expected_parent is None:
                raise CleanupRefused
            p_stat = os.fstat(parent_fd)
            if (p_stat.st_dev, p_stat.st_ino) != expected_parent[:2]:
                raise CleanupRefused
        else:
            p_stat = os.fstat(parent_fd)
            if (p_stat.st_dev, p_stat.st_ino) != owned._identity():
                raise CleanupRefused

        # Invariant C check 3: Verify entry identity without following symlinks
        try:
            st = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise CleanupRefused from None

        if not stat.S_ISREG(st.st_mode):
            raise CleanupRefused

        expected_file = owned.files.get(rel)
        if expected_file is None or (st.st_dev, st.st_ino) != expected_file[:2]:
            raise CleanupRefused

        os.unlink(filename, dir_fd=parent_fd)
    finally:
        _close_all(opened)


def _rmdir_at(
    root_fd: int, rel: str, owned: _OwnedArchive | None = None
) -> None:
    if owned is None:
        owned = _ACTIVE_ARCHIVES.get(root_fd)
    if owned is None:
        raise CleanupRefused

    parent_fd, opened = _open_rel_parent(root_fd, rel, "cleanup_failed")
    try:
        dirname = rel.split("/")[-1]

        # Invariant C check 1: Verify parent_fd is contained within root_fd
        root_real = _fd_real_path(root_fd)
        parent_real = _fd_real_path(parent_fd)
        if root_real is None or parent_real is None:
            raise CleanupRefused
        if not (parent_real == root_real or parent_real.startswith(root_real + os.sep)):
            if parent_real:
                candidate = os.path.join(parent_real, dirname)
                try:
                    st = os.stat(candidate, follow_symlinks=False)
                    if (st.st_dev, st.st_ino) == owned.dirs[rel][:2]:
                        owned.record_location(rel, candidate)
                except OSError:
                    pass
            raise CleanupRefused

        # Invariant C check 2: Verify parent directory inode
        parent_rel = "/".join(rel.split("/")[:-1])
        if parent_rel:
            expected_parent = owned.dirs.get(parent_rel)
            if expected_parent is None:
                raise CleanupRefused
            p_stat = os.fstat(parent_fd)
            if (p_stat.st_dev, p_stat.st_ino) != expected_parent[:2]:
                raise CleanupRefused
        else:
            p_stat = os.fstat(parent_fd)
            if (p_stat.st_dev, p_stat.st_ino) != owned._identity():
                raise CleanupRefused

        # Invariant C check 3: Verify directory identity without following symlinks
        try:
            st = os.stat(dirname, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            raise CleanupRefused from None

        if not stat.S_ISDIR(st.st_mode):
            raise CleanupRefused

        expected_dir = owned.dirs.get(rel)
        if expected_dir is None or (st.st_dev, st.st_ino) != expected_dir[:2]:
            raise CleanupRefused

        os.rmdir(dirname, dir_fd=parent_fd)
    finally:
        _close_all(opened)


def _cleanup_created(created: list[_OwnedArchive]) -> bool:
    if not created:
        return True
    try:
        return created[0].cleanup()
    except (CleanupRefused, SnapshotError, OSError, RecursionError):
        return False


def _is_hex(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _sha256_hex(value: object, code: str) -> str:
    if not _is_hex(value, 64):
        _fail(code)
    return str(value).lower()


def _fd_real_path(fd: int) -> str | None:
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None


def _assert_dest_not_in_source(fd: int, source_real: str) -> None:
    real_path = _fd_real_path(fd)
    if real_path is not None and (
        real_path == source_real or real_path.startswith(source_real + os.sep)
    ):
        _fail("source_output_alias")
    try:
        fd_stat = os.fstat(fd)
        src_stat = os.stat(source_real)
        if fd_stat.st_dev == src_stat.st_dev and fd_stat.st_ino == src_stat.st_ino:
            _fail("source_output_alias")
    except OSError:
        _fail("source_output_alias")


def validate_rel_path(rel: object) -> str:
    if not isinstance(rel, str) or not rel or len(rel) > 4096:
        _fail("invalid_path")
    if rel == MANIFEST_NAME:
        _fail("reserved_path")
    if rel.startswith("/") or "\\" in rel:
        _fail("invalid_path")
    try:
        rel.encode("utf-8")
    except UnicodeEncodeError:
        _fail("invalid_path")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in rel):
        _fail("invalid_path")
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        _fail("invalid_path")
    if any(part.casefold() == ".git" for part in parts):
        _fail("invalid_path")
    if PurePosixPath(rel).as_posix() != rel:
        _fail("invalid_path")
    return rel


def is_excluded_path(rel: str) -> bool:
    """Return True if path matches excluded categories.

    Excluded: .git, .venv, caches, captures, local storage, logs, credential files.
    """
    parts = rel.split("/")
    filename = parts[-1]
    name_lower = filename.lower()

    # .git, .venv, venv, env
    if any(p.casefold() in (".git", ".venv", "venv", "env") for p in parts):
        return True

    # Caches
    if any(
        p.casefold() in ("__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", ".cache")
        for p in parts
    ):
        return True
    if any(p.casefold().endswith((".pyc", ".pyo")) for p in parts):
        return True
    if any("cache" in p.casefold() for p in parts):
        return True

    # Java archives
    if filename.endswith(".jar") or any(p.casefold().endswith(".jar") for p in parts):
        return True

    # Captures
    if any("capture" in p.casefold() for p in parts):
        # Exclude unless part of captcha test/fixtures
        if not all("captcha" in p.casefold() for p in parts if "capture" in p.casefold()):
            return True
    if filename.endswith((".pcap", ".pcapng", ".har")):
        return True

    # Local storage
    if any(p.casefold() in ("local_storage", ".storage") for p in parts):
        return True
    if filename.endswith((".db", ".sqlite", ".sqlite3")):
        return True

    # Logs
    if any(p.casefold() == "logs" for p in parts):
        return True
    if name_lower.endswith(".log") or ".log." in name_lower:
        return True

    # Credentials
    if name_lower in (".env", "id_rsa", "id_ed25519") or name_lower.startswith(".env."):
        return True
    if name_lower.endswith((".key", ".pem", ".token", ".crt")):
        return True
    if "secret" in name_lower or "credential" in name_lower:
        return True

    return False


def _read_manifest_bytes(path: str | Path) -> bytes:
    try:
        info = os.lstat(path)
    except OSError:
        _fail("manifest_unreadable")
    if not stat.S_ISREG(info.st_mode):
        _fail("manifest_unreadable")
    if info.st_size > MAX_MANIFEST_BYTES:
        _fail("manifest_too_large")
    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError:
        _fail("manifest_unreadable")
    try:
        opened_info = os.fstat(descriptor)
        if not stat.S_ISREG(opened_info.st_mode):
            _fail("manifest_unreadable")
        raw = _read_all_fd(descriptor, MAX_MANIFEST_BYTES, "manifest_unreadable")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_MANIFEST_BYTES:
        _fail("manifest_too_large")
    return raw


def load_manifest(path: str | Path) -> dict[str, Any]:
    raw = _read_manifest_bytes(path)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _fail("invalid_manifest_json")
    if not isinstance(doc, dict):
        _fail("invalid_manifest_shape")

    head = doc.get("head")
    if not _is_hex(head, 40) and not _is_hex(head, 64):
        _fail("invalid_manifest_head")

    aggregates = []
    for key in ("sha256", "aggregate_sha256"):
        if key in doc:
            aggregates.append(_sha256_hex(doc[key], "invalid_manifest_aggregate"))
    if not aggregates:
        _fail("invalid_manifest_aggregate")
    if len(set(aggregates)) > 1:
        _fail("manifest_aggregate_conflict")

    entries = doc.get("paths")
    if not isinstance(entries, list):
        _fail("invalid_manifest_paths")
    seen = set()
    paths: list[tuple[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            _fail("invalid_manifest_paths")
        rel = validate_rel_path(entry.get("path"))
        if rel in seen:
            _fail("duplicate_path")
        if is_excluded_path(rel):
            _fail("excluded_path_in_manifest", path=rel)
        seen.add(rel)
        paths.append((rel, _sha256_hex(entry.get("sha256"), "invalid_file_hash")))

    for key in ("count", "files"):
        if key in doc:
            value = doc[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value != len(paths)
            ):
                _fail("invalid_manifest_count")

    return {
        "head": str(head).lower(),
        "aggregate": aggregates[0],
        "paths": paths,
    }


def compute_digest(files: dict[str, bytes]) -> str:
    """Compute aggregate SHA-256 over sorted rel path + NUL + exact bytes + NUL."""
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(files[rel])
        digest.update(b"\0")
    return digest.hexdigest()


def _git(repo: str, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", repo, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        _fail("git_error")
    if result.returncode != 0:
        _fail("git_error")
    return result.stdout


def _read_head(repo: str) -> str:
    head = _git(repo, "rev-parse", "--verify", "HEAD").strip()
    text = head.decode("ascii", "replace")
    if not _is_hex(text, 40) and not _is_hex(text, 64):
        _fail("head_unreadable")
    return text.lower()


def _git_status_paths(repo: str) -> set[str]:
    raw = _git(
        repo,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignore-submodules=all",
    )
    paths = set()
    fields = raw.split(b"\0")
    index = 0
    while index < len(fields):
        field = fields[index]
        index += 1
        if not field:
            continue
        if len(field) < 4 or field[2:3] != b" ":
            _fail("status_parse_error")
        code = field[:2].decode("ascii", "replace")
        encoded = field[3:]
        if "R" in code or "C" in code:
            _fail("unsupported_rename")
        if "D" in code:
            _fail("unsupported_deletion")
        if code in _UNMERGED or "U" in code:
            _fail("unsupported_unmerged")
        rel = os.fsdecode(encoded)
        try:
            rel.encode("utf-8")
        except UnicodeEncodeError:
            _fail("invalid_path")
        if not is_excluded_path(rel):
            paths.add(rel)
    return paths


def _source_path(source_real: str, rel: str) -> str:
    """Walk components with lstat so no symlink is traversed, then return the path."""
    current = source_real
    parts = rel.split("/")
    for offset, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except OSError:
            _fail("source_missing", path=rel)
        if stat.S_ISLNK(info.st_mode):
            _fail("source_symlink", path=rel)
        if offset < len(parts) - 1:
            if not stat.S_ISDIR(info.st_mode):
                _fail("source_not_directory", path=rel)
        elif not stat.S_ISREG(info.st_mode):
            _fail("source_not_regular", path=rel)
    return current


def _read_source_bytes(source_real: str, rel: str) -> bytes:
    _source_path(source_real, rel)
    root_fd = _open_dir_chain(source_real, "source_unreadable")
    try:
        data = _read_rel(root_fd, rel, "source_unreadable", MAX_FILE_BYTES)
    finally:
        os.close(root_fd)
    if len(data) > MAX_FILE_BYTES:
        _fail("file_too_large", path=rel)
    return data


def _collect(source_real: str, paths: list[tuple[str, str | None]]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    root_fd = _open_dir_chain(source_real, "source_unreadable")
    try:
        total = 0
        for rel, expected in paths:
            _source_path(source_real, rel)
            data = _read_rel(root_fd, rel, "source_unreadable", MAX_FILE_BYTES)
            total += len(data)
            if len(data) > MAX_FILE_BYTES:
                _fail("file_too_large", path=rel)
            if total > MAX_TOTAL_BYTES:
                _fail("snapshot_too_large")
            if expected is not None and hashlib.sha256(data).hexdigest() != expected:
                _fail("file_hash_mismatch", path=rel)
            files[rel] = data
    finally:
        os.close(root_fd)
    return files


def _verify_source_unchanged(
    source_real: str,
    head: str,
    initial_status: set[str],
    files: dict[str, bytes],
    is_git: bool,
    fail_code: str,
) -> None:
    if is_git:
        if _read_head(source_real) != head:
            _fail(fail_code)
        if _git_status_paths(source_real) != initial_status:
            _fail(fail_code)
    for rel, data in files.items():
        if _read_source_bytes(source_real, rel) != data:
            _fail(fail_code)


def _load_paths_from(source_real: str, paths_from: str | Path) -> list[str]:
    path_obj = Path(paths_from)
    if not path_obj.is_file():
        _fail("paths_from_missing")
    try:
        raw = _read_manifest_bytes(path_obj)
    except SnapshotError:
        _fail("paths_from_unreadable")

    paths: list[str] = []
    try:
        doc = json.loads(raw.decode("utf-8"))
        entries = doc.get("paths", doc) if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            _fail("invalid_paths_from_format")
        for entry in entries:
            p = entry.get("path") if isinstance(entry, dict) else entry
            if not isinstance(p, str):
                _fail("invalid_paths_from_format")
            paths.append(validate_rel_path(p))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        for line in raw.decode("utf-8", "replace").splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("#"):
                paths.append(validate_rel_path(line_str))

    seen = set()
    validated = []
    for rel in paths:
        if is_excluded_path(rel):
            _fail("excluded_path_in_paths_from", path=rel)
        _source_path(source_real, rel)
        if rel not in seen:
            seen.add(rel)
            validated.append(rel)
    return sorted(validated)


def _resolve_source_paths(
    source_real: str, paths_from: str | Path | None
) -> tuple[str, list[tuple[str, str | None]], bool, set[str]]:
    manifest_file = os.path.join(source_real, MANIFEST_NAME)
    is_snapshot = os.path.isfile(manifest_file)

    if is_snapshot:
        manifest = load_manifest(manifest_file)
        head = manifest["head"]
        all_manifest_paths = manifest["paths"]

        all_files = _collect(source_real, [(rel, h) for rel, h in all_manifest_paths])
        computed_full_aggregate = compute_digest(all_files)
        if computed_full_aggregate != manifest["aggregate"]:
            _fail("manifest_aggregate_mismatch")

        manifest_rel_set = {item[0] for item in all_manifest_paths}
        for root, _dirs, files in os.walk(source_real):
            for f in files:
                full = os.path.join(root, f)
                rel = os.path.relpath(full, source_real).replace(os.sep, "/")
                if rel != MANIFEST_NAME and rel not in manifest_rel_set and not is_excluded_path(rel):
                    _fail("unmanifested_source_file", path=rel)

        if paths_from is not None:
            specified = set(_load_paths_from(source_real, paths_from))
            chosen = [item for item in all_manifest_paths if item[0] in specified]
            if len(chosen) != len(specified):
                _fail("missing_path")
        else:
            chosen = all_manifest_paths

        return head, [(rel, expected) for rel, expected in chosen], False, set()

    git_dir = os.path.join(source_real, ".git")
    if not (os.path.isdir(git_dir) or os.path.isfile(git_dir)):
        _fail("not_git_repo")

    cdup = _git(source_real, "rev-parse", "--show-cdup").strip()
    if cdup:
        _fail("git_repo_subdir")

    head = _read_head(source_real)
    status_paths = _git_status_paths(source_real)

    tracked_raw = _git(source_real, "ls-files", "-z")
    tracked_paths: set[str] = set()
    for entry in tracked_raw.split(b"\0"):
        if not entry:
            continue
        rel = os.fsdecode(entry)
        if not is_excluded_path(rel):
            validate_rel_path(rel)
            _source_path(source_real, rel)
            tracked_paths.add(rel)

    included: set[str] = set(tracked_paths)

    if paths_from is not None:
        additions = _load_paths_from(source_real, paths_from)
        for rel in additions:
            if not any(rel.endswith(sfx) for sfx in ALLOWED_ADDITION_SUFFIXES):
                _fail("arbitrary_file_rejected", path=rel)
            included.add(rel)

    return head, [(rel, None) for rel in sorted(included)], True, status_paths


def _resolve_out(out: str | Path, source_real: str) -> tuple[str, str, str]:
    target = os.path.abspath(out)
    name = os.path.basename(target)
    parent = os.path.dirname(target)
    if not name or name in (".", "..") or not parent:
        _fail("out_path_invalid")
    if not os.path.isdir(parent):
        _fail("out_parent_missing")

    # Verify parent is opened without following symlinks where specified
    parent_real = os.path.realpath(parent)
    target_real = os.path.join(parent_real, name)

    # Check alias / containment (including through symlink ancestors) BEFORE existence
    if (
        target_real == source_real
        or target_real.startswith(source_real + os.sep)
        or parent_real == source_real
        or parent_real.startswith(source_real + os.sep)
        or source_real.startswith(target_real + os.sep)
    ):
        _fail("source_output_alias")

    # Destination reuse check
    if os.path.lexists(target) or os.path.lexists(target_real):
        _fail("out_exists")

    # Check if parent path has any symlink ancestors
    try:
        p_fd = _open_dir_chain(parent_real, "out_symlink_ancestor")
        os.close(p_fd)
    except SnapshotError:
        _fail("out_symlink_ancestor")

    return parent_real, name, target_real


def _manifest_bytes(head: str, aggregate: str, paths: list[tuple[str, str]]) -> bytes:
    doc = {
        "tool": MANIFEST_TOOL,
        "version": MANIFEST_VERSION,
        "head": head,
        "sha256": aggregate,
        "aggregate_sha256": aggregate,
        "count": len(paths),
        "paths": [{"path": rel, "sha256": digest} for rel, digest in sorted(paths)],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _create_archive(
    parent_real: str,
    name: str,
    source_real: str,
    files: dict[str, bytes],
    manifest_payload: bytes,
    created: list[_OwnedArchive],
) -> None:
    parent_fd = _open_dir_chain(parent_real, "out_parent_changed")
    owned = None
    root_fd = None
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            _fail("out_exists")
        except OSError:
            _fail("write_failed")
        try:
            root_fd = os.open(
                name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=parent_fd
            )
        except OSError:
            _fail("write_failed")
        if stat.S_IMODE(os.fstat(root_fd).st_mode) & 0o077:
            _fail("write_failed")

        _assert_dest_not_in_source(root_fd, source_real)

        owned = _OwnedArchive(parent_fd, name, root_fd, source_real=source_real)
        created.append(owned)
        for rel in sorted(files):
            _ensure_dirs(root_fd, rel, owned)
            _write_file(root_fd, rel, files[rel], owned)
        _write_file(root_fd, MANIFEST_NAME, manifest_payload, owned)
        _assert_dest_not_in_source(root_fd, source_real)
    except BaseException:
        if owned is None:
            if root_fd is not None:
                os.close(root_fd)
            os.close(parent_fd)
        raise


def _verify_archive(
    parent_real: str,
    name: str,
    files: dict[str, bytes],
    manifest_payload: bytes,
) -> None:
    parent_fd = _open_dir_chain(parent_real, "readback_failed")
    try:
        root_fd = os.open(
            name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=parent_fd
        )
    except OSError:
        os.close(parent_fd)
        _fail("readback_failed")
    try:
        for rel, data in files.items():
            readback_data = _read_rel(root_fd, rel, "readback_failed", MAX_FILE_BYTES)
            if readback_data != data:
                _fail("readback_failed")
        readback_manifest = _read_rel(
            root_fd, MANIFEST_NAME, "readback_failed", MAX_MANIFEST_BYTES
        )
        if readback_manifest != manifest_payload:
            _fail("readback_failed")
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def freeze(
    source: str | Path = ".", paths_from: str | Path | None = None
) -> dict[str, Any]:
    """Freeze source into an in-memory manifest dict with per-file and aggregate hashes."""
    source_real = os.path.realpath(source)
    if not os.path.isdir(source_real):
        _fail("source_not_found")

    initial_source_entries = _scan_source_tree(source_real)

    try:
        head, paths_spec, is_git, initial_status = _resolve_source_paths(
            source_real, paths_from
        )
        files = _collect(source_real, paths_spec)
        aggregate = compute_digest(files)

        _verify_source_unchanged(
            source_real, head, initial_status, files, is_git, "source_changed_during_freeze"
        )
        new_source_entries = _find_new_source_entries(
            source_real, initial_source_entries
        )
        if new_source_entries:
            _fail(
                "source_tree_changed",
                paths=new_source_entries,
                path=new_source_entries[0],
            )
    except BaseException:
        new_source_entries = _find_new_source_entries(
            source_real, initial_source_entries
        )
        if new_source_entries:
            _fail(
                "source_tree_changed",
                paths=new_source_entries,
                path=new_source_entries[0],
            )
        raise

    path_hashes = [
        {"path": rel, "sha256": hashlib.sha256(files[rel]).hexdigest()}
        for rel in sorted(files)
    ]
    return {
        "tool": MANIFEST_TOOL,
        "version": MANIFEST_VERSION,
        "head": head,
        "sha256": aggregate,
        "aggregate_sha256": aggregate,
        "count": len(files),
        "paths": path_hashes,
    }


def snapshot(
    source: str | Path,
    dest: str | Path,
    paths_from: str | Path | None = None,
) -> dict[str, Any]:
    """Safely snapshot source into a new independent directory dest."""
    source_real = os.path.realpath(source)
    if not os.path.isdir(source_real):
        _fail("source_not_found")

    initial_source_entries = _scan_source_tree(source_real)

    created: list[_OwnedArchive] = []
    try:
        head, paths_spec, is_git, initial_status = _resolve_source_paths(
            source_real, paths_from
        )
        files = _collect(source_real, paths_spec)
        aggregate = compute_digest(files)

        parent_real, name, target_real = _resolve_out(dest, source_real)

        path_hashes = [
            (rel, hashlib.sha256(files[rel]).hexdigest()) for rel in sorted(files)
        ]
        manifest_payload = _manifest_bytes(head, aggregate, path_hashes)

        try:
            _create_archive(parent_real, name, source_real, files, manifest_payload, created)
            _verify_archive(parent_real, name, files, manifest_payload)
        except SnapshotError:
            raise
        except OSError:
            _fail("write_failed")

        _verify_source_unchanged(
            source_real, head, initial_status, files, is_git, "source_changed_during_copy"
        )

        # Invariant B: SOURCE-TREE NO-NEW-ENTRIES CHECK (completion)
        new_source_entries = _find_new_source_entries(
            source_real, initial_source_entries
        )
        if new_source_entries:
            _fail(
                "source_tree_changed",
                paths=new_source_entries,
                path=new_source_entries[0],
            )

        if created and not created[0].is_still_named():
            _fail("out_replaced")

        # Invariant A: FINAL CONTAINMENT CHECK (must be the LAST step before returning success)
        if created:
            root_fd = created[0].root_fd
            real_dest = _fd_real_path(root_fd)
            if real_dest is None:
                _fail("out_replaced")
            if real_dest == source_real or real_dest.startswith(source_real + os.sep):
                _fail("source_output_alias")
            if real_dest != target_real:
                _fail("out_replaced")
            _assert_dest_not_in_source(root_fd, source_real)

    except BaseException as exc:
        cleanup_ok = _cleanup_created(created)
        # Invariant B: SOURCE-TREE NO-NEW-ENTRIES CHECK (failure path)
        new_source_entries = _find_new_source_entries(
            source_real, initial_source_entries
        )
        if new_source_entries:
            _fail(
                "source_tree_changed",
                paths=new_source_entries,
                path=new_source_entries[0],
            )
        if not cleanup_ok:
            retained: list[str] = []
            for owned in created:
                retained.extend(owned.retained_paths())
            retained = sorted(set(retained))
            if isinstance(exc, SnapshotError):
                exc.context["retained_paths"] = retained
                exc.context["retained"] = retained
                exc.context["paths"] = retained
                if retained:
                    exc.context["path"] = retained[0]
                raise exc
            _fail(
                "cleanup_failed",
                retained_paths=retained,
                retained=retained,
                paths=retained,
                path=retained[0] if retained else "",
            )
        raise
    finally:
        for owned in created:
            owned.close()

    return {
        "tool": MANIFEST_TOOL,
        "version": MANIFEST_VERSION,
        "head": head,
        "sha256": aggregate,
        "aggregate_sha256": aggregate,
        "count": len(files),
        "paths": [{"path": rel, "sha256": digest} for rel, digest in path_hashes],
        "dest": target_real,
    }
