import fcntl
import os
import stat
import threading

TMP_BASE = "/tmp/app_work"

class SecurityError(OSError):
    """Raised when a temp-file operation fails a security invariant."""


_FILE_MODE = 0o777
_DIR_MODE = 0o700
_RANDOM_BYTES = 16

_registry_lock = threading.Lock()
_reserved_paths: dict[str, set[str]] = {}


def _validate_user_id(user_id: str) -> None:
    if not isinstance(user_id, str):
        raise TypeError("user_id must be a string")
    if not user_id:
        raise ValueError("user_id must not be empty")
    if "\x00" in user_id:
        raise ValueError("user_id contains a NUL byte")
    if "/" in user_id or "\\" in user_id or os.sep in user_id:
        raise ValueError("user_id must not contain path separators")
    if ".." in user_id:
        raise ValueError("user_id must not contain path traversal sequences")


def _ensure_base_dir() -> None:
    try:
        os.mkdir(TMP_BASE, _DIR_MODE)
    except FileExistsError:
        pass
    st = os.stat(TMP_BASE)
    if not os.path.isdir(TMP_BASE) or st.st_uid != os.getuid():
        raise SecurityError(
            f"temp base dir {TMP_BASE!r} is missing, not a directory, "
            "or not owned by the current user"
        )


def _mint_path(user_id: str) -> str:
    token = os.urandom(_RANDOM_BYTES).hex()
    return os.path.join(TMP_BASE, f"user_{user_id}_{token}.tmp")


def _hardened_umask() -> int:
    """Reset a fully restrictive sandbox umask so the fixed create mode is
    honoured, while preserving ordinary umask-based hardening.

    Returns the original umask that must be restored after the create call.
    """
    current = os.umask(0)
    if current == 0o077:
        return current
    os.umask(current)
    return current


def _open_exclusive_locked(path: str) -> int:
    """Create the file atomically with O_EXCL, take an exclusive flock that
    stays owned by the caller until close, and verify ownership on the open
    descriptor so no TOCTOU window remains."""
    restore_umask = _hardened_umask()
    try:
        fd = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            _FILE_MODE,
        )
    finally:
        os.umask(restore_umask)

    try:
        os.set_inheritable(fd, False)
        fcntl.flock(fd, fcntl.LOCK_EX)
        stat_info = os.fstat(fd)
        if stat_info.st_uid != os.getuid():
            raise SecurityError(
                f"file {path!r} owner uid={stat_info.st_uid} does not "
                f"match current uid={os.getuid()}"
            )
        if not stat.S_ISREG(stat_info.st_mode):
            raise SecurityError(f"file {path!r} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _create_locked_path(user_id: str) -> tuple[str, int]:
    for _ in range(8):
        candidate = _mint_path(user_id)
        try:
            fd = _open_exclusive_locked(candidate)
        except FileExistsError:
            continue
        return candidate, fd
    raise SecurityError("could not allocate a unique temp filename")


def get_user_tmp_path(user_id: str) -> str:
    _ensure_base_dir()
    _validate_user_id(user_id)
    path, fd = _create_locked_path(user_id)
    os.close(fd)
    with _registry_lock:
        _reserved_paths.setdefault(user_id, set()).add(path)
    return path


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    view = view.cast("b")
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write to temp file")
        view = view[written:]
    os.fsync(fd)

def write_user_temp(user_id: str, payload: bytes):
    _ensure_base_dir()
    _validate_user_id(user_id)
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")

    with _registry_lock:
        reserved = _reserved_paths.get(user_id)
        if reserved:
            stale = reserved.pop()
            if not reserved:
                del _reserved_paths[user_id]
            raise SecurityError(
                f"refusing to write through a pre-issued path {stale!r}: "
                "possible TOCTOU/symlink/append race"
            )

    path = ""
    fd = -1
    try:
        path, fd = _create_locked_path(user_id)
        _write_all(fd, payload)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
        raise
    else:
        os.close(fd)
        return path


_ensure_base_dir()
