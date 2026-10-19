"""Durable local-file replacement; only Linux filesystems with fsync support."""
import os
import stat
import tempfile


def _sync_directory(directory):
    fd = os.open(os.fspath(directory), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_makedirs(directory):
    """Persist each new directory entry; existing parents are left untouched."""
    directory = os.path.abspath(os.fspath(directory))
    if os.path.isdir(directory):
        _sync_directory(os.path.dirname(directory))
        return
    parent = os.path.dirname(directory)
    durable_makedirs(parent)
    try:
        os.mkdir(directory)
    except FileExistsError:
        if not os.path.isdir(directory):
            raise
    _sync_directory(parent)


def atomic_write_durable(filename, data, mode=None):
    """Write bytes or UTF-8 text, fsync file, replace, then fsync parent.

    Existing permission bits are preserved unless mode is supplied; a new file
    defaults to 0644. Ownership follows the writing service, as for mkstemp.
    A sync failure after replace is reported; the new path must not be undone.
    """
    filename = os.path.abspath(os.fspath(filename))
    directory = os.path.dirname(filename)
    if mode is None:
        try:
            mode = stat.S_IMODE(os.stat(filename).st_mode)
        except FileNotFoundError:
            mode = 0o644
    if isinstance(data, str):
        data = data.encode('utf-8')
    fd, tmp = tempfile.mkstemp(prefix='.' + os.path.basename(filename) + '.', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, filename)
        _sync_directory(directory)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass  # Preserve the original write/sync error if cleanup also fails.
