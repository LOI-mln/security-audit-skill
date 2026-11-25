#!/usr/bin/env python3
"""Promote allowlisted result files from an agent's scratch/ into retained artifacts/.

Trusted parent-side reference implementation, for POSIX systems, of the 11-step
promotion procedure in SKILL.md "Write isolation". Run it only after the
sandbox and all of its processes have terminated.

Usage:
  promote-artifact.py --scratch-root DIR --artifacts-root DIR
                      --max-file-bytes N --max-total-bytes N RELATIVE/PATH...

Each RELATIVE/PATH is promoted from the scratch root to the same relative path
under the artifacts root. stdout gets "PROMOTED <path> <bytes> sha256=<hex>" per
success, stderr gets "REJECT <path>: <reason>" per failure. Exit status: 0 every
file promoted, 1 any file rejected, 2 usage error, 3 platform support missing.

Where each step of the procedure lives:
  1   validate_relative_path: rejects absolute, empty, ".", "..", backslash, NUL,
      control characters, and more than 16 components. Symlinked components
      are refused by the no-follow opens of steps 2, 3, and 7.
  2   open_parent: no-follow opens relative to the retained scratch-root
      descriptor, never by path.
  3   read_source: leaf opened O_NOFOLLOW | O_NONBLOCK.
  4   read_source: fstat shows a regular file, link count 1, within the per-file
      limit and the remaining cumulative limit.
  5   read_exact: the limits are enforced again while reading.
  6   read_source: exactly the verified size is copied, then a second fstat must
      match in device, inode, type, link count, size, and mtime.
  7   open_parent(create=True): the same walk from the retained artifacts-root
      descriptor; an existing component must be a real directory, a missing
      one is created exclusively, then reopened no-follow and verified.
  8   write_destination: O_CREAT | O_EXCL | O_NOFOLLOW leaf, fstat shows a regular
      file with link count 1, the verified bytes are written, fsync.
  9   platform_supported: no non-POSIX equivalent is implemented, so exit 3.
  10  main: only the listed files, one at a time; nothing is globbed, recursed
      into, or extracted. Steps 3, 4, and 6 refuse every non-regular, linked,
      changing, or oversized file.
  11  main, write_destination: a failed file is reported with its exact blocker
      and is not retained; a partial destination leaf is unlinked.
"""

import argparse
import errno
import hashlib
import os
import stat
import sys
import unicodedata

MAX_COMPONENTS = 16
READ_CHUNK = 1 << 16


class Reject(Exception):
    """This file must not be promoted; the message is the promotion blocker."""


def platform_supported():
    """Step 9."""
    flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC")
    return (os.name == "posix" and all(getattr(os, flag, 0) for flag in flags)
            and all(function in os.supports_dir_fd for function in (os.open, os.mkdir, os.unlink)))


def open_directory(name, dir_fd=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def describe(error):
    return f"{error.strerror} ({errno.errorcode.get(error.errno, error.errno)})"


def printable(text):
    return "".join(char if char.isprintable() else "?" for char in text)


def identity(status):
    return (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode),
            status.st_nlink, status.st_size, status.st_mtime_ns)


def validate_relative_path(path):
    """Step 1. Returns the path components."""
    if not path:
        raise Reject("path is empty")
    if path.startswith("/"):
        raise Reject("path is absolute")
    if "\\" in path:
        raise Reject("path contains a backslash")
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in path):
        raise Reject("path contains a NUL, control, or undecodable character")
    parts = path.split("/")
    if len(parts) > MAX_COMPONENTS:
        raise Reject(f"path has more than {MAX_COMPONENTS} components")
    for part in parts:
        if part in ("", ".", ".."):
            raise Reject(f"path has {'a ' + repr(part) if part else 'an empty'} component")
    return parts


def open_parent(root_fd, parents, side, create=False):
    """Steps 2 and 7. Returns a new descriptor for the directory that holds the leaf."""
    fd = os.dup(root_fd)
    try:
        for name in parents:
            try:
                try:
                    child = open_directory(name, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(name, 0o700, dir_fd=fd)  # fails if anything exists at this name by now
                    child = open_directory(name, dir_fd=fd)
            except OSError as error:
                raise Reject(f"{side} directory {name!r} is not a real directory: {describe(error)}")
            os.close(fd)
            fd = child
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise Reject(f"{side} directory {name!r} is not a directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_exact(fd, size):
    """Step 5. Never reads past the verified size; detects shrinking and growth."""
    chunks, received = [], 0
    while received < size:
        chunk = os.read(fd, min(READ_CHUNK, size - received))
        if not chunk:
            raise Reject("source shrank while it was being read")
        chunks.append(chunk)
        received += len(chunk)
    if os.read(fd, 1):
        raise Reject("source grew past its verified size while it was being read")
    return b"".join(chunks)


def read_source(parent_fd, leaf, max_file_bytes, remaining_bytes):
    """Steps 3 to 6. Returns the verified content."""
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError as error:
        raise Reject(f"source cannot be opened without following links: {describe(error)}")
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Reject(f"source is not a regular file (mode {stat.filemode(before.st_mode)})")
        if before.st_nlink != 1:
            raise Reject(f"source link count is {before.st_nlink}, expected exactly 1")
        if before.st_size > max_file_bytes:
            raise Reject(f"source size {before.st_size} exceeds the per-file limit {max_file_bytes}")
        if before.st_size > remaining_bytes:
            raise Reject(f"source size {before.st_size} exceeds the remaining cumulative limit {remaining_bytes}")
        data = read_exact(fd, before.st_size)
        if identity(os.fstat(fd)) != identity(before):
            raise Reject("source changed while it was being copied")
        return data
    finally:
        os.close(fd)


def write_destination(parent_fd, leaf, data):
    """Step 8, and the partial-file removal of step 11."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
    except FileExistsError:
        raise Reject("destination already exists and is never overwritten")
    except OSError as error:
        raise Reject(f"destination cannot be created exclusively: {describe(error)}")
    try:
        created = os.fstat(fd)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise Reject("created destination is not a regular file with link count 1")
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except BaseException as failure:
        try:  # this process created the entry exclusively above, so it is ours to remove
            os.unlink(leaf, dir_fd=parent_fd)
        except OSError as error:
            raise Reject(f"{failure}; the partial destination could not be removed: {describe(error)}")
        raise
    finally:
        os.close(fd)


def promote(scratch_fd, artifacts_fd, path, max_file_bytes, remaining_bytes):
    """Promote one file. Returns (size, sha256 hex), or raises Reject or OSError."""
    *parents, leaf = validate_relative_path(path)
    source_dir = open_parent(scratch_fd, parents, "source")
    try:
        data = read_source(source_dir, leaf, max_file_bytes, remaining_bytes)
    finally:
        os.close(source_dir)
    # The destination is touched only after the source is fully verified.
    destination_dir = open_parent(artifacts_fd, parents, "destination", create=True)
    try:
        write_destination(destination_dir, leaf, data)
    finally:
        os.close(destination_dir)
    return len(data), hashlib.sha256(data).hexdigest()


def byte_limit(text):
    if not (text.isascii() and text.isdigit()):
        raise argparse.ArgumentTypeError("must be a non-negative integer number of bytes")
    return int(text)


def main(argv=None):
    if not platform_supported():
        print("promote-artifact: no-follow, directory-relative file operations are not available "
              "on this platform; nothing was promoted", file=sys.stderr)
        return 3
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.splitlines()[0])
    parser.add_argument("--scratch-root", required=True, metavar="DIR")
    parser.add_argument("--artifacts-root", required=True, metavar="DIR")
    parser.add_argument("--max-file-bytes", required=True, type=byte_limit, metavar="N")
    parser.add_argument("--max-total-bytes", required=True, type=byte_limit, metavar="N")
    parser.add_argument("paths", nargs="+", metavar="RELATIVE/PATH")
    args = parser.parse_args(argv)  # exits 2 on a usage error

    # Both roots are opened once; everything later is relative to these descriptors.
    try:
        scratch_fd, artifacts_fd = open_directory(args.scratch_root), open_directory(args.artifacts_root)
    except OSError as error:
        print(f"promote-artifact: root {error.filename!r} is not a real directory: {describe(error)}",
              file=sys.stderr)
        return 2
    if os.path.samestat(os.fstat(scratch_fd), os.fstat(artifacts_fd)):
        print("promote-artifact: --scratch-root and --artifacts-root are the same directory", file=sys.stderr)
        return 2

    remaining_bytes = args.max_total_bytes
    rejected = False
    for path in args.paths:  # steps 10 and 11: listed files only, each one separately
        try:
            size, digest = promote(scratch_fd, artifacts_fd, path, args.max_file_bytes, remaining_bytes)
        except (Reject, OSError) as blocker:
            reason = str(blocker) if isinstance(blocker, Reject) else f"I/O error: {describe(blocker)}"
            print(f"REJECT {printable(path)}: {reason}", file=sys.stderr, flush=True)
            rejected = True
        else:
            remaining_bytes -= size
            print(f"PROMOTED {printable(path)} {size} sha256={digest}", flush=True)
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
