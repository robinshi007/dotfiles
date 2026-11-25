"""Standalone guard embedded in the Fail2ban jail; compatible with distro Python."""

import hashlib
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
from pathlib import Path
from time import monotonic


def trusted_log(path: Path, caddy_uid: int) -> bool:
    if not path.is_absolute() or ".." in path.parts:
        return False
    dir_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    fd = os.open(path.anchor, dir_flags)
    try:
        root = os.fstat(fd)
        if root.st_uid != 0 or root.st_mode & 0o022:
            return False
        for index, component in enumerate(path.parts[1:-1]):
            child = os.open(component, dir_flags, dir_fd=fd)
            os.close(fd)
            fd = child
            meta = os.fstat(fd)
            owner = caddy_uid if index == len(path.parts) - 3 else 0
            if meta.st_uid != owner or meta.st_mode & 0o022:
                return False
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        log = os.open(path.name, flags, dir_fd=fd)
        try:
            meta = os.fstat(log)
            return (
                stat.S_ISREG(meta.st_mode)
                and meta.st_uid == caddy_uid
                and not meta.st_mode & 0o022
                and meta.st_nlink == 1
            )
        finally:
            os.close(log)
    finally:
        os.close(fd)


def service() -> tuple[int, str]:
    response = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "--property=ActiveState,LoadState,MainPID,InvocationID",
            "caddy.service",
        ],
        check=True,
        capture_output=True,
        encoding="ascii",
        timeout=2,
    )
    data = dict(line.split("=", 1) for line in response.stdout.splitlines() if "=" in line)
    pid = int(data.get("MainPID", "0"))
    invocation = data.get("InvocationID", "")
    if (
        data.get("ActiveState") != "active"
        or data.get("LoadState") != "loaded"
        or pid <= 1
        or not re.fullmatch(r"[0-9a-f]{32}", invocation)
        or invocation == "0" * 32
    ):
        raise ValueError("unknown Caddy service identity")
    return pid, invocation


def runtime_digest(admin: str, pid: int) -> str:
    deadline = monotonic() + 2
    limit = 1 << 20
    response = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect(admin)
        creds = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        peer, _, _ = struct.unpack("3i", creds)
        if peer != pid:
            raise ValueError("wrong Caddy admin socket peer")
        stream.sendall(b"GET /config/ HTTP/1.0\r\nHost:\r\nConnection: close\r\n\r\n")
        while len(response) < limit:
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("Caddy admin response timed out")
            stream.settimeout(remaining)
            chunk = stream.recv(min(65536, limit - len(response)))
            if not chunk:
                header, separator, body = response.partition(b"\r\n\r\n")
                if not separator or not header.startswith(b"HTTP/1.0 200 "):
                    raise ValueError("invalid Caddy admin response")
                return hashlib.sha256(body.rstrip(b"\n")).hexdigest()
            response.extend(chunk)
    raise ValueError("oversized Caddy admin response")


def permits(digest: str, admin: str, log: Path) -> bool:
    try:
        before = service()
        return (
            trusted_log(log, pwd.getpwnam("caddy").pw_uid)
            and runtime_digest(admin, before[0]) == digest
            and service() == before
        )
    except OSError, ValueError, KeyError, subprocess.SubprocessError:
        return False


if __name__ == "__main__":
    sys.exit(42 if permits(sys.argv[1], sys.argv[2], Path(sys.argv[3])) else 0)
