"""Helpers to validate SSH connectivity for targets."""

from __future__ import annotations

from time import perf_counter
from typing import Any, Dict

from app.adapters.ssh import SshClient
from app.core.errors import AdapterError
from app.db import models


def validate_ssh_connection(target: models.Target, timeout: int = 10) -> Dict[str, Any]:
    connection = target.connection_info or {}
    credentials = target.credentials or {}

    host = connection.get("host") or connection.get("ip")
    user = credentials.get("username")
    key_path = credentials.get("key_path")
    password = credentials.get("password")
    port_raw = connection.get("port", 22)

    if not host:
        raise ValueError("SSH host is required")
    if not user:
        raise ValueError("SSH username is required")
    if not key_path and not password:
        raise ValueError("SSH key_path or password is required")

    try:
        port = int(port_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid SSH port") from exc

    client = SshClient(
        host=host,
        user=user,
        key_path=key_path,
        password=password,
        port=port,
        timeout=timeout,
        proxy_jump=connection.get("proxy_jump"),
        proxy_command=connection.get("proxy_command"),
        identities_only=bool(connection.get("identities_only", False)),
    )

    start = perf_counter()
    try:
        result = client.run("echo __vuln_inspector_ok__")
    except AdapterError as exc:
        duration_ms = int((perf_counter() - start) * 1000)
        return {
            "success": False,
            "message": str(exc),
            "duration_ms": duration_ms,
            "stdout": None,
            "stderr": None,
            "host": host,
            "port": port,
            "user": user,
        }

    duration_ms = int((perf_counter() - start) * 1000)
    if result.exit_code != 0:
        message = result.stderr.strip() or f"SSH exit code {result.exit_code}"
        return {
            "success": False,
            "message": message,
            "duration_ms": duration_ms,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "host": host,
            "port": port,
            "user": user,
        }

    return {
        "success": True,
        "message": "SSH connection ok",
        "duration_ms": duration_ms,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "host": host,
        "port": port,
        "user": user,
    }
