from app.adapters.ssh import SshClient
from pathlib import Path
from typing import Optional
from app.core.errors import PluginConfigError
from plugins.remote.utils.text import strip_comments

class RemoteFile:
    def __init__(self, path: Path, raw: str, lines: list[str]) -> None:
        self.path = path
        self.raw = raw
        self.lines = lines

    def __repr__(self) -> str:
        return f"RemoteFile(path={self.path!r})"

def ssh_read_config(target:dict, path: Path, config: dict) -> Optional[RemoteFile]:
    connection = target.get("connection_info", {}) or {}
    credentials = target.get("credentials", {}) or {}
    
    host = connection.get("host") or connection.get("ip")
    user = credentials.get("username")
    
    key_path = credentials.get("key_path")
    password = credentials.get("password")
    port = int(connection.get("port", 22))
    
    proxy_jump = connection.get("proxy_jump")
    proxy_command = connection.get("proxy_command")
    identities_only = bool(connection.get("identities_only", False))

    if not host or not user:
        return None
    if not key_path and not password:
        return None

    client = SshClient(
        host=host,
        user=user,
        key_path=key_path,
        password=password,
        port=port,
        proxy_jump=proxy_jump,
        proxy_command=proxy_command,
        identities_only=identities_only,
        sudo=bool(config.get("use_sudo", False)),
        sudo_user=config.get("sudo_user"),
    )
    result = client.run(f"cat {path}")
    if result.exit_code != 0:
        err = (result.stderr or result.stdout or "").strip()
        if (
            "No such file or directory" in err
            or err.startswith("cat:")
        ):
            return None
        raise PluginConfigError(f"SSH command failed: {err}")
    raw = result.stdout
    lines = strip_comments(result.stdout.splitlines())
    return RemoteFile(path=path, raw=raw, lines=lines)