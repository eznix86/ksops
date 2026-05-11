"""SOPS binary wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .exceptions import KsopsError


def _format_stderr(error: subprocess.CalledProcessError) -> str:
    stderr = error.stderr.strip() if isinstance(error.stderr, str) else ""
    return stderr or f"exit status {error.returncode}"


class Sops:
    """Thin wrapper around the native sops binary."""

    def __init__(self, binary: str = "sops") -> None:
        self.binary = binary

    def run(self, args: list[str], operation: str, *, capture: bool = True) -> str:
        """Run sops and return stdout when captured."""
        command = [self.binary, *args]
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=capture,
                text=True,
            )
            return result.stdout if capture else ""
        except FileNotFoundError as e:
            raise KsopsError(f"sops binary not found: {self.binary}") from e
        except subprocess.CalledProcessError as e:
            raise KsopsError(f"sops {operation} failed: {_format_stderr(e)}") from e

    def edit(self, path: Path) -> None:
        """Open native sops edit flow."""
        self.run([str(path)], "edit", capture=False)

    def decrypt(self, path: Path) -> str:
        """Decrypt a file to stdout."""
        return self.run(["-d", str(path)], "decrypt")

    def decrypt_in_place(self, path: Path) -> None:
        """Decrypt a file in-place."""
        self.run(["-d", "-i", str(path)], "decrypt", capture=False)

    def encrypt(self, path: Path) -> str:
        """Encrypt a file to stdout."""
        return self.run(["-e", str(path)], "encrypt")

    def encrypt_in_place(self, path: Path) -> None:
        """Encrypt a file in-place."""
        self.run(["-e", "-i", str(path)], "encrypt", capture=False)

    def update_keys(self, path: Path) -> None:
        """Update SOPS recipients from the current .sops.yaml policy."""
        self.run(["updatekeys", "-y", str(path)], "updatekeys", capture=False)
