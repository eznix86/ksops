"""SOPS binary wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .exceptions import KsopsError


def _format_stderr(error: subprocess.CalledProcessError) -> str:
    stderr = error.stderr.strip() if isinstance(error.stderr, str) else ""
    if "no identity matched any of the recipients" in stderr:
        return (
            "no matching age identity found; set SOPS_AGE_KEY_FILE or SOPS_AGE_KEY "
            "for one of the file recipients"
        )
    return stderr or f"exit status {error.returncode}"


class Sops:
    """Thin wrapper around the native sops binary."""

    def __init__(self, binary: str = "sops") -> None:
        self.binary = binary

    def run(
        self,
        args: list[str],
        operation: str,
        *,
        interactive: bool = False,
        success_codes: set[int] | None = None,
    ) -> str:
        """Run sops and return stdout."""
        command = [self.binary, *args]
        success_codes = success_codes or {0}
        try:
            if interactive:
                result = subprocess.run(command)
                if result.returncode not in success_codes:
                    raise subprocess.CalledProcessError(result.returncode, command)
                return ""

            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode not in success_codes:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    command,
                    output=result.stdout,
                    stderr=result.stderr,
                )
            return result.stdout
        except FileNotFoundError as e:
            raise KsopsError(f"sops binary not found: {self.binary}") from e
        except subprocess.CalledProcessError as e:
            raise KsopsError(f"sops {operation} failed: {_format_stderr(e)}") from e

    def edit(self, path: Path) -> None:
        """Open native sops edit flow."""
        self.run([str(path)], "edit", interactive=True, success_codes={0, 200})

    def decrypt(self, path: Path) -> str:
        """Decrypt a file to stdout."""
        return self.run(["-d", str(path)], "decrypt")

    def decrypt_in_place(self, path: Path) -> None:
        """Decrypt a file in-place."""
        self.run(["-d", "-i", str(path)], "decrypt")

    def encrypt(self, path: Path) -> str:
        """Encrypt a file to stdout."""
        return self.run(["-e", str(path)], "encrypt")

    def encrypt_in_place(self, path: Path) -> None:
        """Encrypt a file in-place."""
        self.run(["-e", "-i", str(path)], "encrypt")

    def update_keys(self, path: Path) -> None:
        """Update SOPS recipients from the current .sops.yaml policy."""
        self.run(["updatekeys", "-y", str(path)], "updatekeys")
