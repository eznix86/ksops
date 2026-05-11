"""CLI commands for ksops."""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import click
from click.shell_completion import shell_complete

from . import __version__
from .exceptions import KsopsError
from .files import find_plaintext_secret_files, find_sops_files, validate_files
from .sops import Sops

DEFAULT_CONFIG = Path(".sops.yaml")


def write_default_config(
    path: Path,
    *,
    age: str | None = None,
    force: bool = False,
    path_regex: str = r".*secret.*\.ya?ml$",
    encrypted_regex: str = r"^(data|stringData)$",
) -> Path:
    """Write a starter .sops.yaml config."""
    if path.exists() and not force:
        raise FileExistsError(path)
    if not age:
        raise KsopsError("provide --age to create an encryptable .sops.yaml")

    lines = [
        "creation_rules:",
        f"  - path_regex: {path_regex}",
        f"    encrypted_regex: {encrypted_regex}",
        f"    age: {age}",
    ]

    path.write_text("\n".join(lines) + "\n")
    return path


def _completion_script(shell: str) -> str:
    """Return Click's generated shell completion script."""
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exit_code = shell_complete(main, {}, "ksops", "_KSOPS_COMPLETE", f"{shell}_source")
    if exit_code != 0:
        raise KsopsError(f"Unsupported shell: {shell}")
    return output.getvalue()


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """ksops - A SOPS companion CLI for Kubernetes secrets."""


@main.command()
@click.option("--age", help="Age recipient to include in the starter .sops.yaml")
@click.option("-f", "--force", is_flag=True, help="Overwrite an existing .sops.yaml")
def init(age: str | None, force: bool) -> None:
    """Create a starter .sops.yaml."""
    try:
        config_path = write_default_config(DEFAULT_CONFIG, age=age, force=force)
        click.echo(f"Created {config_path}")
    except FileExistsError:
        click.echo(".sops.yaml already exists. Use --force to overwrite.", err=True)
        sys.exit(1)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def edit(path: Path) -> None:
    """Edit a SOPS-encrypted file with native sops."""
    try:
        Sops().edit(path)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def cat(path: Path) -> None:
    """Decrypt a file to stdout."""
    try:
        click.echo(Sops().decrypt(path), nl=False)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--in-place", is_flag=True, help="Replace the input file")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file path")
def encrypt(path: Path, in_place: bool, output: Path | None) -> None:
    """Encrypt a plaintext file with sops."""
    if in_place and output:
        click.echo("Cannot use both --in-place and --output", err=True)
        sys.exit(2)

    try:
        sops = Sops()
        if in_place:
            sops.encrypt_in_place(path)
            click.echo(f"Encrypted {path}")
        else:
            encrypted = sops.encrypt(path)
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(encrypted)
                click.echo(f"Encrypted to {output}")
            else:
                click.echo(encrypted, nl=False)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command("encrypt-all")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def encrypt_all(path: Path) -> None:
    """Encrypt every plaintext Kubernetes Secret YAML file under a path."""
    files = find_plaintext_secret_files(path)
    if not files:
        click.echo("No plaintext Kubernetes Secret YAML files found.")
        return

    errors: list[str] = []
    sops = Sops()
    for file_path in files:
        try:
            sops.encrypt_in_place(file_path)
        except KsopsError as e:
            errors.append(f"{file_path}: {e}")

    click.echo(f"Encrypted {len(files) - len(errors)} file(s)")
    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--in-place", is_flag=True, help="Replace the input file")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file path")
def decrypt(path: Path, in_place: bool, output: Path | None) -> None:
    """Decrypt a SOPS-encrypted file."""
    if in_place and output:
        click.echo("Cannot use both --in-place and --output", err=True)
        sys.exit(2)

    try:
        sops = Sops()
        if in_place:
            sops.decrypt_in_place(path)
            click.echo(f"Decrypted {path}")
        else:
            decrypted = sops.decrypt(path)
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(decrypted)
                click.echo(f"Decrypted to {output}")
            else:
                click.echo(decrypted, nl=False)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def rekey(path: Path) -> None:
    """Update SOPS recipients for one file from .sops.yaml."""
    try:
        Sops().update_keys(path)
        click.echo(f"Rekeyed {path}")
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command("rekey-all")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def rekey_all(path: Path) -> None:
    """Update SOPS recipients for every SOPS YAML file under a path."""
    files = find_sops_files(path)
    if not files:
        click.echo("No SOPS-encrypted YAML files found.")
        return

    errors: list[str] = []
    sops = Sops()
    for file_path in files:
        try:
            sops.update_keys(file_path)
        except KsopsError as e:
            errors.append(f"{file_path}: {e}")

    click.echo(f"Rekeyed {len(files) - len(errors)} file(s)")
    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        sys.exit(1)


@main.command("validate-all")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
def validate_all(path: Path) -> None:
    """Validate SOPS files and plaintext Kubernetes Secret leaks."""
    encrypted_count, errors = validate_files(path, Sops())
    if errors:
        for error in errors:
            click.echo(f"Error: {error}", err=True)
        sys.exit(1)

    click.echo(f"Validated {encrypted_count} SOPS-encrypted file(s)")


@main.command()
@click.argument("shell", type=click.Choice(["bash", "zsh"]))
def completion(shell: str) -> None:
    """Print shell completion script for bash or zsh."""
    try:
        click.echo(_completion_script(shell), nl=False)
    except KsopsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
