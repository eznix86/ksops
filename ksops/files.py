"""File discovery and validation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from .exceptions import KsopsError
from .sops import Sops

yaml = YAML(typ="safe")


def is_yaml_file(path: Path) -> bool:
    """Return True when path is a YAML file."""
    return path.suffix in {".yaml", ".yml"}


def find_yaml_files(root: Path) -> list[Path]:
    """Find YAML files under a file or directory."""
    if root.is_file():
        return [root] if is_yaml_file(root) else []

    files: list[Path] = []
    for pattern in ("*.yaml", "*.yml"):
        files.extend(path for path in root.rglob(pattern) if ".git" not in path.parts)
    return sorted(files)


def load_yaml_docs(path: Path) -> list[dict[str, Any]]:
    """Load YAML documents from a file."""
    try:
        docs = list(yaml.load_all(path.read_text()))
    except Exception as e:
        raise KsopsError(f"invalid YAML: {e}") from e

    return [doc for doc in docs if isinstance(doc, dict)]


def has_sops_metadata(path: Path) -> bool:
    """Return whether any YAML document has SOPS metadata."""
    return any("sops" in doc for doc in load_yaml_docs(path))


def has_plaintext_kubernetes_secret(path: Path) -> bool:
    """Return whether a file contains a non-SOPS Kubernetes Secret with data fields."""
    for doc in load_yaml_docs(path):
        if doc.get("kind") != "Secret" or "sops" in doc:
            continue
        data = doc.get("data") or doc.get("stringData")
        if isinstance(data, dict) and data:
            return True
    return False


def find_sops_files(root: Path) -> list[Path]:
    """Find YAML files that contain SOPS metadata."""
    result: list[Path] = []
    for path in find_yaml_files(root):
        try:
            if has_sops_metadata(path):
                result.append(path)
        except KsopsError:
            continue
    return result


def find_plaintext_secret_files(root: Path) -> list[Path]:
    """Find YAML files that contain plaintext Kubernetes Secrets."""
    result: list[Path] = []
    for path in find_yaml_files(root):
        try:
            if not has_sops_metadata(path) and has_plaintext_kubernetes_secret(path):
                result.append(path)
        except KsopsError:
            continue
    return result


def validate_files(root: Path, sops: Sops) -> tuple[int, list[str]]:
    """Validate YAML files for SOPS metadata, decryptability, and plaintext Secret leaks."""
    encrypted_count = 0
    errors: list[str] = []

    for path in find_yaml_files(root):
        try:
            encrypted = has_sops_metadata(path)
            if encrypted:
                encrypted_count += 1
                sops.decrypt(path)
            elif has_plaintext_kubernetes_secret(path):
                errors.append(f"{path}: plaintext Kubernetes Secret")
        except KsopsError as e:
            errors.append(f"{path}: {e}")

    return encrypted_count, errors
