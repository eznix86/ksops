"""Tests for ksops CLI commands."""

from __future__ import annotations

import subprocess
from pathlib import Path

from click.testing import CliRunner

from ksops.cli import main
from ksops.exceptions import KsopsError
from ksops.files import (
    find_sops_files,
    find_yaml_files,
    has_plaintext_kubernetes_secret,
    has_sops_metadata,
)
from ksops.sops import Sops


def completed(stdout: str = "") -> subprocess.CompletedProcess[str]:
    """Return a successful subprocess result."""
    return subprocess.CompletedProcess(["sops"], 0, stdout=stdout, stderr="")


def test_init_creates_sops_yaml() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--age", "age1example"])

        assert result.exit_code == 0
        content = Path(".sops.yaml").read_text()
        assert "creation_rules:" in content
        assert "encrypted_regex: ^(data|stringData)$" in content
        assert "age: age1example" in content


def test_init_refuses_existing_config() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path(".sops.yaml").write_text("creation_rules: []\n")
        result = runner.invoke(main, ["init"])

        assert result.exit_code == 1
        assert "already exists" in result.output


def test_init_force_overwrites_existing_config() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path(".sops.yaml").write_text("old\n")
        result = runner.invoke(main, ["init", "--force"])

        assert result.exit_code == 0
        assert "creation_rules:" in Path(".sops.yaml").read_text()


def test_edit_calls_native_sops(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["edit", "secret.yaml"])

    assert result.exit_code == 0
    assert calls == [["sops", "secret.yaml"]]


def test_edit_reports_sops_error(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="edit failed")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["edit", "secret.yaml"])

    assert result.exit_code == 1
    assert "edit failed" in result.output


def test_cat_decrypts_to_stdout(monkeypatch) -> None:
    def run(command, **kwargs):
        assert command == ["sops", "-d", "secret.yaml"]
        return completed("kind: Secret\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["cat", "secret.yaml"])

    assert result.exit_code == 0
    assert result.output == "kind: Secret\n"


def test_cat_reports_sops_error(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="decrypt failed")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["cat", "secret.yaml"])

    assert result.exit_code == 1
    assert "decrypt failed" in result.output


def test_encrypt_writes_output_file(monkeypatch) -> None:
    def run(command, **kwargs):
        assert command == ["sops", "-e", "secret.yaml"]
        return completed("encrypted\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\n")
        result = runner.invoke(main, ["encrypt", "secret.yaml", "-o", "sealed.yaml"])

        assert result.exit_code == 0
        assert Path("sealed.yaml").read_text() == "encrypted\n"


def test_encrypt_rejects_in_place_and_output() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\n")
        result = runner.invoke(main, ["encrypt", "secret.yaml", "--in-place", "-o", "out.yaml"])

    assert result.exit_code == 2
    assert "Cannot use both" in result.output


def test_encrypt_outputs_stdout(monkeypatch) -> None:
    def run(command, **kwargs):
        return completed("encrypted\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\n")
        result = runner.invoke(main, ["encrypt", "secret.yaml"])

    assert result.exit_code == 0
    assert result.output == "encrypted\n"


def test_encrypt_reports_sops_error(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="encrypt failed")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\n")
        result = runner.invoke(main, ["encrypt", "secret.yaml"])

    assert result.exit_code == 1
    assert "encrypt failed" in result.output


def test_encrypt_in_place_calls_sops(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\n")
        result = runner.invoke(main, ["encrypt", "secret.yaml", "--in-place"])

    assert result.exit_code == 0
    assert calls == [["sops", "-e", "-i", "secret.yaml"]]


def test_decrypt_in_place_calls_sops(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["decrypt", "secret.yaml", "--in-place"])

    assert result.exit_code == 0
    assert calls == [["sops", "-d", "-i", "secret.yaml"]]


def test_decrypt_writes_output_file(monkeypatch) -> None:
    def run(command, **kwargs):
        assert command == ["sops", "-d", "secret.yaml"]
        return completed("decrypted\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["decrypt", "secret.yaml", "-o", "plain.yaml"])

        assert result.exit_code == 0
        assert Path("plain.yaml").read_text() == "decrypted\n"


def test_decrypt_rejects_in_place_and_output() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["decrypt", "secret.yaml", "--in-place", "-o", "out.yaml"])

    assert result.exit_code == 2
    assert "Cannot use both" in result.output


def test_decrypt_outputs_stdout(monkeypatch) -> None:
    def run(command, **kwargs):
        return completed("decrypted\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["decrypt", "secret.yaml"])

    assert result.exit_code == 0
    assert result.output == "decrypted\n"


def test_decrypt_reports_sops_error(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="decrypt failed")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["decrypt", "secret.yaml"])

    assert result.exit_code == 1
    assert "decrypt failed" in result.output


def test_rekey_calls_updatekeys(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["rekey", "secret.yaml"])

    assert result.exit_code == 0
    assert calls == [["sops", "updatekeys", "-y", "secret.yaml"]]


def test_rekey_reports_sops_error(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="rekey failed")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["rekey", "secret.yaml"])

    assert result.exit_code == 1
    assert "rekey failed" in result.output


def test_rekey_all_updates_sops_files_only(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("encrypted.yaml").write_text("kind: Secret\nsops: {}\n")
        Path("plain.yaml").write_text("kind: ConfigMap\n")
        result = runner.invoke(main, ["rekey-all"])

    assert result.exit_code == 0
    assert calls == [["sops", "updatekeys", "-y", "encrypted.yaml"]]
    assert "Rekeyed 1 file" in result.output


def test_rekey_all_finds_nested_sops_files(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed()

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        nested = Path("clusters/prod/app")
        nested.mkdir(parents=True)
        (nested / "secret.yaml").write_text("kind: Secret\nsops: {}\n")
        result = runner.invoke(main, ["rekey-all", "clusters"])

    assert result.exit_code == 0
    assert calls == [["sops", "updatekeys", "-y", "clusters/prod/app/secret.yaml"]]
    assert "Rekeyed 1 file" in result.output


def test_rekey_all_reports_no_sops_files() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("plain.yaml").write_text("kind: ConfigMap\n")
        result = runner.invoke(main, ["rekey-all"])

    assert result.exit_code == 0
    assert "No SOPS-encrypted YAML files found" in result.output


def test_rekey_all_reports_errors(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(1, command, stderr="cannot update keys")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("encrypted.yaml").write_text("sops: {}\n")
        result = runner.invoke(main, ["rekey-all"])

    assert result.exit_code == 1
    assert "cannot update keys" in result.output


def test_validate_all_fails_on_plaintext_secret(monkeypatch) -> None:
    monkeypatch.setattr("ksops.sops.subprocess.run", lambda command, **kwargs: completed())
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\nstringData:\n  password: secret\n")
        result = runner.invoke(main, ["validate-all"])

    assert result.exit_code == 1
    assert "plaintext Kubernetes Secret" in result.output


def test_validate_all_finds_plaintext_secret_between_manifests(monkeypatch) -> None:
    monkeypatch.setattr("ksops.sops.subprocess.run", lambda command, **kwargs: completed())
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("bundle.yaml").write_text(
            """kind: Deployment
metadata:
  name: app
---
kind: Secret
metadata:
  name: app-secret
stringData:
  password: secret
---
kind: Ingress
metadata:
  name: app
"""
        )
        result = runner.invoke(main, ["validate-all"])

    assert result.exit_code == 1
    assert "bundle.yaml: plaintext Kubernetes Secret" in result.output


def test_validate_all_decrypts_sops_files(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed("kind: Secret\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("kind: Secret\nsops: {}\n")
        result = runner.invoke(main, ["validate-all"])

    assert result.exit_code == 0
    assert calls == [["sops", "-d", "secret.yaml"]]
    assert "Validated 1" in result.output


def test_validate_all_ignores_non_secret_yaml(monkeypatch) -> None:
    calls: list[list[str]] = []

    def run(command, **kwargs):
        calls.append(command)
        return completed("kind: Secret\n")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("config.yaml").write_text("kind: ConfigMap\ndata:\n  key: value\n")
        Path("secret.yaml").write_text("kind: Secret\nsops: {}\n")
        result = runner.invoke(main, ["validate-all"])

    assert result.exit_code == 0
    assert calls == [["sops", "-d", "secret.yaml"]]
    assert "Validated 1" in result.output


def test_validate_all_reports_invalid_yaml() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("broken.yaml").write_text("key: [\n")
        result = runner.invoke(main, ["validate-all"])

    assert result.exit_code == 1
    assert "invalid YAML" in result.output


def test_find_sops_files_skips_invalid_yaml() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("broken.yaml").write_text("key: [\n")
        Path("encrypted.yaml").write_text("sops: {}\n")

        assert find_sops_files(Path(".")) == [Path("encrypted.yaml")]


def test_plaintext_secret_detection_ignores_safe_documents() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("config.yaml").write_text("kind: ConfigMap\ndata:\n  key: value\n")
        Path("encrypted.yaml").write_text("kind: Secret\nsops: {}\nstringData:\n  key: value\n")
        Path("empty.yaml").write_text("kind: Secret\nstringData: {}\n")

        assert has_plaintext_kubernetes_secret(Path("config.yaml")) is False
        assert has_plaintext_kubernetes_secret(Path("encrypted.yaml")) is False
        assert has_plaintext_kubernetes_secret(Path("empty.yaml")) is False


def test_find_yaml_files_accepts_single_yaml_file() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("secret.yaml").write_text("sops: {}\n")

        assert find_yaml_files(Path("secret.yaml")) == [Path("secret.yaml")]
        assert find_yaml_files(Path("notes.txt")) == []


def test_has_sops_metadata_rejects_invalid_yaml() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        Path("broken.yaml").write_text("key: [\n")

        try:
            has_sops_metadata(Path("broken.yaml"))
        except KsopsError as e:
            assert "invalid YAML" in str(e)
        else:
            raise AssertionError("expected KsopsError")


def test_sops_reports_missing_binary(monkeypatch) -> None:
    def run(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("ksops.sops.subprocess.run", run)

    try:
        Sops().decrypt(Path("secret.yaml"))
    except KsopsError as e:
        assert "sops binary not found" in str(e)
    else:
        raise AssertionError("expected KsopsError")


def test_sops_reports_called_process_error_without_stderr(monkeypatch) -> None:
    def run(command, **kwargs):
        raise subprocess.CalledProcessError(12, command, stderr="")

    monkeypatch.setattr("ksops.sops.subprocess.run", run)

    try:
        Sops().decrypt(Path("secret.yaml"))
    except KsopsError as e:
        assert "exit status 12" in str(e)
    else:
        raise AssertionError("expected KsopsError")


def test_completion_outputs_shell_script() -> None:
    result = CliRunner().invoke(main, ["completion", "zsh"])

    assert result.exit_code == 0
    assert "#compdef ksops" in result.output


def test_completion_reports_generation_error(monkeypatch) -> None:
    def shell_complete(*args, **kwargs):
        return 1

    monkeypatch.setattr("ksops.cli.shell_complete", shell_complete)

    result = CliRunner().invoke(main, ["completion", "zsh"])

    assert result.exit_code == 1
    assert "Unsupported shell" in result.output
