"""Exercise every installed console script declared by this distribution."""

from importlib.metadata import distribution
import os
from pathlib import Path
import subprocess
import sys


def test_all_installed_console_scripts_report_package_version(tmp_path):
    dist = distribution("keyrings.cryptfile")
    scripts = [entry for entry in dist.entry_points if entry.group == "console_scripts"]
    assert scripts, "the executable inventory must come from installed metadata"
    home = tmp_path / "home"
    home.mkdir()
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        "import builtins, socket, sqlite3, subprocess, sys\n"
        "def forbidden(*args, **kwargs):\n"
        "    raise AssertionError('runtime initialization during --version')\n"
        "builtins.input = forbidden\n"
        "socket.socket.connect = forbidden\n"
        "socket.create_connection = forbidden\n"
        "sqlite3.connect = forbidden\n"
        "subprocess.Popen = forbidden\n"
        "class NoInput:\n"
        "    read = readline = readlines = forbidden\n"
        "sys.stdin = NoInput()\n",
        encoding="utf-8",
    )
    invalid_config = tmp_path / "invalid.toml"
    invalid_config.write_text("invalid TOML [", encoding="utf-8")
    environment = dict(os.environ)
    environment.update(
        HOME=str(home), USERPROFILE=str(home),
        XDG_CONFIG_HOME=str(home), XDG_DATA_HOME=str(home), XDG_STATE_HOME=str(home),
        PYTHONPATH=str(guard), PYTHONNOUSERSITE="1",
        INFERENCE_CORE_CONFIG=str(invalid_config),
        INFERENCE_CONSOLE_CONFIG=str(invalid_config),
        KNOWLEDGE_KIT_CONFIG=str(invalid_config),
    )
    for entry in scripts:
        executable = Path(sys.executable).with_name(entry.name)
        if os.name == "nt":
            executable = executable.with_suffix(".exe")
        result = subprocess.run(
            [str(executable), "--version"], input="", capture_output=True,
            text=True, check=False, timeout=20, cwd=tmp_path, env=environment,
        )
        assert result.returncode == 0, (entry.name, result.stdout, result.stderr)
        assert result.stderr == "", (entry.name, result.stderr)
        assert result.stdout.endswith(" " + dist.version + "\n"), result.stdout
        assert entry.name in result.stdout, result.stdout
        assert dist.metadata["Name"] in result.stdout, result.stdout
        assert len(result.stdout.splitlines()) == 1, result.stdout
    assert not list(home.iterdir()), "version reporting must not create runtime state"
