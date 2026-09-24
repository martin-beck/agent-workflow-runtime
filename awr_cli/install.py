"""Safe, provider-free runtime-home initialization and lifecycle operations."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .cli import CliError, canonical

MARKER = "install.json"
CONFIG = "config.json"
STATE = "state.json"


def default_home() -> Path:
    configured = os.environ.get("AWR_HOME")
    if configured:
        return Path(configured).expanduser()
    data_home = os.environ.get("XDG_DATA_HOME")
    return (Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share") / "awr"


def _safe_home(home: Path, *, create: bool = False) -> Path:
    home = home.expanduser().absolute()
    if home == Path(home.anchor) or home.is_symlink():
        raise CliError("unsafe_runtime_home")
    try:
        if not home.exists() and create:
            home.mkdir(parents=True, mode=0o700)
        if not home.is_dir():
            raise CliError("runtime_home_not_directory")
        info = home.stat()
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise CliError("runtime_home_not_user_owned")
        if not os.access(home, os.R_OK | os.W_OK | os.X_OK):
            raise CliError("runtime_home_not_writable")
    except OSError as exc:
        raise CliError("runtime_home_unavailable") from exc
    return home


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CliError("managed_file_missing_or_unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CliError("config_corrupt_preserve_and_repair_manually") from exc
    if not isinstance(value, dict):
        raise CliError("config_corrupt_preserve_and_repair_manually")
    return value


def _marker(home: Path) -> dict[str, Any] | None:
    path = home / MARKER
    if not path.exists() and not path.is_symlink():
        return None
    marker = _read_json(path)
    if (
        set(marker) != {"schema_version", "kind", "version", "previous"}
        or marker.get("schema_version") != 1
        or marker.get("kind") != "awr-runtime-install"
        or not isinstance(marker.get("version"), str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", marker["version"])
    ):
        raise CliError("install_marker_invalid_preserve_home")
    prior = marker["previous"]
    if prior is not None and (
        not isinstance(prior, dict)
        or set(prior) != {"schema_version", "kind", "version", "previous"}
        or prior.get("schema_version") != 1
        or prior.get("kind") != "awr-runtime-install"
        or not isinstance(prior.get("version"), str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", prior["version"])
        or prior.get("previous") is not None
    ):
        raise CliError("install_marker_invalid_preserve_home")
    return marker


def _atomic_write(path: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=".awr-tmp-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def doctor(home: Path | None = None) -> dict[str, Any]:
    selected = home if home is not None else default_home()
    if not selected.exists() and not selected.is_symlink():
        return {"status": "not_installed", "version": __version__}
    try:
        safe = _safe_home(selected)
    except CliError as exc:
        raise
    marker = _marker(safe)
    if marker is None:
        return {"status": "not_installed", "version": __version__}
    config = _read_json(safe / CONFIG)
    state = _read_json(safe / STATE)
    if config.get("schema_version") != 1 or state.get("schema_version") != 1:
        raise CliError("runtime_config_incompatible")
    return {"status": "healthy", "version": __version__, "installed_version": marker["version"]}


def install(home: Path | None = None, *, repair: bool = False, upgrade: bool = False) -> dict[str, Any]:
    safe = _safe_home(home if home is not None else default_home(), create=True)
    previous = _marker(safe)
    if previous and not (repair or upgrade):
        raise CliError("already_installed_use_repair_or_upgrade")
    if not previous and (repair or upgrade):
        raise CliError("not_installed")

    paths = {name: safe / name for name in (CONFIG, STATE, MARKER)}
    for path in paths.values():
        if path.is_symlink():
            raise CliError("managed_path_is_symlink")
    config_path, state_path = paths[CONFIG], paths[STATE]
    config = {"schema_version": 1, "network": "disabled"}
    state = {"schema_version": 1, "kind": "awr-runtime-state", "provider": "not_performed", "authority_state": "not_performed"}
    if config_path.exists():
        existing_config = _read_json(config_path)
        if existing_config.get("schema_version") != 1:
            raise CliError("runtime_config_incompatible")
    if state_path.exists():
        existing_state = _read_json(state_path)
        if existing_state.get("schema_version") != 1:
            raise CliError("runtime_state_incompatible")

    marker = {"schema_version": 1, "kind": "awr-runtime-install", "version": __version__, "previous": previous}
    created: list[Path] = []
    try:
        for path, value in ((config_path, config), (state_path, state)):
            if not path.exists():
                _atomic_write(path, canonical(value) + b"\n")
                created.append(path)
        _atomic_write(paths[MARKER], canonical(marker) + b"\n")
    except BaseException as exc:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(exc, CliError):
            raise
        raise CliError("bootstrap_interrupted_partial_files_preserved") from exc
    return {"status": "repaired" if repair else "upgraded" if upgrade else "installed", "version": __version__}


def rollback(home: Path | None = None) -> dict[str, Any]:
    safe = _safe_home(home if home is not None else default_home())
    current = _marker(safe)
    if current is None:
        raise CliError("not_installed")
    previous = current.get("previous")
    if not isinstance(previous, dict) or previous.get("kind") != "awr-runtime-install":
        raise CliError("no_rollback_available")
    _atomic_write(safe / MARKER, canonical(previous) + b"\n")
    return {"status": "rolled_back", "version": previous.get("version")}


def uninstall(home: Path | None = None) -> dict[str, Any]:
    safe = _safe_home(home if home is not None else default_home())
    if _marker(safe) is None:
        raise CliError("not_installed")
    (safe / MARKER).unlink()
    # Config and state are user data after first initialization; retain them.
    return {"status": "uninstalled", "preserved": [CONFIG, STATE]}

