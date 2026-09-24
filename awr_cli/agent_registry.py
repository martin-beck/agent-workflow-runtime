"""Durable provider-neutral adapter registry for executable runtime paths.

The registry is deliberately local and provider-free.  A profile is a
capability/lifecycle declaration, not permission to contact a backend.  JSON
replacement under an advisory lock gives callers atomic updates and a
revision fence for stale writers.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


class RegistryError(ValueError):
    """Fail-closed registry or negotiation rejection."""


_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UNSAFE = re.compile(r"[;&|<>`$()\n\r]|(?:^|[/\\])(?:home|users|private|secret|credentials)(?:[/\\]|$)", re.I)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class AdapterProfile:
    adapter_id: str
    version: str
    command_profile: tuple[str, ...]
    capabilities: frozenset[str]
    lifecycle: tuple[str, ...]
    resources: dict[str, int]
    sandbox_required: bool = True

    def public(self) -> dict[str, object]:
        body = {
            "adapter_id": self.adapter_id,
            "version": self.version,
            "command_profile": list(self.command_profile),
            "capabilities": sorted(self.capabilities),
            "lifecycle": list(self.lifecycle),
            "resources": dict(sorted(self.resources.items())),
            "sandbox_required": self.sandbox_required,
        }
        return body | {"profile_digest": _digest(body)}

    @classmethod
    def from_public(cls, value: dict[str, object]) -> "AdapterProfile":
        required = {"adapter_id", "version", "command_profile", "capabilities", "lifecycle", "resources", "sandbox_required", "profile_digest"}
        if set(value) != required:
            raise RegistryError("profile_shape_invalid")
        if not isinstance(value["adapter_id"], str) or not isinstance(value["version"], str) or not isinstance(value["command_profile"], list) or not isinstance(value["capabilities"], list) or not isinstance(value["lifecycle"], list) or not isinstance(value["resources"], dict) or not isinstance(value["sandbox_required"], bool):
            raise RegistryError("profile_types_invalid")
        try:
            profile = cls(
                str(value["adapter_id"]), str(value["version"]), tuple(value["command_profile"]),
                frozenset(value["capabilities"]), tuple(value["lifecycle"]), dict(value["resources"]), bool(value["sandbox_required"]),
            )
        except (TypeError, ValueError) as exc:
            raise RegistryError("profile_types_invalid") from exc
        profile.validate()
        if value["profile_digest"] != profile.public()["profile_digest"]:
            raise RegistryError("profile_digest_invalid")
        return profile

    def validate(self) -> None:
        if not _ID.fullmatch(self.adapter_id) or not _VERSION.fullmatch(self.version):
            raise RegistryError("adapter_identity_invalid")
        if not 1 <= len(self.command_profile) <= 16 or any(not isinstance(item, str) or not item or len(item) > 256 or any(char.isspace() for char in item) or _UNSAFE.search(item) for item in self.command_profile):
            raise RegistryError("unsafe_command_profile")
        if not self.capabilities or any(not isinstance(item, str) or not _CAPABILITY.fullmatch(item) for item in self.capabilities):
            raise RegistryError("capabilities_invalid")
        if not self.lifecycle or len(set(self.lifecycle)) != len(self.lifecycle) or any(not isinstance(item, str) or item not in {"start", "request", "stream", "interrupt", "checkpoint", "resume", "close"} for item in self.lifecycle):
            raise RegistryError("lifecycle_invalid")
        if any(not isinstance(key, str) or not _CAPABILITY.fullmatch(key) or isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65536 for key, value in self.resources.items()):
            raise RegistryError("resources_invalid")
        if not isinstance(self.sandbox_required, bool):
            raise RegistryError("sandbox_requirement_invalid")


class AdapterRegistry:
    """Atomic, revisioned registry backed by one JSON file."""

    def __init__(self, path: Path, *, initialize: bool = True):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        if initialize and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_save({"schema_version": 1, "revision": 0, "profiles": {}})

    @classmethod
    def memory_with_fakes(cls) -> "AdapterRegistry":
        path = Path(tempfile.mkdtemp(prefix="awr-registry-") ) / "registry.json"
        registry = cls(path)
        for profile in deterministic_fake_profiles():
            registry.register(profile)
        return registry

    def _load(self) -> dict[str, object]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError("registry_unreadable") from exc
        if set(value) != {"schema_version", "revision", "profiles"} or value["schema_version"] != 1 or not isinstance(value["revision"], int) or value["revision"] < 0 or not isinstance(value["profiles"], dict):
            raise RegistryError("registry_corrupt")
        for profile in value["profiles"].values():
            AdapterProfile.from_public(profile)
        return value

    def _atomic_save(self, value: dict[str, object]) -> None:
        fd, name = tempfile.mkstemp(prefix=".registry-", dir=str(self.path.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.flush(); os.fsync(handle.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name): os.unlink(name)

    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    @property
    def revision(self) -> int:
        return int(self._load()["revision"])

    def register(self, profile: AdapterProfile, *, expected_revision: int | None = None) -> int:
        profile.validate()
        with self._locked() as lock:
            value = self._load()
            if expected_revision is not None and expected_revision != value["revision"]:
                raise RegistryError("stale_registry_revision")
            if profile.adapter_id in value["profiles"]:
                raise RegistryError("duplicate_adapter_identity")
            value["profiles"][profile.adapter_id] = profile.public()
            value["revision"] += 1
            self._atomic_save(value)
            return int(value["revision"])

    def profile(self, adapter_id: str) -> AdapterProfile:
        value = self._load()
        try:
            return AdapterProfile.from_public(value["profiles"][adapter_id])
        except KeyError as exc:
            raise RegistryError("unknown_adapter") from exc

    def negotiate(self, adapter_id: str, requested: Iterable[str], *, expected_revision: int | None = None) -> dict[str, object]:
        if expected_revision is not None and expected_revision != self.revision:
            raise RegistryError("stale_registry_revision")
        profile = self.profile(adapter_id)
        requested_set = set(requested)
        if not requested_set or any(not isinstance(item, str) or not _CAPABILITY.fullmatch(item) for item in requested_set):
            raise RegistryError("capability_request_invalid")
        unsupported = sorted(requested_set - profile.capabilities)
        if unsupported:
            raise RegistryError("unsupported_capability")
        return {"adapter_id": profile.adapter_id, "profile_digest": profile.public()["profile_digest"], "registry_revision": self.revision, "capabilities": sorted(requested_set), "status": "accepted", "execute": False, "provider": "not_performed"}

    def snapshot(self) -> dict[str, object]:
        value = self._load()
        return {"schema_version": 1, "revision": value["revision"], "profiles": {key: value["profiles"][key] for key in sorted(value["profiles"])}}


def deterministic_fake_profiles() -> tuple[AdapterProfile, ...]:
    return (
        AdapterProfile("fake-alpha", "1.0.0", ("deterministic-alpha",), frozenset({"request", "stream", "close"}), ("start", "request", "stream", "close"), {"max_request_bytes": 4096, "max_output_events": 8}, False),
        AdapterProfile("fake-beta", "1.0.0", ("deterministic-beta",), frozenset({"request", "checkpoint", "resume", "close"}), ("start", "request", "checkpoint", "resume", "close"), {"max_request_bytes": 2048, "max_output_events": 4}, False),
        AdapterProfile("fake-sandbox", "1.0.0", ("deterministic-sandbox",), frozenset({"request", "close"}), ("start", "request", "close"), {"max_request_bytes": 4096, "max_output_events": 4}, True),
        AdapterProfile("fake-agent", "1.0.0", ("deterministic-agent",), frozenset({"request", "close"}), ("start", "request", "close"), {"max_request_bytes": 4096, "max_output_events": 4}, False),
    )


class DeterministicFakeAdapter:
    """A provider-free adapter double with intentionally distinct behavior."""

    def __init__(self, profile: AdapterProfile):
        profile.validate()
        self.profile = profile

    def respond(self, request_digest: str) -> dict[str, str | bool]:
        if not _DIGEST.fullmatch(request_digest):
            raise RegistryError("request_digest_invalid")
        style = "stream" if "stream" in self.profile.capabilities else "checkpointed"
        return {"adapter_id": self.profile.adapter_id, "style": style, "request_digest": request_digest, "execute": False, "provider": "not_performed"}


def deterministic_fake_adapters() -> tuple[DeterministicFakeAdapter, DeterministicFakeAdapter]:
    profiles = deterministic_fake_profiles()
    return DeterministicFakeAdapter(profiles[0]), DeterministicFakeAdapter(profiles[1])


__all__ = ["AdapterProfile", "AdapterRegistry", "DeterministicFakeAdapter", "RegistryError", "deterministic_fake_adapters", "deterministic_fake_profiles"]
