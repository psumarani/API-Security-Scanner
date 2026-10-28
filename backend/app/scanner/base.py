"""Scanner module interface and the per-scan context handed to every module."""

import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from app.models.enums import OwaspCategory
from app.scanner.http_client import (
    NetworkError,
    RedirectBlocked,
    RequestBudgetExceeded,
    SafeHttpClient,
    ScopedResponse,
    TooManyRedirects,
    UnsafeMethodError,
)
from app.scanner.openapi import sample_value
from app.scanner.settings import ScanSettings
from app.scanner.types import EndpointInfo, FindingDraft, ProfileAuth


class ScanCancelled(Exception):
    """The scan was cancelled by the user."""


class ScanTimeLimit(Exception):
    """The scan exceeded its maximum duration."""


@dataclass
class ModuleMeta:
    id: str
    name: str
    description: str
    categories: list[OwaspCategory]
    automated: bool
    prerequisites: list[str]
    validation: str
    limitations: str
    default_enabled: bool = True


@dataclass
class ScanContext:
    client: SafeHttpClient
    endpoints: list[EndpointInfo]
    profiles: dict[str, ProfileAuth]
    settings: ScanSettings
    deadline: float
    is_cancelled: Callable[[], bool]
    path_prefix: str = ""
    inconclusive: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # ---- control ----
    def check_running(self) -> None:
        if self.is_cancelled():
            raise ScanCancelled
        if time.monotonic() > self.deadline:
            raise ScanTimeLimit

    # ---- profiles ----
    def usable_profiles(self) -> list[ProfileAuth]:
        return [p for p in self.profiles.values() if p.usable and (p.headers or p.query)]

    def default_profile(self) -> ProfileAuth | None:
        usable = self.usable_profiles()
        return usable[0] if usable else None

    # ---- requests ----
    def full_path(self, path: str) -> str:
        return f"{self.path_prefix}{path}" if self.path_prefix else path

    async def send(
        self,
        method: str,
        path: str,
        *,
        profile: ProfileAuth | None = None,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,
        prefixed: bool = True,
    ) -> ScopedResponse:
        self.check_running()
        send_headers: dict[str, str] = dict(headers or {})
        send_params: dict[str, Any] = dict(params or {})
        if profile is not None:
            send_headers = {**profile.headers, **send_headers}
            send_params = {**profile.query, **send_params}
        target = self.full_path(path) if prefixed else path
        return await self.client.request(
            method, target, headers=send_headers, params=send_params or None, json=json
        )

    async def try_send(self, *args: Any, why: str = "", **kwargs: Any) -> ScopedResponse | None:
        """Like send(), but records transport problems as inconclusive instead of raising."""
        try:
            return await self.send(*args, **kwargs)
        except (NetworkError, RedirectBlocked, TooManyRedirects, UnsafeMethodError) as exc:
            self.inconclusive.append(f"{why or args[:2]}: {type(exc).__name__}: {exc}"[:300])
            return None

    # ---- endpoint helpers ----
    def safe_endpoints(self) -> list[EndpointInfo]:
        return [e for e in self.endpoints if e.method == "GET"]

    @staticmethod
    def fill_path(endpoint: EndpointInfo, overrides: Mapping[str, str] | None = None) -> str:
        values = {p["name"]: sample_value(p) for p in endpoint.parameters if p["in"] == "path"}
        values.update(overrides or {})
        path = endpoint.path
        for name, value in values.items():
            path = path.replace("{" + name + "}", quote(str(value), safe=""))
        return path

    @staticmethod
    def sample_query(endpoint: EndpointInfo) -> dict[str, str]:
        return {
            p["name"]: sample_value(p)
            for p in endpoint.parameters
            if p["in"] == "query" and p.get("required")
        }

    @staticmethod
    def has_unfilled_path(path: str) -> bool:
        return "{" in path and "}" in path


class ScannerModule(ABC):
    meta: ModuleMeta

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[FindingDraft]:
        """Execute checks. Must stay within the context's budgets and be non-destructive."""


__all__ = [
    "ModuleMeta",
    "RequestBudgetExceeded",
    "ScanCancelled",
    "ScanContext",
    "ScanTimeLimit",
    "ScannerModule",
]
