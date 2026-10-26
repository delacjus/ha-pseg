"""Client generation factory, registry and exit-boundary catalog.

Instruments client construction across package and config flow so that each
created client instance receives a distinct generation ID and is automatically
bound to a per-generation ScriptedPortal adapter view.

The P2-01 client contract also requires the before/after method gates to form a
named boundary catalog. The P2-07 inventory showed this factory had no boundary
catalog at all (only client construction), so :data:`EXIT_BOUNDARY_CATALOG`
completes it below: every persistence-relevant exit method of the client, with
the phase, the runner that reaches it and the lifecycle operation that does.
Test adapters wrap those names instead of hard-coding production attributes.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import sys
import threading
from typing import Any

from .portal import ScriptedPortal


@dataclass(frozen=True, slots=True)
class ExitBoundary:
    """One named before/after method gate at a client persistence exit."""

    name: str
    """Isolated production method name (never spelled out by the cases)."""

    phase: str
    """``before`` the method body runs, or ``after`` it returns/raises."""

    runner: str
    """``executor`` when production calls it off the event loop, else ``loop``."""

    operation: str
    """Lifecycle operation that reaches this boundary: poll/keepalive/backfill."""

    description: str = ""

    @property
    def boundary_id(self) -> str:
        """Stable gate/case identifier, e.g. ``after:keepalive``."""
        return f"{self.phase}:{self.name}"


#: Methods whose before/after gates bound every client persistence exit.
EXIT_BOUNDARY_METHODS: tuple[tuple[str, str, str, str], ...] = (
    (
        "fetch_energy_data",
        "executor",
        "poll",
        "Daily+hourly fetch: confirms/publishes the validated whole-jar checkpoint.",
    ),
    (
        "keepalive",
        "executor",
        "keepalive",
        "GET-only keepalive: confirms a rotated jar without the poll's export.",
    ),
    (
        "fetch_history_range",
        "executor",
        "backfill",
        "History chunks: each validated chunk confirms/publishes a jar.",
    ),
    (
        "export_cookies_and_auth_reason",
        "executor",
        "poll",
        "Cookie/auth export queued by the coordinator's persistence handoff.",
    ),
    (
        "confirmed_cookies",
        "loop",
        "poll",
        "Confirmed-jar accessor compared against the live export.",
    ),
    (
        "pending_confirmed_snapshot",
        "loop",
        "poll",
        "Pending immutable checkpoint read by every failure/stop handoff.",
    ),
)

#: The complete before/after exit-boundary catalog (12 named gates).
EXIT_BOUNDARY_CATALOG: tuple[ExitBoundary, ...] = tuple(
    ExitBoundary(
        name=name, phase=phase, runner=runner, operation=operation, description=description
    )
    for name, runner, operation, description in EXIT_BOUNDARY_METHODS
    for phase in ("before", "after")
)

#: Declared-but-not-applicable gate variants, with the reason recorded per phase.
EXIT_BOUNDARY_GATE_EXCLUSIONS: dict[str, str] = {
    "export_cookies": (
        "export_cookies (the plain cookie export) is only reached by the unattached "
        "human config-flow commit, not by the authenticated persistence handoff; the "
        "authenticated exit exports through export_cookies_and_auth_reason."
    ),
}


def exit_boundary(name: str, phase: str) -> ExitBoundary:
    """Return the catalog entry for one method/phase pair."""
    for boundary in EXIT_BOUNDARY_CATALOG:
        if boundary.name == name and boundary.phase == phase:
            return boundary
    raise KeyError(f"{phase}:{name}")


def exit_boundary_ids() -> tuple[str, ...]:
    """Return every catalog gate identifier in declaration order."""
    return tuple(boundary.boundary_id for boundary in EXIT_BOUNDARY_CATALOG)


class ClientRegistry:
    """Registry tracking PsegClient instances by generation ID."""

    def __init__(self) -> None:
        self._clients: dict[str, Any] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def register(self, generation_id: str, client: Any) -> None:
        """Register a client under a generation ID."""
        with self._lock:
            self._clients[generation_id] = client
            if generation_id not in self._order:
                self._order.append(generation_id)

    def get(self, generation_id: str) -> Any | None:
        """Retrieve a client by generation ID."""
        with self._lock:
            return self._clients.get(generation_id)

    @property
    def latest(self) -> Any | None:
        """Return the most recently created client instance."""
        with self._lock:
            if not self._order:
                return None
            return self._clients[self._order[-1]]

    @property
    def latest_generation_id(self) -> str | None:
        """Return the most recently created generation ID."""
        with self._lock:
            return self._order[-1] if self._order else None

    @property
    def generations(self) -> list[str]:
        """Return all registered generation IDs in creation order."""
        with self._lock:
            return list(self._order)

    def all_clients(self) -> list[Any]:
        """Return all registered client instances in creation order."""
        with self._lock:
            return [self._clients[g] for g in self._order]

    def clear(self) -> None:
        """Clear all registered clients and generations."""
        with self._lock:
            self._clients.clear()
            self._order.clear()


class ClientFactory:
    """Factory instrumenting client construction across package and config flow."""

    def __init__(
        self,
        portal: ScriptedPortal,
        registry: ClientRegistry | None = None,
    ) -> None:
        self.portal = portal
        self.registry = registry or ClientRegistry()
        self._generation_counter = 0
        self._installed = False
        self._orig_constructors: dict[tuple[Any, str], Any] = {}
        self._lock = threading.Lock()

    def next_generation_id(self) -> str:
        """Generate the next sequential generation identifier."""
        with self._lock:
            self._generation_counter += 1
            return f"gen_{self._generation_counter:03d}"

    def create_client(
        self,
        *args: Any,
        generation_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Create and instrument a PsegClient instance with a generation ID."""
        from custom_components.pseg.pseg_client import PsegClient

        gen_id = generation_id or self.next_generation_id()
        orig_cls = self._orig_constructors.get(
            (sys.modules.get("custom_components.pseg.pseg_client"), "PsegClient"),
            PsegClient,
        )
        client = orig_cls(*args, **kwargs)
        client.generation_id = gen_id
        self.portal.mount_on(client.session, generation_id=gen_id)
        self.registry.register(gen_id, client)
        return client

    def install(self) -> ClientFactory:
        """Patch discovered client construction seams across custom_components.pseg."""
        with self._lock:
            if self._installed:
                return self

            modules_to_patch = [
                "custom_components.pseg",
                "custom_components.pseg.__init__",
                "custom_components.pseg.config_flow",
                "custom_components.pseg.pseg_client",
            ]

            factory_self = self

            def _factory_client_constructor(*args: Any, **kwargs: Any) -> Any:
                return factory_self.create_client(*args, **kwargs)

            for mod_name in modules_to_patch:
                try:
                    mod = importlib.import_module(mod_name)
                except Exception:
                    mod = sys.modules.get(mod_name)
                if mod and hasattr(mod, "PsegClient"):
                    orig = getattr(mod, "PsegClient")
                    if (mod, "PsegClient") not in self._orig_constructors:
                        self._orig_constructors[(mod, "PsegClient")] = orig
                    setattr(mod, "PsegClient", _factory_client_constructor)

            self._installed = True
            return self

    def uninstall(self) -> None:
        """Restore original unpatched client constructors."""
        with self._lock:
            if not self._installed:
                return
            for (mod, attr), orig in self._orig_constructors.items():
                if mod and hasattr(mod, attr):
                    setattr(mod, attr, orig)
            self._orig_constructors.clear()
            self._installed = False

    def __enter__(self) -> ClientFactory:
        return self.install()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.uninstall()
