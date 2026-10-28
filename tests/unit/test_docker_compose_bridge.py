"""Guard the docker-compose wiring of the MCP bridge.

Why this exists
---------------
The bridge container's topology is not a style choice, and every constraint on
it is enforced somewhere the compose file cannot see:

* ``validate_server_url()`` in ``python/bridge_mcp_ghidra/validation.py``
  refuses any Ghidra URL whose host is not loopback. So the obvious Compose
  spelling, ``http://ghidra-mcp:8089``, is rejected by the bridge before a
  socket is opened. Only ``127.0.0.1`` works, and it only *means* the Ghidra
  server because the two containers share a network namespace.
* A container that joins another container's namespace has no network stack of
  its own, so its published port must be declared on the container it joins.
  ``docker compose config`` does not catch a ``ports:`` entry on such a
  service -- it validates cleanly and fails at ``up``.
* ``entrypoint.sh`` binds ``0.0.0.0`` by default and
  ``SecurityConfig.requireAuthForNonLoopbackBind`` refuses that bind without
  ``GHIDRA_MCP_AUTH_TOKEN``, so the token is a prerequisite for the stack
  starting at all -- not a hardening option.

None of that is visible in the YAML, and all of it breaks quietly: the wrong
URL surfaces as a bridge that starts and answers nothing, a ``ports:`` entry on
the wrong service surfaces as an engine error only at ``up``, and a missing
token surfaces as a container that builds, starts and dies in its own log.

These tests need no Docker daemon, which matters: the daemon is exactly what is
not available in CI.
"""

from __future__ import annotations

import pathlib
import sys

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker" / "docker-compose.yml"
COMPOSE_MULTI = REPO_ROOT / "docker" / "docker-compose.multi.yml"
DOCKERFILE_BRIDGE = REPO_ROOT / "docker" / "Dockerfile.bridge"

GHIDRA_SERVICE = "ghidra-mcp"
BRIDGE_SERVICE = "bridge"
BRIDGE_PORT = "8081"

sys.path.insert(0, str(REPO_ROOT / "python"))


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _env_map(service: dict) -> dict[str, str]:
    """Compose accepts both the list and mapping forms of `environment:`."""
    env = service.get("environment") or {}
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    out: dict[str, str] = {}
    for item in env:
        key, _, value = str(item).partition("=")
        out[key] = value
    return out


def test_bridge_service_exists_and_builds_the_bridge_dockerfile():
    services = _compose()["services"]
    assert BRIDGE_SERVICE in services, (
        "docker/Dockerfile.bridge is only reachable through compose if a "
        "service builds it. A Dockerfile nothing references is a file, not a "
        "deployment."
    )
    build = services[BRIDGE_SERVICE]["build"]
    assert build["dockerfile"] == "docker/Dockerfile.bridge"


def test_bridge_shares_the_ghidra_containers_network_namespace():
    bridge = _compose()["services"][BRIDGE_SERVICE]
    assert bridge.get("network_mode") == f"service:{GHIDRA_SERVICE}", (
        "The bridge must share the Ghidra container's network namespace. "
        "validate_server_url() refuses a non-loopback Ghidra URL, so "
        "http://ghidra-mcp:8089 is rejected outright and 127.0.0.1 is the only "
        "address that works -- which is only the Ghidra server if the "
        "namespace is shared."
    )


def test_bridge_ghidra_url_is_one_validate_server_url_accepts():
    """Assert against the real function, not a copy of its rule."""
    from bridge_mcp_ghidra.validation import validate_server_url

    url = _env_map(_compose()["services"][BRIDGE_SERVICE])["GHIDRA_MCP_URL"]
    assert validate_server_url(url), (
        f"GHIDRA_MCP_URL={url!r} is refused by validate_server_url(), so the "
        f"bridge would reject its own configured server. It requires the http "
        f"scheme, a loopback host and an explicit port."
    )


def test_service_name_url_would_be_refused():
    """Pin the negative case, so the reason for the topology stays legible."""
    from bridge_mcp_ghidra.validation import validate_server_url

    assert not validate_server_url(f"http://{GHIDRA_SERVICE}:8089")


def test_bridge_publishes_no_ports_of_its_own():
    bridge = _compose()["services"][BRIDGE_SERVICE]
    assert "ports" not in bridge, (
        "A service joining another container's network namespace has no "
        "network stack to publish from; the engine refuses to create it "
        "('conflicting options: port publishing and the container type network "
        "mode'). `docker compose config` does NOT catch this -- it validates "
        "cleanly and fails at `up`. Publish on the "
        f"{GHIDRA_SERVICE} service instead."
    )


def test_bridge_port_is_published_on_the_ghidra_service():
    ghidra = _compose()["services"][GHIDRA_SERVICE]
    published = [str(p) for p in ghidra.get("ports", [])]
    assert any(p.startswith(f"{BRIDGE_PORT}:") for p in published), (
        f"port {BRIDGE_PORT} is not published on {GHIDRA_SERVICE}, so nothing "
        f"on the host can reach the bridge. It cannot be published on the "
        f"bridge service itself -- see the test above."
    )


def test_published_bridge_port_matches_the_dockerfiles_bind():
    """The compose port and the image's own CMD must name the same port."""
    text = DOCKERFILE_BRIDGE.read_text(encoding="utf-8")
    assert f'"--mcp-port", "{BRIDGE_PORT}"' in text, (
        f"Dockerfile.bridge does not bind {BRIDGE_PORT}; the published port "
        f"would reach nothing."
    )
    assert '"--mcp-host", "0.0.0.0"' in text, (
        "The bridge must bind 0.0.0.0: a published port cannot reach a "
        "loopback bind inside the container."
    )


@pytest.mark.parametrize("service", [GHIDRA_SERVICE, BRIDGE_SERVICE])
def test_both_services_require_the_auth_token(service):
    """`:?` so a missing token is a compose error, not a dead container.

    The Ghidra side needs it to bind at all. The bridge side needs it to
    forward `Authorization: Bearer` to Ghidra, and -- once #438 lands -- to
    require the same header from its own clients, because it binds 0.0.0.0 and
    an unauthenticated non-loopback bridge that holds a token for Ghidra is a
    confused deputy.
    """
    value = _env_map(_compose()["services"][service])["GHIDRA_MCP_AUTH_TOKEN"]
    assert value.startswith("${GHIDRA_MCP_AUTH_TOKEN:?"), (
        f"{service} takes GHIDRA_MCP_AUTH_TOKEN as {value!r}. It must use the "
        f"`:?` required-variable form: entrypoint.sh binds 0.0.0.0 and "
        f"SecurityConfig.requireAuthForNonLoopbackBind refuses that without a "
        f"token, so an unset token is not a weaker deployment -- it is a stack "
        f"that cannot start, and `:-` would turn that into a container dying "
        f"in its own log instead of one line at the prompt."
    )


def test_bridge_waits_for_ghidra_to_be_healthy():
    bridge = _compose()["services"][BRIDGE_SERVICE]
    depends = bridge.get("depends_on") or {}
    assert GHIDRA_SERVICE in depends
    assert depends[GHIDRA_SERVICE].get("condition") == "service_healthy", (
        "Plain `depends_on` waits for the container to be created, not for "
        "Ghidra to answer. The bridge auto-connects at startup, so starting it "
        "against a Ghidra that is still loading means a bridge that comes up "
        "with no tools registered."
    )


def test_multi_instance_compose_deliberately_has_no_bridge():
    """A decision recorded as a test, so it cannot be undone by accident.

    `network_mode: "service:X"` names one container and cannot target a scaled
    service, and nginx.conf load-balances with `least_conn` and no session
    affinity -- so a bridge in front of it would hand consecutive MCP tool
    calls to different Ghidra instances holding different projects. Adding one
    here needs a topology decision, not a copied service block.
    """
    doc = yaml.safe_load(COMPOSE_MULTI.read_text(encoding="utf-8"))
    assert BRIDGE_SERVICE not in doc["services"]
    assert "bridge" in COMPOSE_MULTI.read_text(encoding="utf-8").lower(), (
        "docker-compose.multi.yml must at least explain why it has no bridge; "
        "silence reads as an oversight."
    )
