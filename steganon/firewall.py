"""The firewall — one interface, a different implementation per system.

The rest of the code calls in here and does not need to know where it runs.
The two implementations differ substantially — a rule set replaced atomically
on Linux, permanent prefixed rules on Windows — but the behaviour they present
is the same.
"""

from __future__ import annotations

from . import backends

_impl = backends.firewall()

FirewallError = _impl.FirewallError

available = _impl.available
apply = _impl.apply
teardown = _impl.teardown
rollback = _impl.rollback
is_active = _impl.is_active
publish_state = _impl.publish_state
blocked_counters = _impl.blocked_counters
cache_servers = _impl.cache_servers
cached_servers = _impl.cached_servers
update_server_ips = _impl.update_server_ips

# The following exist only in the Linux implementation, where the rules are
# written as text and applied behind a rollback guard. On Windows the firewall
# changes incrementally, so there is no "set" to hand back.
build_ruleset = getattr(_impl, "build_ruleset", None)
check_syntax = getattr(_impl, "check_syntax", None)
current_ruleset = getattr(_impl, "current_ruleset", lambda: "")
confirm = getattr(_impl, "confirm", lambda: False)
resolve_servers = getattr(_impl, "resolve_servers", None)

if resolve_servers is None:
    import socket

    def resolve_servers(settings):
        """Resolves the server names to addresses, while there is a network."""
        found = []
        for loc in settings.enabled_locations():
            try:
                for info in socket.getaddrinfo(loc.remote, loc.port,
                                               proto=socket.IPPROTO_UDP):
                    found.append(info[4][0])
            except socket.gaierror:
                continue
        return sorted(set(found))
