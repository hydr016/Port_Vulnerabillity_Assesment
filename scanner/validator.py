"""Target validation: reject malformed input and targets outside the allowed networks."""
import ipaddress
import re
import socket

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
FORBIDDEN_CHARS = re.compile(r"[\s/,;|&$`'\"<>*()\\]")


class TargetError(Exception):
    """Raised with a friendly message when a target is not acceptable."""


def validate_target(raw_target, allowed_networks):
    """Return {"target", "address", "ip_version"} or raise TargetError.

    Rules:
      * exactly one host (no CIDR ranges, lists or wildcards)
      * valid IPv4/IPv6 address or valid hostname
      * the resolved address must be inside config.json "allowed_networks"
    """
    target = (raw_target or "").strip()
    if not target:
        raise TargetError("Enter a target IP address or hostname.")
    if len(target) > 253 or FORBIDDEN_CHARS.search(target):
        raise TargetError(
            "Invalid target. Enter a single IP address or hostname "
            "(ranges, lists and special characters are not allowed)."
        )

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if not HOSTNAME_RE.match(target):
            raise TargetError("That is not a valid IP address or hostname.")
        try:
            address = ipaddress.ip_address(socket.gethostbyname(target))
        except (socket.gaierror, socket.herror, UnicodeError, ValueError):
            raise TargetError(f"The hostname '{target}' could not be resolved.")

    networks = [ipaddress.ip_network(n, strict=False) for n in allowed_networks]
    if not any(address in network for network in networks):
        raise TargetError(
            f"{address} is outside the allowed networks in config.json. "
            "Only scan systems you are authorized to test. If this is your own "
            "lab machine, add its network to 'allowed_networks'."
        )
    return {"target": target, "address": str(address), "ip_version": address.version}
