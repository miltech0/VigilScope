"""Classify local and remote IP addresses with the standard library."""

from __future__ import annotations

import ipaddress

ALL_INTERFACES = "all_interfaces"
LOOPBACK = "loopback"
PRIVATE = "private"
LINK_LOCAL = "link_local"
PUBLIC = "public"
LOCAL_DEVICE = "local_device"
UNCERTAIN = "uncertain"


def classify_ip(address: str) -> str:
    text = str(address).split("%", 1)[0]
    # This compares address text for classification; it never binds a socket.
    if text in {"0.0.0.0", "::"}:  # nosec
        return ALL_INTERFACES
    try:
        value = ipaddress.ip_address(text)
    except ValueError:
        return UNCERTAIN
    if value.is_loopback:
        return LOOPBACK
    if value.is_link_local:
        return LINK_LOCAL
    if value.is_private:
        return PRIVATE
    if value.is_global:
        return PUBLIC
    if value.is_unspecified:
        return ALL_INTERFACES
    return UNCERTAIN


def address_family(address: str) -> str:
    text = str(address).split("%", 1)[0]
    try:
        return "IPv6" if ipaddress.ip_address(text).version == 6 else "IPv4"
    except ValueError:
        return "Bilinmiyor"


def is_externally_exposed(scope: str) -> bool:
    return scope not in {LOOPBACK, LOCAL_DEVICE, UNCERTAIN}


def is_public_address(address: str) -> bool:
    return classify_ip(address) == PUBLIC
