import pytest

from system_info.address_utils import (
    ALL_INTERFACES,
    LINK_LOCAL,
    LOOPBACK,
    PRIVATE,
    PUBLIC,
    UNCERTAIN,
    address_family,
    classify_ip,
    is_externally_exposed,
)


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.0.0.1", LOOPBACK),
        ("::1", LOOPBACK),
        ("0.0.0.0", ALL_INTERFACES),
        ("::", ALL_INTERFACES),
        ("10.0.0.1", PRIVATE),
        ("172.16.1.1", PRIVATE),
        ("192.168.1.1", PRIVATE),
        ("169.254.1.1", LINK_LOCAL),
        ("fe80::1", LINK_LOCAL),
        ("8.8.8.8", PUBLIC),
        ("not-an-ip", UNCERTAIN),
    ],
)
def test_ip_classification(address, expected) -> None:
    assert classify_ip(address) == expected


def test_address_family_and_exposure() -> None:
    assert address_family("8.8.8.8") == "IPv4"
    assert address_family("2001:4860:4860::8888") == "IPv6"
    assert is_externally_exposed(LOOPBACK) is False
    assert is_externally_exposed(ALL_INTERFACES) is True

