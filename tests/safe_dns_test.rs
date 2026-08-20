use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use codex_egress_relay::safe_dns::{validate_resolved_addresses, DnsPolicyError};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(segments: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(segments))
}

#[test]
fn allows_public_addresses() {
    let addresses = [v4(1, 1, 1, 1), v6([0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888])];

    assert_eq!(validate_resolved_addresses(&addresses).unwrap(), addresses);
}

#[test]
fn rejects_forbidden_ipv4_ranges() {
    for address in [
        v4(0, 0, 0, 0),
        v4(10, 0, 0, 1),
        v4(100, 64, 0, 1),
        v4(127, 0, 0, 1),
        v4(169, 254, 169, 254),
        v4(172, 16, 0, 1),
        v4(192, 0, 2, 1),
        v4(192, 168, 1, 1),
        v4(198, 18, 0, 1),
        v4(198, 51, 100, 1),
        v4(203, 0, 113, 1),
        v4(224, 0, 0, 1),
        v4(240, 0, 0, 1),
    ] {
        assert!(
            matches!(
                validate_resolved_addresses(&[address]),
                Err(DnsPolicyError::ForbiddenAddress(forbidden)) if forbidden == address
            ),
            "must reject {address}"
        );
    }
}

#[test]
fn rejects_forbidden_ipv6_ranges_and_classifies_mapped_ipv4() {
    for address in [
        v6([0, 0, 0, 0, 0, 0, 0, 0]),
        v6([0, 0, 0, 0, 0, 0, 0, 1]),
        v6([0xfc00, 0, 0, 0, 0, 0, 0, 1]),
        v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]),
        v6([0xff02, 0, 0, 0, 0, 0, 0, 1]),
        v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]),
        v6([0x2001, 2, 0, 0, 0, 0, 0, 1]),
        v6([0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101]),
    ] {
        assert!(
            matches!(
                validate_resolved_addresses(&[address]),
                Err(DnsPolicyError::ForbiddenAddress(forbidden)) if forbidden == address
            ),
            "must reject {address}"
        );
    }

    let mapped_public = v6([0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808]);
    assert_eq!(
        validate_resolved_addresses(&[mapped_public]).unwrap(),
        [mapped_public]
    );
}

#[test]
fn rejects_empty_and_mixed_public_private_answers() {
    assert_eq!(
        validate_resolved_addresses(&[]),
        Err(DnsPolicyError::NoAddresses)
    );

    assert_eq!(
        validate_resolved_addresses(&[v4(1, 1, 1, 1), v4(10, 0, 0, 1)]),
        Err(DnsPolicyError::MixedAddressClasses)
    );
}
