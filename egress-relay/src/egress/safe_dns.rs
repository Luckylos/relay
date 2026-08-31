use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPolicyError {
    NoAddresses,
    ForbiddenAddress(IpAddr),
    MixedAddressClasses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressClass {
    Public,
    Forbidden,
}

pub fn validate_resolved_addresses(addresses: &[IpAddr]) -> Result<Vec<IpAddr>, DnsPolicyError> {
    if addresses.is_empty() {
        return Err(DnsPolicyError::NoAddresses);
    }

    let mut has_public = false;
    let mut first_forbidden = None;
    for &address in addresses {
        match classify_address(address) {
            AddressClass::Public => has_public = true,
            AddressClass::Forbidden => {
                if first_forbidden.is_none() {
                    first_forbidden = Some(address);
                }
            }
        }
    }

    if let Some(forbidden) = first_forbidden {
        if has_public {
            return Err(DnsPolicyError::MixedAddressClasses);
        }
        return Err(DnsPolicyError::ForbiddenAddress(forbidden));
    }

    Ok(addresses.to_vec())
}

fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                classify_ipv4(mapped)
            } else if is_forbidden_ipv6(address) {
                AddressClass::Forbidden
            } else {
                AddressClass::Public
            }
        }
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressClass {
    let forbidden = [
        // Unspecified, loopback, private, link-local, and CGNAT ranges.
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
    ];

    if forbidden
        .iter()
        .any(|&(network, prefix)| ipv4_in_prefix(address, network, prefix))
        || address.octets()[0] >= 224
    {
        AddressClass::Forbidden
    } else {
        AddressClass::Public
    }
}

fn is_forbidden_ipv6(address: Ipv6Addr) -> bool {
    address.is_unspecified()
        || address.is_loopback()
        || ipv6_in_prefix(address, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7)
        || ipv6_in_prefix(address, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10)
        || ipv6_in_prefix(address, [0xff00, 0, 0, 0, 0, 0, 0, 0], 8)
        || ipv6_in_prefix(address, [0x2001, 0, 0, 0, 0, 0, 0, 0], 32)
        || ipv6_in_prefix(address, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32)
        || ipv6_in_prefix(address, [0x2001, 2, 0, 0, 0, 0, 0, 0], 48)
        || ipv6_in_prefix(address, [0x2001, 0x10, 0, 0, 0, 0, 0, 0], 28)
        || ipv6_in_prefix(address, [0x3fff, 0, 0, 0, 0, 0, 0, 0], 20)
}

fn ipv4_in_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    let address = u32::from_be_bytes(address.octets());
    let network = u32::from_be_bytes(network);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    address & mask == network & mask
}

fn ipv6_in_prefix(address: Ipv6Addr, network: [u16; 8], prefix: u8) -> bool {
    let address = address.segments();
    let complete_segments = usize::from(prefix / 16);
    if address[..complete_segments] != network[..complete_segments] {
        return false;
    }

    let remaining_bits = prefix % 16;
    remaining_bits == 0
        || (address[complete_segments] >> (16 - remaining_bits))
            == (network[complete_segments] >> (16 - remaining_bits))
}
