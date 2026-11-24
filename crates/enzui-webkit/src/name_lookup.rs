//! Per-family system name lookup.
//!
//! `std` resolves both address families in one blocking call. The destination
//! guard needs them separately, so that a slow family cannot hold the other;
//! this is the one `getaddrinfo` binding that provides it.
// `unsafe_code` is allowed for this module by the `#[allow(unsafe_code)]` on its
// declaration in `lib.rs`.

use std::net::SocketAddr;
#[cfg(not(target_os = "linux"))]
use std::net::ToSocketAddrs;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};

/// One address family of a lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    /// IPv4, `A` records.
    V4,
    /// IPv6, `AAAA` records.
    V6,
}

type Lookup = std::io::Result<Vec<SocketAddr>>;

/// The addresses of one family, in the system's order. A name without an
/// address of that family yields an empty list rather than an error.
#[cfg(target_os = "linux")]
pub(crate) fn family_lookup(host: &str, port: u16, family: Family) -> Lookup {
    use std::ffi::{CString, c_char, c_int};

    const AF_INET: c_int = 2;
    const AF_INET6: c_int = 10;
    const SOCK_STREAM: c_int = 1;
    // The name has no address of this family: an empty answer, not a failure.
    const EAI_NONAME: c_int = -2;
    const EAI_NODATA: c_int = -5;
    const EAI_ADDRFAMILY: c_int = -9;

    /// `struct addrinfo` as Linux lays it out on every architecture.
    #[repr(C)]
    struct AddressInfo {
        flags: c_int,
        family: c_int,
        socket_type: c_int,
        protocol: c_int,
        address_length: u32,
        address: *const u8,
        canonical_name: *mut c_char,
        next: *mut AddressInfo,
    }
    unsafe extern "C" {
        fn getaddrinfo(
            node: *const c_char,
            service: *const c_char,
            hints: *const AddressInfo,
            result: *mut *mut AddressInfo,
        ) -> c_int;
        fn freeaddrinfo(result: *mut AddressInfo);
    }

    let name = CString::new(host).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "host name contains NUL")
    })?;
    let hints = AddressInfo {
        flags: 0,
        family: if family == Family::V4 {
            AF_INET
        } else {
            AF_INET6
        },
        socket_type: SOCK_STREAM,
        protocol: 0,
        address_length: 0,
        address: std::ptr::null(),
        canonical_name: std::ptr::null_mut(),
        next: std::ptr::null_mut(),
    };
    let mut list: *mut AddressInfo = std::ptr::null_mut();
    // SAFETY: the name is NUL-terminated, the hints outlive the call, and the
    // result list is released below with the matching function.
    let code = unsafe { getaddrinfo(name.as_ptr(), std::ptr::null(), &hints, &mut list) };
    if code != 0 {
        return if matches!(code, EAI_NONAME | EAI_NODATA | EAI_ADDRFAMILY) {
            Ok(Vec::new())
        } else {
            Err(std::io::Error::other(format!(
                "failed to look up address information (getaddrinfo {code})"
            )))
        };
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: getaddrinfo returned this node; it stays valid until freeaddrinfo.
        let info = unsafe { &*entry };
        let length = info.address_length as usize;
        if !info.address.is_null() {
            // sockaddr_in: family, port, four address bytes. sockaddr_in6: family,
            // port, flow label, sixteen address bytes, scope. Ports are zero here.
            if info.family == AF_INET && length >= 8 {
                // SAFETY: the node declares at least eight readable bytes at `address`.
                let bytes = unsafe { std::slice::from_raw_parts(info.address, 8) };
                let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                addresses.push(SocketAddr::new(ip.into(), port));
            } else if info.family == AF_INET6 && length >= 28 {
                // SAFETY: the node declares at least twenty-eight readable bytes at `address`.
                let bytes = unsafe { std::slice::from_raw_parts(info.address, 28) };
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&bytes[8..24]);
                let scope = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
                addresses.push(SocketAddr::V6(std::net::SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    scope,
                )));
            }
        }
        entry = info.next;
    }
    // SAFETY: the list came from the successful getaddrinfo call above and is not used again.
    unsafe { freeaddrinfo(list) };
    addresses.dedup();
    Ok(addresses)
}

/// Without a per-family binding, filter the combined answer.
#[cfg(not(target_os = "linux"))]
pub(crate) fn family_lookup(host: &str, port: u16, family: Family) -> Lookup {
    Ok((host, port)
        .to_socket_addrs()?
        .filter(|address| address.is_ipv4() == (family == Family::V4))
        .collect())
}
