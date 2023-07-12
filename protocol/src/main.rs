#![feature(slice_group_by)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use plain::Plain;

use common::err::to_err;
use common::net::AddressFamily;

use crate::protocol::protocol_bss_types::addr_info_t;
use crate::protocol::ProtocolSkelBuilder;

mod protocol {
    include!("./protocol.bpf.rs");
}

fn main() -> Result<()> {
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = ProtocolSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let maps = skel.maps();
    let mut rbb = RingBufferBuilder::new();
    rbb.add(maps.address_ringbuf(), move |buf| {
        if let Err(err) = ip(buf) {
            println!("{}", err.to_string());
        }
        0
    })?;
    let address_ringbuf = rbb.build()?;
    let handle = thread::spawn(move || {
        loop {
            if let Err(err) = address_ringbuf.poll(Duration::MAX) {
                println!("poll error: {}", err);
            }
        }
    });
    thread::sleep(Duration::MAX);
    Ok(())
}

//SAFE: ELF64Header satisfies all the requirements of `Plain`.
unsafe impl Plain for addr_info_t {}

fn ip(buf: &[u8]) -> Result<()> {
    let addr_info = plain::from_bytes::<addr_info_t>(buf)
        .map_err(to_err)?;
    let ip_addr = match AddressFamily::from_repr(addr_info.family as usize) {
        Some(AddressFamily::Inet) => unsafe {
            IpAddr::V4(Ipv4Addr::from(addr_info.ip_info.ip.ipv4_be.to_le()))
        }
        Some(AddressFamily::Inet6) => unsafe {
            let x = addr_info.ip_info.ip.ipv6_be;

            let ip = u128::from_be_bytes(addr_info.ip_info.ip.ipv6_be);
            match ip >> 32 {
                0xFFFF => IpAddr::V4(Ipv4Addr::from(ip as u32)),
                _ => IpAddr::V6(Ipv6Addr::from(ip))
            }
        }
        None => return Ok(()),
    };
    let addr = SocketAddr::new(ip_addr, addr_info.ip_info.port_le);
    println!("{}", addr);
    Ok(())
}
