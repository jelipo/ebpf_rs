#![feature(slice_group_by)]

mod pre;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use byteorder::ByteOrder;
use clap::Parser;
use libbpf_rs::{MapFlags, RingBufferBuilder};
use libbpf_rs::libbpf_sys::bpf_map__fd;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use plain::Plain;

use common::err::to_err;
use common::net::AddressFamily;

use crate::protocol::protocol_bss_types::addr_info_t;
use crate::protocol::ProtocolSkelBuilder;



#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "offcputime", about = "trace pid offcputime")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
}

fn main() -> Result<()> {
    let cmd = Command::parse();
    // 初始化
    common::bump_memlock_rlimit()?;


    let mut maps = skel.maps_mut();

    if let Err(err) = maps.listen_tgid().update(&cmd.pid.to_le_bytes(), &[0], MapFlags::ANY) {
        println!("{}", err);
    }

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

const ADDR_TYPE_CONNECT: u8 = 1;
const ADDR_TYPE_ACCEPT: u8 = 2;

//SAFE: ELF64Header satisfies all the requirements of `Plain`.
unsafe impl Plain for addr_info_t {}

fn ip(buf: &[u8]) -> Result<()> {
    let addr_info = plain::from_bytes::<addr_info_t>(buf)
        .map_err(to_err)?;

    let ip_addr = match AddressFamily::from_repr(addr_info.family as usize) {
        Some(AddressFamily::Inet) => unsafe {
            IpAddr::V4(Ipv4Addr::from(u32::from_be(addr_info.ip_info.ip.ipv4_be)))
        }
        Some(AddressFamily::Inet6) => unsafe {
            let ipv6 = u128::from_be_bytes(addr_info.ip_info.ip.ipv6_be);
            IpAddr::V6(Ipv6Addr::from(ipv6))
        }
        None => return Ok(()),
    };
    let addr = SocketAddr::new(ip_addr, addr_info.ip_info.port_le);
    let tgid = addr_info.pid_tgid >> 32;
    match addr_info.addr_type {
        ADDR_TYPE_CONNECT => println!("TGID: {} ---> {}", tgid, addr),
        ADDR_TYPE_ACCEPT => println!("{} ---> TGID:{}", addr, tgid),
        _ => return Ok(()),
    }

    Ok(())
}
