#![feature(slice_group_by)]

use std::time::Duration;

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

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
    rbb.add(maps.address_ringbuf(), move |data| {
        println!("{}", data.len());
        0
    })?;
    let address_ringbuf = rbb.build()?;
    loop {
        if let Err(err) = address_ringbuf.poll(Duration::MAX) {
            println!("poll error: {}", err);
        }
    }
    Ok(())
}
