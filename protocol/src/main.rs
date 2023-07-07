#![feature(slice_group_by)]

use std::thread::{sleep, Thread};
use std::time::Duration;
use anyhow::Result;

use crate::protocol::ProtocolSkelBuilder;

mod protocol {
    include!("./protocol.bpf.rs");
}

fn main() -> Result<()> {
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = ProtocolSkelBuilder::default();
    let mut open_skel = builder.open()?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    sleep(Duration::from_secs(100));
    Ok(())
}
