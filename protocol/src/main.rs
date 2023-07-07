#![feature(slice_group_by)]

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
    open_skel.progs().sys_enter_connect().set_attach_target()
    let mut skel = open_skel.load()?;
    skel.attach()?;
    Ok(())
}
