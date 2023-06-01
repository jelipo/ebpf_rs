#![feature(slice_group_by)]


use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{TC_CUSTOM, TC_EGRESS, TC_H_CLSACT, TC_H_MIN_INGRESS, TC_INGRESS, TcHookBuilder};

use crate::drop::DropSkelBuilder;

mod drop {
    include!("./drop.bpf.rs");
}

#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "drop", about = "drop net")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
    /// wait timeout (second)
    #[clap(short = 'f')]
    time: u64,
}

fn main() -> Result<()> {
    //let cmd = Command::parse();
    // 初始化
    common::bump_memlock_rlimit()?;

    let builder = DropSkelBuilder::default();
    let open = builder.open()?;
    let mut skel = open.load()?;
    let progs = skel.progs();
    let ifidx = nix::net::if_::if_nametoindex("enp3s0")? as i32;

    let mut tc_builder = TcHookBuilder::new();
    tc_builder
        .fd(progs.tc_ingress().fd())
        .ifindex(ifidx)
        .replace(true)
        .handle(1)
        .priority(1);

    let mut egress = tc_builder.hook(TC_EGRESS);
    let mut ingress = tc_builder.hook(TC_INGRESS);
    let mut custom = tc_builder.hook(TC_CUSTOM);
    custom.parent(TC_H_CLSACT, TC_H_MIN_INGRESS).handle(2);

    let hook = egress.attach()?;

    thread::sleep(Duration::from_secs(10));
    Ok(())
}
