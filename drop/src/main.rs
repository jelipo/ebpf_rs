#![feature(slice_group_by)]



use anyhow::Result;
use clap::Parser;
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
    let cmd = Command::parse();
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = DropSkelBuilder::default();
    let mut open_skel = builder.open()?;
    open_skel.progs_mut()
    open_skel.rodata().listen_tgid = cmd.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    Ok(())
}
