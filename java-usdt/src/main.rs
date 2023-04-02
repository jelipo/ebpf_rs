use anyhow::Result;
use byteorder::ByteOrder;
use clap::Parser;
use crate::javausdt::JavausdtSkelBuilder;

mod javausdt {
    include!("./javausdt.bpf.rs");
}

#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "offcputime", about = "trace pid offcputime")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
    /// wait timeout (second)
    #[clap(short = 'f')]
    time: u64,
}

fn main() -> Result<()> {
    let builder = JavausdtSkelBuilder::default();
    let open_skel = builder.open()?;
    let open_prog = open_skel.progs();
    open_prog.sched_switch()
    let skel = open_skel.load()?;
    let progs = skel.progs().sched_switch().attach_usdt();
    Ok(())
}

