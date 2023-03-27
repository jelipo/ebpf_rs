use std::ops::Deref;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;

use common::convert::BpfStruct;

use crate::runqslower::TracepointSkelBuilder;
use crate::runqslower::tracepoint_bss_types::key_t;

mod runqslower {
    include!("./tracepoint.bpf.rs");
}

fn main() -> Result<()> {
    let cmd = Command::parse();
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = TracepointSkelBuilder::default();
    let mut open_skel = builder.open()?;
    open_skel.rodata().listen_tgid = cmd.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    // 等待完成
    println!("wait {} seconds", cmd.time);
    thread::sleep(Duration::from_secs(cmd.time));
    // 开始处理
    println!("finished waiting");

    let maps = skel.maps();
    let key_iter = maps.pid_stack_counter().keys();
    for key_data in key_iter {
        let x = key_data.deref();
        let key = key_data.to_struct::<key_t>()?;
        println!("{}", key.pid);
    }
    Ok(())
}

/// Trace capabilities
#[derive(Debug, Copy, Clone, Parser)]
#[clap(name = "offcputime", about = "trace pid offcputime")]
struct Command {
    /// trace pid
    #[clap(short = 'p', long)]
    pid: u32,
    /// wait timeout
    #[clap(short = 'f')]
    time: u64,
}