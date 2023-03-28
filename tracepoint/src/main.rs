use std::mem::size_of;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use clap::Parser;
use libbpf_rs::MapFlags;

use crate::runqslower::{TracepointMaps, TracepointSkelBuilder};
use crate::runqslower::tracepoint_bss_types::key_t;

mod runqslower {
    include!("./tracepoint.bpf.rs");
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
        let bytes = key_data.as_slice();
        let info: key_t = bytes.try_into()
            .map_err(|_| anyhow!("error casting bytes into ProcessInfo"))?;
        let data: [u8; size_of::<key_t>()] = key_data.try_into()
            .map_err(|_| anyhow!("ensure that the size of type is equal to the length of the vec"))?;
        let key = unsafe { std::mem::transmute::<[u8; size_of::<key_t>()], key_t>(data) };
        let value_data = maps.pid_stack_counter().lookup(&key_data, MapFlags::ANY)?.expect("key not found");


        // let key = to_bpf_struct::<key_t>(key_data)?;
        // let value = to_bpf_struct::<u64>(value_data)?;
        println!("pid:{}  count:{}", key.pid, key.tgid);
    }
    Ok(())
}


fn print_user_stacks_by_id(maps: &TracepointMaps, stack_id: u32) -> Result<()> {
    let stack_stack = maps.stack_traces().lookup(&stack_id.to_ne_bytes(), MapFlags::ANY)?.ok_or(anyhow!("not found"))?;
    let x: Vec<u64> = stack_stack.into();
    Ok(())
}
