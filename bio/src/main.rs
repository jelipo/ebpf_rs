#![feature(slice_group_by)]

use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, NativeEndian};
use clap::Parser;
use libbpf_rs::MapFlags;

use common::stack::procsyms::ProcsymsCache;

use crate::bio::bio_bss_types::{key_t, value_t};
use crate::bio::{BioMaps, BioSkelBuilder};

mod bio {
    include!("./bio.bpf.rs");
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
    let builder = BioSkelBuilder::default();
    let mut open_skel = builder.open()?;
    open_skel.rodata().listen_tgid = cmd.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    // 等待完成
    thread::sleep(Duration::from_secs(cmd.time));
    // 开始处理
    let maps = skel.maps();
    let key_iter = maps.pid_stack_counter().keys();
    let procsyms_cache = ProcsymsCache::new(cmd.pid)?;
    for key_data in key_iter {
        let value_data = maps.pid_stack_counter().lookup(&key_data, MapFlags::ANY)?.expect("key not found");
        let key = unsafe { std::ptr::read_unaligned(key_data.as_ptr() as *const key_t) };
        let value = unsafe { std::ptr::read_unaligned(value_data.as_ptr() as *const value_t) };
        print_bio_stack(&maps, &procsyms_cache, &key)?;
        print_bio_distributions(&value.distribution_count);
        println!("max_data:{} min_data:{}", value.max_len, value.min_len);
    }
    Ok(())
}

fn print_bio_stack(maps: &BioMaps, cache: &ProcsymsCache, key: &key_t) -> Result<()> {
    let symbols_data_result = maps
        .stack_traces()
        .lookup(&key.user_stack_id.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow!("stack_user_id ({})  not found pid: {}", key.user_stack_id, key.pid));
    match symbols_data_result {
        Ok(symbols_data) => {
            let symbols = symbols_data.chunks(8).map(NativeEndian::read_u64).collect::<Vec<_>>();
            let symbol_names = symbols
                .iter()
                .rev()
                .filter(|&&symbol| symbol != 0)
                .map(|&symbol| cache.search(symbol))
                .collect::<Result<Vec<&str>>>()?;
            println!("stack: {}", symbol_names.join(","));
        }
        Err(err) => println!("get stack has a error: {}", err),
    }
    Ok(())
}

fn print_bio_distributions(distribution_count: &[u32]) {
    println!("{:>10} - {:<10}  : {:<8}", "min", "max", "count");
    for (i, count) in distribution_count.iter().enumerate() {
        let max = 1u32 << i;
        let min = max >> 1;
        println!("{:>10} - {:<10}  : {:<8}", min, max, count)
    }
}
