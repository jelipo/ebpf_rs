use std::thread;
use std::time::Duration;

use anyhow::Result;
use libbpf_rs::MapFlags;

use crate::runqslower::HashmapSkelBuilder;

mod runqslower {
    include!("./hashmap.bpf.rs");
}

fn main() -> Result<()> {
    // 初始化
    common::bump_memlock_rlimit()?;
    let builder = HashmapSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    let mut key_bytes = [0u8; 4];
    key_bytes[..3].copy_from_slice("key".as_bytes());
    skel.maps_mut().my_map().update(&key_bytes, &key_bytes, MapFlags::ANY)?;
    loop {
        thread::sleep(Duration::from_secs(3));
        let option = skel.maps_mut().my_map().lookup(&key_bytes, MapFlags::ANY)?;
        match option {
            None => println!("无数据"),
            Some(data) => {
                let count = u32::from_le_bytes((&data)[..4].try_into()?);
                println!("count：{}", count);
            }
        }
    }
}
