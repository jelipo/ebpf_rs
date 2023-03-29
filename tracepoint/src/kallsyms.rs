use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::Result;

struct Ksym {
    addr: u64,
    name: String,
}

pub struct KallsymsCache {
    syms: Vec<Ksym>,
}

impl KallsymsCache {
    pub fn new() -> Result<KallsymsCache> {
        let file = File::open("/proc/kallsyms")?;
        let lines = BufReader::new(file).lines();
        let mut vec = Vec::<Ksym>::new();
        for line in lines.map_while(|r| r.ok()) {
            let mut split = line.split(' ').collect::<Vec<_>>();
            if split.len() < 3 {
                continue;
            }
            let addr = u64::from_str_radix(split[0], 16)?;
            let func_name = split[2].to_string();
            vec.push(Ksym { addr, name: func_name })
        }
        vec.sort_by(|a, b| a.addr.cmp(&b.addr));
        Ok(KallsymsCache { syms: vec })
    }

    pub fn search(&self, key: u64) -> String {
        let index = match self.syms.binary_search_by(|a| a.addr.cmp(&key)) {
            Ok(i) => i,
            Err(i) => i,
        };
        self.syms[index].name.clone()
    }
}
