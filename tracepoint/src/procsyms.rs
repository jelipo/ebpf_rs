use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use object::{Object, ObjectSymbol};
use proc_maps::Pid;

pub struct ProcsymsCache {
    maps: Vec<ProcSymsMap>,
    file_fd_symbol_map: HashMap<String, Vec<ProcSymbol>>,
}

pub struct ProcSymsMap {
    vm_start: usize,
    vm_end: usize,
    vm_pgoff: usize,
    fd_file: String,
}

pub struct ProcSymbol {
    name: String,
    address: u64,
    size: u64,
}

impl ProcsymsCache {
    pub fn new(pid: u32) -> Result<ProcsymsCache> {
        let maps = proc_maps::get_process_maps(pid as i32)?;
        let mut vec = Vec::<ProcSymsMap>::new();
        for map_range in maps {
            let fd_file = match map_range.filename() {
                None => continue,
                Some(path) => {
                    let path_cow = path.to_string_lossy();
                    if path_cow.starts_with('[') || path_cow.ends_with(']') { continue; }
                    path_cow.to_string()
                }
            };
            let symbol_map = ProcSymsMap {
                vm_start: map_range.start(),
                vm_end: map_range.start() + map_range.size(),
                vm_pgoff: map_range.offset,
                fd_file,
            };
            vec.push(symbol_map);
        }
        // 根据vm_start排序
        vec.sort_by(|a, b| a.vm_start.cmp(&b.vm_start));
        let file_fd_symbol_map = link(&vec, pid)?;
        Ok(ProcsymsCache {
            maps: vec,
            file_fd_symbol_map,
        })
    }

    pub fn search(&self, address: u64) -> Result<String> {
        let (file_fd_path, offset) = match self.maps.binary_search_by_key(&address, |sym| sym.vm_start as u64) {
            Ok(i) => (&self.maps[i].fd_file, self.maps[i].vm_start + self.maps[i].vm_pgoff),
            Err(i) => {
                let proc_sym = &self.maps[i - 1];
                if address > proc_sym.vm_end as u64 { return Ok("[unknown]".to_string()); }
                (&proc_sym.fd_file, address as usize - proc_sym.vm_start + proc_sym.vm_pgoff)
            }
        };
        let symbols = match self.file_fd_symbol_map.get(file_fd_path) {
            None => return Ok("[unknown]".to_string()),
            Some(symbols) => symbols
        };

        let name = match symbols.binary_search_by_key(&(offset as u64), |symbol| symbol.address) {
            Ok(i) => &symbols[i].name,
            Err(i) => {
                let symbol = &symbols[i];
                let prev_symbol = &symbols[i - 1];
                if offset as u64 > prev_symbol.address + prev_symbol.size { return Ok("[unknown]".to_string()); }
                &prev_symbol.name
            }
        };
        Ok(name.to_string())
    }
}

fn link(maps: &[ProcSymsMap], pid: u32) -> Result<HashMap::<String, Vec<ProcSymbol>>> {
    let mut fd_file_map = HashMap::<String, Vec<ProcSymbol>>::new();
    for map in maps {
        if fd_file_map.contains_key(map.fd_file.as_str()) { continue; }
        let path = format!("/proc/{:?}/root{}", pid, map.fd_file);
        let file_data = std::fs::read(path)?;
        let obj_file = match object::File::parse(file_data.as_slice()) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let mut symbols = obj_file.dynamic_symbols().collect::<Vec<_>>();
        let mut custom_symbols = symbols.iter().map(|symbol| {
            ProcSymbol {
                name: symbol.name().unwrap_or("[unknown]").to_string(),
                address: symbol.address(),
                size: symbol.size(),
            }
        }).collect::<Vec<_>>();
        custom_symbols.sort_by(|a, b| a.address.cmp(&b.address));
        fd_file_map.insert(map.fd_file.to_string(), custom_symbols);
    }
    Ok(fd_file_map)
}