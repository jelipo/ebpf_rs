use std::collections::HashMap;
use crate::runqslower::HashmapSkelBuilder;

mod runqslower {
    include!("./hashmap.bpf.rs");
}

fn main() {
    HashmapSkelBuilder::open()
    println!("Hello, world!");
}
