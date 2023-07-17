use std::os::fd::{AsFd, AsRawFd, RawFd};

use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use anyhow::Result;

use crate::pre::protocol::{ProtocolSkel, ProtocolSkelBuilder};

mod protocol {
    include!("./bpf/pre/protocol.bpf.rs");
}

pub struct PreBpfProg<'a> {
    skel: ProtocolSkel<'a>,
}

impl PreBpfProg<'_> {
    pub fn new<'a>() -> Result<PreBpfProg<'a>> {
        let builder = ProtocolSkelBuilder::default();
        let mut open_skel = builder.open()?;
        let mut skel = open_skel.load()?;
        skel.attach()?;
        Ok(PreBpfProg {
            skel,
        })
    }

    pub fn tgid_map_fd(&self) -> RawFd {
        self.skel.maps().listen_tgid().as_fd().as_raw_fd()
    }
}