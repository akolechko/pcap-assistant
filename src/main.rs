#![allow(unused_variables)]
#![allow(unused_must_use)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(dead_code)]

use pcap_file::pcap::{PcapReader, Packet,PcapWriter};
use std::time::Duration;
use std::io::prelude::*;
use colored::Colorize;
use std::borrow::Cow;
use thiserror::Error;
use pcap_parser::*;
use std::fs::File;
use std::vec;

pub use crate::pcap_assistant::*;
mod pcap_assistant;

fn main () {
    
    
}















