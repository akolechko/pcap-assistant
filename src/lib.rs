pub(crate) mod myerrors;
pub use errors::*;

pub(crate) mod common;
pub use common::*;

pub mod pcap;
pub use pcap::{PcapReader, PcapParser, PcapWriter};

pub(crate) mod peek_reader;

pub mod pcap_assistant;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
