use byteorder::{BigEndian, LittleEndian};

use crate::{
    myerrors::*,
    pcap::vpp_packet::SomePacket,
    //pcap::Packet,
    pcap::PcapHeader,
    Endianness,
};

/// Parser for a Pcap formated stream.
///
/// # Examples
///
/// ```no_run
/// use pcap_file::pcap::PcapParser;
/// use pcap_file::PcapError;
///
/// let pcap = vec![0_u8; 0];
/// let mut src = &pcap[..];
///
/// // Creates a new parser and parse the pcap header
/// let (rem, pcap_parser) = PcapParser::new(&pcap[..]).unwrap();
/// src = rem;
///
/// loop {
///
///     match pcap_parser.next_packet(src) {
///         Ok((rem, packet)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///
///             // No more data, if no more incoming either then this is the end of the file
///             if rem.is_empty() {
///                 break;
///             }
///         },
///         Err(PcapError::IncompleteBuffer(needed)) => {},// Load more data into src
///         Err(_) => {}// Parsing error
///     }
/// }
/// ```
#[derive(Debug)]
pub struct PcapParser {
    header: PcapHeader,
}

impl PcapParser {
    /// Creates a new `PcapParser`.
    /// Returns the parser and the remainder.
    pub fn new(slice: &[u8]) -> ResultParsing<(&[u8], PcapParser)> {
        let (slice, header) = PcapHeader::from_slice(slice)?;

        let parser = PcapParser { header };

        Ok((slice, parser))
    }

    /// Returns the next packet and the remainder.
    pub fn next_packet<'a, P: SomePacket<'a>>(
        &self,
        slice: &'a [u8],
    ) -> ResultParsing<(&'a [u8], P::Item)> {
        let ts_resolution = self.header.ts_resolution();

        match self.header.endianness() {
            Endianness::Big => P::from_slice::<BigEndian>(slice, ts_resolution),
            Endianness::Little => P::from_slice::<LittleEndian>(slice, ts_resolution),
        }
    }
}
