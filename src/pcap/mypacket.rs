use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};

use crate::{
    myerrors::*,
    TsResolution,
    pcap::*
};
 
use std::{
    borrow::Cow,
    io::Read,
    io::Write,
    time::Duration
};

/// Describes a pcap packet header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct PacketHeader {

    /// Timestamp in seconds
    pub ts_sec: u32,

    /// Nanosecond part of the timestamp
    pub ts_nsec: u32,

    /// Number of octets of the packet saved in file
    pub incl_len: u32,

    /// Original length of the packet on the wire
    pub orig_len: u32
}

impl SomePacketHeader for  PacketHeader {

    fn set_incl_len(&mut self, incl_len: u32) {
        self.incl_len = incl_len;
    }

    fn set_orig_len(&mut self, orig_len: u32) {
        self.orig_len = orig_len;
    }

    /// Create a new `PacketHeader` with the given parameters.
    fn new(ts_sec: u32, ts_nsec: u32, incl_len:u32, orig_len:u32) -> PacketHeader {

        PacketHeader {
            ts_sec,
            ts_nsec,
            incl_len,
            orig_len
        }
    }

    /// Create a new `PacketHeader` from a reader.
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<PacketHeader> {

        let ts_sec = reader.read_u32::<B>()?;
        let mut ts_nsec = reader.read_u32::<B>()?;
        if ts_resolution == TsResolution::MicroSecond {
            ts_nsec *= 1000;
        }
        let incl_len = reader.read_u32::<B>()?;
        let orig_len = reader.read_u32::<B>()?;

        if incl_len > 0xFFFF {
            return Err(PcapError::InvalidField("PacketHeader incl_len > 0xFFFF"));
        }

        if orig_len > 0xFFFF {
            return Err(PcapError::InvalidField("PacketHeader orig_len > 0xFFFF"));
        }

        if incl_len > orig_len {
            return Err(PcapError::InvalidField("PacketHeader incl_len > orig_len"));
        }


        Ok(
            PacketHeader {

                ts_sec,
                ts_nsec,
                incl_len,
                orig_len
            }
        )
    }

    /// Create a new `PacketHeader` from a slice.
    fn from_slice<B: ByteOrder>(mut slice: &[u8], ts_resolution: TsResolution) -> ResultParsing<(&[u8], PacketHeader)> {

        //Header len
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer(16 - slice.len()));
        }

        let header = Self::from_reader::<_, B>(&mut slice, ts_resolution)?;

        Ok((slice, header))
    }

    /// Write a `PcapHeader` to a writer.
    ///
    /// Writes 24B in the writer on success.
    fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> ResultParsing<()> {

        let mut ts_unsec = self.ts_nsec;
        if ts_resolution == TsResolution::MicroSecond{
            ts_unsec /= 1000;
        }
        writer.write_u32::<B>(self.ts_sec)?;
        writer.write_u32::<B>(ts_unsec)?;
        writer.write_u32::<B>(self.incl_len)?;
        writer.write_u32::<B>(self.orig_len)?;

        Ok(())
    }

    /// Get the timestamp of the packet as a Duration
    fn timestamp(&self) -> Duration {
        Duration::new(self.ts_sec.into(), self.ts_nsec)
    }
}


/// Packet with its header and data.
///
/// The payload can be owned or borrowed.
#[derive(Clone, Debug)]
pub struct Packet<'a> {

    /// Header of the packet
    pub header: PacketHeader,

    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>
}

impl<'a> SomePacket<'a> for Packet<'a> {
    
    type Item = Self;
    type Header = PacketHeader;

    fn get_data(&self) -> &Cow<'a, [u8]> {
        &self.data
    }

    fn get_header(&self) -> Self::Header {
        self.header
    }

    /// Create a new borrowed `Packet` with the given parameters.
    fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> Self {

        let header = PacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len
        };

        Packet {
            header,
            data: Cow::Borrowed(data)
        }
    }

    fn new_with_params(&self, header: Self::Header, data: Vec<u8>) -> Self {
        Packet {
            header,
            data: Cow::Owned(data)
        }
    }

    /// Create a new owned `Packet` with the given parameters.
    fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> Self::Item {

        let header = PacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len
        };

        Packet {
            header,
            data: Cow::Owned(data)
        }
    }

    /// Create a new owned `Packet` from a reader.
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<Self::Item> {

        let header = PacketHeader::from_reader::<R, B>(reader, ts_resolution)?;

        let mut bytes = vec![0_u8; header.incl_len as usize];
        reader.read_exact(&mut bytes)?;

        Ok(
            Packet {

                header,
                data : Cow::Owned(bytes)
            }
        )
    }

    /// Create a new borrowed `Packet` from a slice.
    fn from_slice<B: ByteOrder>(slice: &'a [u8], ts_resolution: TsResolution) -> ResultParsing<(&'a[u8], Self::Item)> {

        let (slice, header) = PacketHeader::from_slice::<B>(slice, ts_resolution)?;
        let len = header.incl_len as usize;

        if slice.len() < len {
            return Err(PcapError::IncompleteBuffer(len - slice.len()));
        }

        let packet = Packet {
            header,
            data : Cow::Borrowed(&slice[..len])
        };

        let slice = &slice[len..];

        Ok((slice, packet))
    }

    /// Convert a borrowed `Packet` to an owned one.
    fn to_owned(& self) -> Packet<'static> {
        Packet {
            header: self.header,
            data: Cow::Owned(self.data.as_ref().to_owned())
        }
    }
}
    

impl <'a> Packet<'a> {
    pub fn convert(&self) -> VppPacket<'a> {
        
        let header = VppPacketHeader {
            ts_sec: self.header.ts_sec,
            ts_nsec: self.header.ts_nsec,
            incl_len: self.header.incl_len,
            orig_len: self.header.orig_len,
            interface_index: 0
        };

        VppPacket {
            header,
            data: self.data.clone()
        }
    }
}

