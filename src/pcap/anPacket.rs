use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};

use crate::{
    myerrors::*,
    TsResolution,
    pcap::{Packet, PacketHeader}
};
 
use std::{
    borrow::Cow,
    io::Read,
    io::Write,
    time::Duration
};

/// Describes a An pcap packet header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct AnPacketHeader {

    /// Timestamp in seconds
    pub ts_sec: u32,

    /// Nanosecond part of the timestamp
    pub ts_nsec: u32,

    /// Number of octets of the packet saved in file
    pub incl_len: u32,

    /// Original length of the packet on the wire
    pub orig_len: u32,

    /// Just need to exist
    pub interface_index: u32
}


impl AnPacketHeader {
    /// Create a new `AnPacketHeader` with the given parameters.
    pub fn new(ts_sec: u32, ts_nsec: u32, incl_len:u32, orig_len:u32) -> AnPacketHeader {

       AnPacketHeader {
           ts_sec,
           ts_nsec,
           incl_len,
           orig_len, 
           interface_index: 0
       }
   }

    /// Create a new `PacketHeader` from a reader.
    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<AnPacketHeader> {

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
            AnPacketHeader {

                ts_sec,
                ts_nsec,
                incl_len,
                orig_len,
                interface_index: 0
            }
        )
    }

    pub fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> ResultParsing<()> {

        let mut ts_unsec = self.ts_nsec;
        if ts_resolution == TsResolution::MicroSecond{
            ts_unsec /= 1000;
        }
        writer.write_u32::<B>(self.ts_sec)?;
        writer.write_u32::<B>(ts_unsec)?;
        writer.write_u32::<B>(self.incl_len)?;
        writer.write_u32::<B>(self.orig_len)?;
        writer.write_u32::<B>(self.interface_index)?;

        Ok(())
    }

}

pub struct AnPacket<'a> {

    /// Header of the packet
    pub header: AnPacketHeader,

    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>
}

impl<'a> AnPacket<'a> {

    /// Create a new borrowed `AnPacket` with the given parameters.
    pub fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> AnPacket<'a> {

        let header = AnPacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len,
            interface_index: 0
        };

        AnPacket {
            header,
            data: Cow::Borrowed(data)
        }
    }

    /// Create a new owned `AnPacket` with the given parameters.
    pub fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> AnPacket<'static> {

        let header = AnPacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len,
            interface_index: 0
        };

        AnPacket {
            header,
            data: Cow::Owned(data)
        }
    }

    /// Create a new owned `AnPacket` from a reader.
    pub fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<AnPacket<'static>> {

        let header = AnPacketHeader::from_reader::<R, B>(reader, ts_resolution)?;

        let mut bytes = vec![0_u8; header.incl_len as usize];
        reader.read_exact(&mut bytes)?;

        Ok(
            AnPacket {
                header,
                data : Cow::Owned(bytes)
            }
        )
    }

    /// Convert a borrowed `Packet` to an owned one.
     pub fn to_owned(& self) -> AnPacket<'static> {
        AnPacket {
            header: self.header,
            data: Cow::Owned(self.data.as_ref().to_owned())
        }
    }

    fn to_packet(&self) -> Packet {

        let header = PacketHeader {
            ts_sec: self.header.ts_sec,
            ts_nsec: self.header.ts_sec,
            incl_len: self.header.incl_len,
            orig_len: self.header.orig_len
        };

        Packet {
            header,
            data: self.data.clone()
        }
    }
}