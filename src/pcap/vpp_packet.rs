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

pub trait SomePacketHeader<H> {
    
    fn new(ts_sec: u32, ts_nsec: u32, incl_len:u32, orig_len:u32) -> H;
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<H>;
    fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> ResultParsing<()>;
    fn from_slice<B: ByteOrder>(slice: &[u8], ts_resolution: TsResolution) -> ResultParsing<(&[u8], H)>;
    fn timestamp(&self) -> Duration;
    
}
pub trait SomePacket<'a, P: 'a> {

    fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> P ;
    fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> P;
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<P>;
    fn to_owned(& self) -> P;
    fn from_slice<B: ByteOrder>(slice: &'a[u8], ts_resolution: TsResolution) -> ResultParsing<(&'a[u8], P)>;
    fn convert(&self) -> P;

}

/// Describes a Vpp pcap packet header.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct VppPacketHeader {

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


impl SomePacketHeader<VppPacketHeader> for VppPacketHeader {
    /// Create a new `VppPacketHeader` with the given parameters.
   fn new(ts_sec: u32, ts_nsec: u32, incl_len:u32, orig_len:u32) -> VppPacketHeader {

       VppPacketHeader {
           ts_sec,
           ts_nsec,
           incl_len,
           orig_len, 
           interface_index: 0
       }
   }

    /// Create a new `PacketHeader` from a reader.
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<VppPacketHeader> {

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
            VppPacketHeader {

                ts_sec,
                ts_nsec,
                incl_len,
                orig_len,
                interface_index: 0
            }
        )
    }

    fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> ResultParsing<()> {

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

    /// Create a new `PacketHeader` from a slice.
    fn from_slice<B: ByteOrder>(mut slice: &[u8], ts_resolution: TsResolution) -> ResultParsing<(&[u8], VppPacketHeader)> {

        //Header len
        if slice.len() < 16 {
            return Err(PcapError::IncompleteBuffer(16 - slice.len()));
        }

        let header = Self::from_reader::<_, B>(&mut slice, ts_resolution)?;

        Ok((slice, header))
    }

    fn timestamp(&self) -> Duration {
        Duration::new(self.ts_sec.into(), self.ts_nsec)
    }

}

pub struct VppPacket<'a> {

    /// Header of the packet
    pub header: VppPacketHeader,

    /// Payload, owned or borrowed, of the packet
    pub data: Cow<'a, [u8]>
}

impl<'a> SomePacket<'a, VppPacket<'a>> for VppPacket<'a> {

    /// Create a new borrowed `VppPacket` with the given parameters.
    fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> VppPacket<'a> {

        let header = VppPacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len,
            interface_index: 0
        };

        VppPacket {
            header,
            data: Cow::Borrowed(data)
        }
    }

    /// Create a new owned `VppPacket` with the given parameters.
    fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> VppPacket<'static> {

        let header = VppPacketHeader {
            ts_sec,
            ts_nsec,
            incl_len: data.len() as u32,
            orig_len,
            interface_index: 0
        };

        VppPacket {
            header,
            data: Cow::Owned(data)
        }
    }

    /// Create a new owned `VppPacket` from a reader.
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<VppPacket<'static>> {

        let header = VppPacketHeader::from_reader::<R, B>(reader, ts_resolution)?;

        let mut bytes = vec![0_u8; header.incl_len as usize];
        reader.read_exact(&mut bytes)?;

        Ok(
            VppPacket {
                header,
                data : Cow::Owned(bytes)
            }
        )
    }

    /// Convert a borrowed `Packet` to Vpp owned one.
    fn to_owned(& self) -> VppPacket<'static> {
        VppPacket {
            header: self.header,
            data: Cow::Owned(self.data.as_ref().to_owned())
        }
    }

     /// Create a new borrowed `VppPacket` from a slice.
    fn from_slice<B: ByteOrder>(slice: &'a[u8], ts_resolution: TsResolution) -> ResultParsing<(&'a[u8], VppPacket<'a>)> {

        let (slice, header) = VppPacketHeader::from_slice::<B>(slice, ts_resolution)?;
        let len = header.incl_len as usize;

        if slice.len() < len {
            return Err(PcapError::IncompleteBuffer(len - slice.len()));
        }

        let packet = VppPacket {
            header,
            data : Cow::Borrowed(&slice[..len])
        };

        let slice = &slice[len..];

        Ok((slice, packet))
    }

    fn convert(&self) -> VppPacket<'a> {

        let header = VppPacketHeader {
            ts_sec: self.header.ts_sec,
            ts_nsec: self.header.ts_sec,
            incl_len: self.header.incl_len,
            orig_len: self.header.orig_len,
            interface_index: self.header.interface_index
        };

        VppPacket {
            header,
            data: self.data.clone()
        }
    }
}