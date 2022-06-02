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
    time::Duration, 
    fmt::Debug
};


pub trait SomePacketHeader: Sized {
    
    fn new(ts_sec: u32, ts_nsec: u32, incl_len:u32, orig_len:u32) -> Self;
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<Self>;
    fn write_to< W: Write, B: ByteOrder>(&self, writer: &mut W, ts_resolution: TsResolution) -> ResultParsing<()>;
    fn from_slice<B: ByteOrder>(slice: &[u8], ts_resolution: TsResolution) -> ResultParsing<(&[u8], Self)>;
    fn timestamp(&self) -> Duration;
    
}

// pub trait 

pub trait SomePacket<'a> {

    type Item;
    type Header;

    fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> Self::Item ;
    fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> Self::Item;
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<Self::Item>;
    fn to_owned(& self) -> Self::Item;
    fn from_slice< B: ByteOrder>(slice: &'a[u8], ts_resolution: TsResolution) -> ResultParsing<(&'a[u8], Self::Item)>;
    fn get_data(&self) -> &Cow<'a, [u8]>;
    fn get_header(&self) -> &Self::Header;
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

    /// Index of Interface
    pub interface_index: u32
}


impl SomePacketHeader for VppPacketHeader {
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
        let interface_index = reader.read_u32::<B>()?;

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
                interface_index
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

    /// Create a new `VppPacketHeader` from a slice.
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

impl<'a> SomePacket<'a> for VppPacket<'a> {

    type Item = VppPacket<'a>;
    type Header = VppPacketHeader;

    fn get_data(&self) -> &Cow<'a, [u8]> {
        &self.data
    }

    fn get_header(&self) -> &Self::Header {
        &self.header
    }

    /// Create a new borrowed `VppPacket` with the given parameters.
    fn new(ts_sec: u32, ts_nsec: u32, data: &'a [u8], orig_len: u32) -> Self::Item {

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
    fn new_owned(ts_sec: u32, ts_nsec: u32, data: Vec<u8>, orig_len: u32) -> Self::Item {

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
    fn from_reader<R: Read, B: ByteOrder>(reader: &mut R, ts_resolution: TsResolution) -> ResultParsing<Self::Item> {

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

    /// Convert a borrowed `VppPacket` to Vpp owned one.
    fn to_owned(& self) -> VppPacket<'static> {
        VppPacket {
            header: self.header,
            data: Cow::Owned(self.data.as_ref().to_owned())
        }
    }

     /// Create a new borrowed `VppPacket` from a slice.
    fn from_slice<B: ByteOrder>(slice: &'a[u8], ts_resolution: TsResolution) -> ResultParsing<(&'a[u8], Self::Item)> {

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

    
}

impl<'a> VppPacket<'a> {
    /// Convert 'VppPacket' to 'Packet'.
    pub fn convert(&self) -> Packet<'a> {

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

