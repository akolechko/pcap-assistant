
pub mod assistant {

    use pcap_file::pcap::{PcapReader, Packet,PcapWriter};
    use std::time::Duration;
    use std::io::prelude::*;
    use colored::Colorize;
    use std::borrow::Cow;
    use thiserror::Error;
    use pcap_parser::*;
    use std::fs::File;
    use std::vec;

    pub fn pcap_print(file: File) {
        let pcap_reader = PcapReader::new(file).unwrap();
    
        for pcap in pcap_reader {
            let pcap = pcap.unwrap();                                                                   
            println!("{:?} \n {} \n", pcap.header, hex::encode(pcap.data.as_ref()));
        }
    }
    
    fn modify_packet_data(packet: &mut Vec<u8>, start: usize, end: usize, new_data: &mut Vec<u8>) {
        // Add dataset to selected range
        if start < end && (end - start) == new_data.len() {
            packet.splice(start..end, new_data.clone());
        }

        // Add dataset from start point till end of dataset and trim end of packet 
        if start > 0 && end == 0 {
            packet.splice(start..(new_data.len() + start), new_data.clone());
            for i in (new_data.len() + start)..packet.len() {
               packet.pop(); 
            }
        }
        
        // If there are no enough data for range size
        if start < end && (end - start) > new_data.len() && end != 0 { 
            panic!("Range is bigger than data set! Uundefined scenario!");
        }  
            
        // If range is smaller than dataset size displace packet data to accommodate dataset
        if start < end && (end - start) < new_data.len() {
            let diff =  new_data.len() - (end - start); 
            let mut temp_vec: Vec<u8> = Vec::new();
            for i in end..packet.len() {   
                temp_vec.insert(0, packet.pop().unwrap());
            }
            for i in 0..new_data.len() {
                packet.push(*new_data.get(i).unwrap());
            }
            packet.append(&mut temp_vec);
        } 

        // If range is not defined add dataset to start of packet
        if start == 0 && end == 0 {
            for i in 0..new_data.len() {
                packet.insert(i,*new_data.get(i).unwrap());
            }
        }

        // If range is equal to sataset size add dataset to end of packet
        if start == new_data.len() && end == new_data.len() {
            for i in 0..new_data.len() {
                packet.push(*new_data.get(i).unwrap());
            }
        }
    }
    
    pub fn modify_pcap_data (file: &File, file_to: &File, start: usize, end: usize, new_data: &mut Vec<u8>) -> Result<(),()> {         
        let pcap_reader = PcapReader::new(file).map_err(|_|())?;
        let mut pcap_writer = PcapWriter::new(file_to).map_err(|_|())?;
         
        for packet in pcap_reader {
            let mut packet = packet.map_err(|_|())?;
            let mut header = packet.header;
            let mut packet_data: Vec<u8> = packet.data.iter().map(|c|*c).collect();
         
            modify_packet_data(&mut packet_data, start, end, new_data);
            header.orig_len = packet_data.len() as u32;
            header.incl_len = packet_data.len() as u32;
            
            let mut packet = Packet { header , data: Cow::Owned(packet_data) };
            pcap_writer.write_packet(&packet).map_err(|_|())?;
        }
        Ok(())
    }
    
    fn encode_reader (reader: PcapReader<&File>) -> Vec<String> {
        let mut vec: Vec<String> = Vec::new();
        for packet in reader {
            let packet = packet.unwrap();
            vec.push(format!("{}", hex::encode(packet.data.as_ref())));
        }
        
        vec
    }
    
    pub fn difference(file1: &File, file2: &File) {
        let pcap_reader1 = PcapReader::new(file1).unwrap();
        let pcap_reader2 = PcapReader::new(file2).unwrap();
        let mut file1_data: Vec<String> = encode_reader(pcap_reader1);
        let mut file2_data: Vec<String> = encode_reader(pcap_reader2);
        let mut result: Vec<String> = Vec::new();
        
        if file1_data.len() > file2_data.len() {

            for i in 0..file2_data.len() {
                let packet1 = file1_data.get(i).unwrap();
                let packet2 = file2_data.get(i).unwrap();
                
                if packet1 != packet2 {
                    let mut compared_packet = format!("Packet {}: {} \n         {} \n         ", i+1, "FAIL".red().bold(), packet1.clone());
                    if packet1.len() > packet2.len() {
                        for j in 0..packet2.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                                       
                    } else if packet2.len() > packet1.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                        for j in packet1.len()..packet2.len() {
                            compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                        }
    
                    } else if packet1.len() == packet2.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                    }
                    result.push(compared_packet);
                } else {
                    result.push(format!("Packet {}: {}", i+1, "OK".green().bold()));
                }
               
            }
            result.push(format!("{} \n", "End of file1:".bold()));
            for i in file2_data.len()..file1_data.len() {
                let packet = file1_data.get(i).unwrap();
                result.push(format!("Packet {} : {} \n         {}", i,"LONELY".yellow().bold(), packet.clone()));
            }
    
        } else if file1_data.len() < file2_data.len() {

            for i in 0..file1_data.len() {
                let packet1 = file1_data.get(i).unwrap();
                let packet2 = file2_data.get(i).unwrap();

                if packet1 != packet2 {
                    let mut compared_packet = format!("Packet {}: {} \n         {} \n         ", i+1, "FAIL".red().bold(), packet1.clone());
                    if packet1.len() > packet2.len() {
                        for j in 0..packet2.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                                       
                    } else if packet2.len() > packet1.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                        for j in packet1.len()..packet2.len() {
                            compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                        }
    
                    } else if packet1.len() == packet2.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                    }
                    result.push(compared_packet);
                } else {
                    result.push(format!("Packet {}: {}", i+1, "OK".green().bold()));
                }
               
            }
            result.push(format!("{} \n", "End of file2:".bold()));
            for i in file1_data.len()..file2_data.len() {
                let packet = file2_data.get(i).unwrap();
                result.push(format!("Packet {} : {} \n         {}", i,"LONELY".yellow().bold(), packet.clone()));
            }
        } else if file1_data.len() == file2_data.len() {

            for i in 0..file2_data.len() {
                let packet1 = file1_data.get(i).unwrap();
                let packet2 = file2_data.get(i).unwrap();
                            
                if packet1 != packet2 {
                    let mut compared_packet = format!("Packet {}: {} \n         {} \n         ", i+1, "FAIL".red().bold(), packet1.clone());
                    if packet1.len() > packet2.len() {
                        for j in 0..packet2.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                                    
                    } else if packet2.len() > packet1.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                        for j in packet1.len()..packet2.len() {
                            compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                        }
    
                    } else if packet1.len() == packet2.len() {
                        for j in 0..packet1.len() {
                            if packet1.as_bytes()[j] != packet2.as_bytes()[j] {
                                compared_packet.push_str( &format!("{}",String::from_utf8_lossy(&[packet2.as_bytes()[j]]).red()));
                            } else {
                                compared_packet.push_str( &String::from_utf8_lossy(&[packet2.as_bytes()[j]]));
                            }
                        }
                    }
                    result.push(compared_packet);
                } else {
                    result.push(format!("Packet {}: {}", i+1, "OK".green().bold()));
                } 
            }
        }
    
        for i in result {
            println!("{}", i);
        }
    }
    
    pub fn save_reader_to_new_pcap(file_to: &File, pcap_reader: PcapReader<File>) {
        let mut pcap_writer = PcapWriter::new(file_to).expect("Error writing file");
        
        for pcap in pcap_reader {
            let pcap = pcap.unwrap();
            pcap_writer.write_packet(&pcap).unwrap();
        }
    }
    
    pub fn save_data_to_new_pcap (file_to: &File, pcap_header: pcap_file::pcap::PcapHeader, packets: Vec<Packet>) {
        let mut pcap_writer = PcapWriter::with_header(pcap_header, file_to).expect("Error writing file");
    
        for packet in packets {
            pcap_writer.write_packet(&packet);
        }
    }
}
    
#[cfg(test)]
mod tests {
    use crate::assistant::*;
    use pcap_file::pcap::{PcapReader, Packet,PcapWriter};
    use std::time::Duration;
    use std::io::prelude::*;
    use colored::Colorize;
    use std::borrow::Cow;
    use thiserror::Error;
    use pcap_parser::*;
    use std::fs::File;
    use std::vec;
    use std::fs;

    #[test]
    fn compare_different_files() {
        let file_corect = File::open("netinfo.pcap").expect("Error opening file\n");
        let file_correct2 = File::open("netinfo2.pcap").expect("Error opening file\n");

        difference(&file_corect, &file_correct2);
    }

    #[test]
    fn compare_indentical_files() {
        let file_corect = File::open("netinfo.pcap").expect("Error opening file\n");
        let file_corect_clone = File::open("netinfo.pcap").expect("Error opening file\n");

        difference(&file_corect, &file_corect_clone);
    }

    #[test]
    fn modify_and_compare_files() {
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file.pcap").expect("Error opening file\n");
        let mut dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];

        modify_pcap_data(&file_correct, &new_file, 1, 7, &mut dataset);
        drop(file_correct);
        drop(new_file);

        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::open("new_file.pcap").expect("Error opening file\n");
        //difference(&file_correct, &new_file);

        fs::remove_file("new_file.pcap");
    }

    #[test]
    fn modify_file_with_trim() {
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file.pcap").expect("Error opening file\n");
        let mut dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];

        modify_pcap_data(&file_correct, &new_file, 10, 0, &mut dataset);
        drop(file_correct);
        drop(new_file);

        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::open("new_file.pcap").expect("Error opening file\n");
        //difference(&file_correct, &new_file);

        fs::remove_file("new_file.pcap");
    }

    #[test]
    fn modify_file_with_displace() {
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file.pcap").expect("Error opening file\n");
        let mut dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];

        modify_pcap_data(&file_correct, &new_file, 2, 4, &mut dataset);
        drop(file_correct);
        drop(new_file);

        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::open("new_file.pcap").expect("Error opening file\n");
        //difference(&file_correct, &new_file);

        fs::remove_file("new_file.pcap");
    }

    #[test]
    fn modify_start_and_end_of_packet() {
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file.pcap").expect("Error opening file\n");
        let new_file2 = File::create("new_file2.pcap").expect("Error opening file\n");
        let mut dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];

        //Add to end of packet 
        modify_pcap_data(&file_correct, &new_file, dataset.len(), dataset.len(), &mut dataset);
        drop(file_correct);
        drop(new_file);
        let new_file = File::open("new_file.pcap").expect("Error opening file\n");
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");

        // Add to start of packet
        modify_pcap_data(&new_file, &new_file2, 0, 0, &mut dataset);
        drop(new_file);
        drop(new_file2);
        let new_file2 = File::open("new_file2.pcap").expect("Error opening file\n");

        //difference(&file_correct, &new_file2);

        fs::remove_file("new_file.pcap");
        fs::remove_file("new_file2.pcap");
    }

    #[test]
    fn get_new_file_from_reader() {
        let file_correct = File::open("netinfo.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file_from_reader.pcap").expect("Error opening file\n");
        let pcap_reader1 = PcapReader::new(file_correct).unwrap();

        save_reader_to_new_pcap(&new_file, pcap_reader1);
        let new_file = File::open("new_file_from_reader.pcap").expect("Error opening file\n");

        fs::remove_file("new_file_from_reader.pcap");
    }

}