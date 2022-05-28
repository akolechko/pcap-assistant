
pub mod assistant {

    use crate::pcap::*;
    use std::cmp::Ordering;
    use colored::Colorize;
    use std::borrow::Cow;
    use std::fs::File;

    /// Trait for packet processor realization.
    /// 
    /// Implement this function to process packet in your scenario.
    pub trait PacketProcessor {
        /// Processes the packet (`Vec<u8>`) and returns false if packet must be dropped and true otherwise.
        fn process_packet(&mut self, _: &mut Vec<u8>) -> bool;
    }
    
    /// PcapTester with original_file and processor.
    #[derive(Default)]
    pub struct PcapTester {
        original_file: String
    }

   /// ProcessorExample with range (start..end) and dataset.
    #[derive(Clone,Debug,Default)]
    pub struct ProcessorExample {
        start: usize, 
        end: usize, 
        new_data: Vec<u8>
    }

    impl ProcessorExample {
        /// Creates a new 'ProcessorExample' with the given parameters.
        pub fn new (start: usize, end: usize, new_data: Vec<u8>) -> ProcessorExample {

            ProcessorExample { start, end, new_data }
        }
    }

    impl PacketProcessor for ProcessorExample {
        /// Example of 'PacketProcessor' implementation, change the packet with given data.
        /// 
        /// # Panic
        /// 
        /// If start or end of range is larger then packet length or given dataset length
        /// is smaller than range length or start of range is bigger then end.
        /// 
        /// # Examples
        /// 
        /// ```
        /// use std::fs::File;
        /// use pcap_assistant::assistant::PcapTester;
        /// use pcap_assistant::assistant::ProcessorExample;
        /// 
        /// let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        /// let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset);  //add to end of packet 
        /// //let mut processor = ProcessorExample::new(0, 0, dataset);  //add to start of packet 
        /// //let mut processor = ProcessorExample::new(2, 8, dataset);  //add to range 
        /// //let mut processor = ProcessorExample::new(2, 4, dataset);  //add and displace packet data to accommodate dataset
        /// //let mut processor = ProcessorExample::new(10, 0, dataset); //add dataset from start point and trim packet after end of dataset
        /// 
        /// let env = PcapTester::new("netinfo.pcap");
        /// env.process_and_compare_files("netinfo.pcap", &mut processor);
        /// ```
        /// 
        fn process_packet(&mut self, packet: &mut Vec<u8>) -> bool {
            if self.start > packet.len() || self.end > packet.len(){
                panic!("Range is out of packet bounds");
            }  

             // If there are no enough data for range size
            if self.start < self.end && (self.end - self.start) > self.new_data.len()  { 
                panic!("Range is bigger than data set! Uundefined scenario!");
            } 
            // Add dataset to selected range
            if self.start < self.end && (self.end - self.start) == self.new_data.len() {
                packet.splice(self.start..self.end, self.new_data.clone());

                return true;
            }  

            // Add dataset from start point till end of dataset and trim of packet end
            if self.start > 0 && self.end == 0 {
                packet.splice(self.start..(self.new_data.len() + self.start), self.new_data.clone());
                for _ in (self.new_data.len() + self.start)..packet.len() {
                    packet.pop(); 
                }

                return true;
            }  
            
            // If range is smaller than dataset size displace packet data to accommodate dataset
            if self.start < self.end && (self.end - self.start) < self.new_data.len() {
                let mut temp_vec: Vec<u8> = Vec::new();
                for _ in self.end..packet.len() {   
                    temp_vec.insert(0, packet.pop().unwrap());
                }
                for i in 0..self.new_data.len() {
                    packet.push(*self.new_data.get(i).unwrap());
                }
                packet.append(&mut temp_vec);

                return true;
            } 

            // If range is not defined add dataset to start of packet
            if self.start == 0 && self.end == 0 {
                for i in 0..self.new_data.len() {
                    packet.insert(i,*self.new_data.get(i).unwrap());
                }

                return true;
            } 

            // If range is equal to dataset size add dataset to end of packet
            if self.start == self.new_data.len() && self.end == self.new_data.len() {
                for i in 0..self.new_data.len() {
                    packet.push(*self.new_data.get(i).unwrap());
                }
                
                return true;
            } 
            
            false
        }
    
    }

    impl PcapTester {
        /// Creates a new 'PcapTester' with the given parameters.
        pub fn new (original_file: &str) -> PcapTester {
           PcapTester { original_file: original_file.to_string()}
        }

        /// Open and print out encoded packets from file.
        pub fn print_reg_pcap(file: &str) {
            let file = File::open(file).expect("Can`t open file!");
            let pcap_reader = PcapReader::<File, Packet<'static>>::new(file).expect("Can`t create reader");
    
            for pcap in pcap_reader {
                let pcap = pcap.unwrap();                                                                   
                println!("{:?} \n {} \n", pcap.header, hex::encode(pcap.data.as_ref()));
            }
        }

        /// Open and print out encoded Vpp packets from file.
        pub fn print_vpp_pcap(file: &str) {
            let file = File::open(file).expect("Can`t open file!");
            let pcap_reader = PcapReader::<File, VppPacket<'static>>::new(file).unwrap();
        
            for pcap in pcap_reader {
                let pcap = pcap.unwrap();                                                                   
                println!("{:?} \n {} \n", pcap.header, hex::encode(pcap.data.as_ref()));
            }
        }

        /// Compare data from 2 vectors and return tuple with hex string with visual difference 
        /// and bool (true if data is same and false if is differend) .
        pub fn compare_pakets_data(data_lhs: &Vec<u8>, data_rhs: &Vec<u8>) -> (String, bool) { 
            let data_lhs = hex::encode(data_lhs);
            let data_rhs = hex::encode(data_rhs);
            let mut result = "".to_string();
            let mut is_same = true;

            match data_lhs.len().cmp(&data_rhs.len()) {
                Ordering::Greater => {
                    result.push_str(&format!("{} \n ", data_lhs));
                    is_same = false;
                    for j in 0..data_rhs.len() {
                        if data_lhs.as_bytes()[j] != data_rhs.as_bytes()[j] {
                            result.push_str( &format!("{}", String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]).red()));
                        } else {
                            result.push_str( &String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]));
                        }
                    }
                },
                Ordering::Less => {
                    result.push_str(&format!("{} \n  ", data_lhs));
                    is_same = false;
                    for j in 0..data_lhs.len() {
                        if data_lhs.as_bytes()[j] != data_rhs.as_bytes()[j] {
                            result.push_str( &format!("{}", String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]).red()));
                        } else {
                            result.push_str( &String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]));
                        }
                    }
                    for j in data_lhs.len()..data_rhs.len() {
                        result.push_str( &format!("{}", String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]).red()));
                    }
                },
                Ordering::Equal => {
                    result.push_str(&format!("{} \n ", data_lhs));
                    for j in 0..data_lhs.len() {
                        if data_lhs.as_bytes()[j] != data_rhs.as_bytes()[j] {
                            result.push_str(&format!("{}", String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]).red()));
                            is_same = false;
                        } else {
                            result.push_str(&String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]));
                        }
                    }
                }
            }
            
            if !is_same {
                return (result, false);
            }

            (result, true)
        }
        /// Process original file and save result to new file.
        /// 
        /// # Example
        /// 
        /// ```
        /// let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        /// let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset); 
        /// let env = PcapTester::new("netinfo.pcap", processor.clone());
        /// 
        /// env.process_and_save("new_file.pcap", &mut processor);
        /// 
        /// ```
        pub fn process_and_save(&self, file_to: &str, processor: &mut ProcessorExample) -> Result<bool,()> { 
            let file_from = File::open(&self.original_file).map_err(|_|())?;
            let file_to = File::create(file_to).map_err(|_|())?;
            let reader = PcapReader::<File, Packet<'static>>::new(file_from).map_err(|_|())?;
            let mut writer = PcapWriter::new(&file_to).map_err(|_|())?;
        
            for packet in reader {
                let packet  = packet.map_err(|_|())?;
                let mut data: Vec<u8> = packet.data.iter().copied().collect();
                let mut header = packet.header;

                let is_dropped = !processor.process_packet(&mut data);
                if !is_dropped {
                    
                    header.orig_len = data.len() as u32;
                    header.incl_len = data.len() as u32;
                    
                    let packet = Packet { header , data: Cow::Owned(data) };
                    writer.write_packet(&packet).map_err(|_|())?;  

                }                
            }
            Ok(true)
        }

                    /// Process original file and save result to new file.
                    pub fn process_and_save_vpp(&self, file_to: &str, processor: &mut ProcessorExample) -> Result<bool,()> { 
            let file_from = File::open(&self.original_file).map_err(|_|())?;
            let file_to = File::create(file_to).map_err(|_|())?;
            let reader = PcapReader::<File, VppPacket<'static>>::new(file_from).map_err(|_|())?;
            let mut writer = PcapWriter::new(&file_to).map_err(|_|())?;
        
            for packet in reader {
                let packet  = packet.map_err(|_|())?;
                let mut data: Vec<u8> = packet.data.iter().copied().collect();
                let mut header = packet.header;

                let is_dropped = !processor.process_packet(&mut data);
                if !is_dropped {
                    
                    header.orig_len = data.len() as u32;
                    header.incl_len = data.len() as u32;
                    
                    let packet = VppPacket { header , data: Cow::Owned(data) };
                    writer.write_packet(&packet).map_err(|_|())?;  

                }                
            }
            Ok(true)
        }

        /// Process given file and compare it with original file.
        /// 
        /// Returns true if file ended and false if self.file ended.
        /// 
        ///  # Examples
        /// 
        /// ```
        /// let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        /// let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset);  //add to end of packet 
        /// 
        /// let env = PcapTester::new("netinfo.pcap");
        /// env.process_and_compare_files("netinfo.pcap", &mut processor);
        /// ```
        /// 
        pub fn process_and_compare_files<Processor: PacketProcessor> (&self, file: &str, processor: &mut Processor) -> Result<bool,()> {
            let file_lhs = File::open(&self.original_file).map_err(|_|())?;
            let file_rhs = File::open(file).map_err(|_|())?;
            let mut reader_lhs = PcapReader::<File, Packet<'static>>::new(file_lhs).map_err(|_|())?;
            let mut reader_rhs = PcapReader::<File, Packet<'static>>::new(file_rhs).map_err(|_|())?;
            
            let mut index: usize = 0;
            let mut packet_lhs_opt = reader_lhs.next();

            for packet_rhs in reader_rhs.by_ref() { 
                let mut data_rhs: Vec<u8> = packet_rhs.unwrap().data.iter().copied().collect();
                let is_dropped = !processor.process_packet(&mut data_rhs);
                if !is_dropped {
                    if packet_lhs_opt.is_none() {
                        return Ok(false);
                    }

                    let data_lhs:Vec<u8> = packet_lhs_opt.unwrap().unwrap().data.iter().copied().collect();

                    if data_rhs == data_lhs {
                        println!("Packet {}: {}", index + 1, "OK".green().bold());
                    } else {
                        println!("Packet {}: {} \n {}", index + 1, "FAIL".red().bold(), Self::compare_pakets_data(&data_lhs, &data_rhs).0);
                    }

                    index += 1;
                    packet_lhs_opt = reader_lhs.next();
                }                
            }

            Ok(reader_rhs.next().is_none()) 
        }
        
        /// Compare .pcap files (original and provided).
        /// 
        /// Returns true if files are same and false if different.
        /// # Example
        /// ```
        /// let env = PcapTester::new("file.pcap");
        /// env.compare_files("file2.pcap");
        /// ```
        pub fn compare_files(&self, file: &str) -> Result<bool, ()> {
            let file_lhs = File::open(&self.original_file).map_err(|_|())?;
            let file_rhs = File::open(file).map_err(|_|())?;
            let mut reader_lhs = PcapReader::<File, Packet<'static>>::new(file_lhs).map_err(|_|())?;
            let reader_rhs = PcapReader::<File, Packet<'static>>::new(file_rhs).map_err(|_|())?;
            let mut is_same = true;

            for (index, packet_rhs) in reader_rhs.enumerate() { 
                let packet_lhs_opt = reader_lhs.next();

                if packet_lhs_opt.is_none() && is_same {
                    return Ok(true);
                } else if packet_lhs_opt.is_none() && !is_same {
                    return Ok(false);
                }
                let data_rhs: Vec<u8> = packet_rhs.unwrap().data.iter().copied().collect();
                let data_lhs: Vec<u8> = packet_lhs_opt.unwrap().unwrap().data.iter().copied().collect();

                if data_rhs == data_lhs {
                    println!("Packet {}: {}", index, "OK".green().bold());
                } else {
                    is_same = false;
                    println!("Packet {}: {} \n {}", index, "FAIL".red().bold(), Self::compare_pakets_data(&data_lhs, &data_rhs).0);
                }

            }

            if is_same {
                return Ok(true);
            }

            Ok(false)
        }
        
                    /// Convert 'VppPackets' to 'Packets' and save to new file.
                    pub fn convert_and_save_reg (&self, file_from: &str, file_to: &str) -> Result<(), ()> {
            let file_from = File::open(file_from).map_err(|_|())?;
            let file_to = File::create(file_to).map_err(|_|())?;
            let reader = PcapReader::<File, VppPacket<'static>>::new(file_from).map_err(|_|())?;
            let mut writer = PcapWriter::new(file_to).map_err(|_|())?;

            for data in reader {
                let packet = VppPacket::convert(&data.unwrap());
                writer.write_packet(&packet).map_err(|_|())?;
            }

            Ok(())
        }

                    /// Convert 'Packets' to 'VppPackets' and save to new file.
                    pub fn convert_and_save_vpp (&self, file_from: &str, file_to: &str) -> Result<(), ()> {
            let file_from = File::open(file_from).map_err(|_|())?;
            let file_to = File::create(file_to).map_err(|_|())?;
            let reader = PcapReader::<File, Packet<'static>>::new(file_from).map_err(|_|())?;
            let mut writer = PcapWriter::new(file_to).map_err(|_|())?;

            for packet in reader {
                let packet = packet.unwrap();
                
                let vpp_packet = Packet::convert(&packet);
                writer.write_packet(&vpp_packet).map_err(|_|())?;
            }

            Ok(())
        }

        /// Save 'PcapReader' with Packets to given file.
        pub fn save_reader_to_new_pcap(file_to: &str, pcap_reader: PcapReader<File, Packet<'static>>) -> Result<(),()>  {
            let file_to = File::create(file_to).map_err(|_|())?;
            let mut pcap_writer = PcapWriter::new(file_to).map_err(|_|())?;
            
            for packet in pcap_reader {
                let packet = packet.unwrap();
                pcap_writer.write_packet(&packet).unwrap();
            }
            Ok(())
        }

        /// Save 'PcapReader' with VppPackets to given file.
        pub fn save_vppreader_to_new_pcap(file_to: &str, pcap_reader: PcapReader<File, VppPacket<'static>>) -> Result<(),()>  {
            let file_to = File::create(file_to).map_err(|_|())?;
            let mut pcap_writer = PcapWriter::new(file_to).map_err(|_|())?;
            
            for pcap in pcap_reader {
                let pcap = pcap.unwrap();
                pcap_writer.write_packet(&pcap).unwrap();
            }
            Ok(())
        }

        /// Save 'PacketHeader' and Packets to given file.
        pub fn save_packets_to_new_pcap (file_to: &str, pcap_header: PcapHeader, packets: Vec<Packet>) -> Result<(),()> {
            let file_to = File::create(file_to).map_err(|_|())?;
            let mut pcap_writer = PcapWriter::with_header(pcap_header, file_to).map_err(|_|())?;
    
            for packet in packets {
                pcap_writer.write_packet(&packet).map_err(|_|())?;
            }
            Ok(())
        }

        /// Save 'PacketHeader' and VppPackets to given file.
        pub fn save_vpp_packets_to_new_pcap (file_to: &str, pcap_header: PcapHeader, packets: Vec<VppPacket>) -> Result<(),()> {
            let file_to = File::create(file_to).map_err(|_|())?;
            let mut pcap_writer = PcapWriter::with_header(pcap_header, file_to).map_err(|_|())?;
    
            for packet in packets {
                pcap_writer.write_packet(&packet).map_err(|_|())?;
            }
            Ok(())
        }
    
    }
}
    

#[cfg(test)]
mod tests {
    use crate::pcap_assistant::assistant::*;
    use crate::pcap::*;
    use std::fs::File;
    use std::vec;
    use std::fs;

    #[test]
    fn compare_files_test() {
        let env = PcapTester::new("netinfo2.pcap");
        assert!(env.compare_files("netinfo2.pcap").unwrap());
    }

    #[test]
    fn convert_test() {
        let env = PcapTester::new("netinfo2.pcap");
        env.convert_and_save_vpp("netinfo2.pcap", "new.pcap").unwrap();
        PcapTester::print_vpp_pcap("new.pcap");
    }

    #[test]
    fn compare_pakets_data_test() {
        let data_rhs: Vec<u8> = vec![1, 2, 3, 4, 5];
        let mut data_lhs: Vec<u8> = vec![1, 2, 3, 4, 5];

        assert!(PcapTester::compare_pakets_data(&data_lhs, &data_rhs).1);

        data_lhs.push(6);

        assert!(!PcapTester::compare_pakets_data(&data_lhs, &data_rhs).1);
    }
    
    #[test]
    fn process_and_compare_test() {

    }

    #[test]
    fn processor_example_test() {
        let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset.clone());
        let mut processor2 = ProcessorExample::new(0, 0, dataset.clone());
        let mut processor3 = ProcessorExample::new(5, 8, dataset.clone());
        let mut processor4 = ProcessorExample::new(2, 8, dataset);
        let env = PcapTester::new("netinfo.pcap");

        env.process_and_compare_files("netinfo.pcap", &mut processor).unwrap();
        env.process_and_compare_files("netinfo.pcap", &mut processor2).unwrap();
        env.process_and_compare_files("netinfo.pcap", &mut processor3).unwrap();
        env.process_and_compare_files("netinfo.pcap", &mut processor4).unwrap();
    }

    #[test]
    fn process_and_save_test() {
        let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset);
        let env = PcapTester::new("netinfo.pcap");

        assert!(env.process_and_save("new_file_test.pcap", &mut processor).unwrap());
        File::open("new_file_test.pcap").expect("Can`t open file!");

        assert!(!env.compare_files("new_file_test.pcap").unwrap());
    }

    #[test]
    fn save_reader_to_new_pcap_test() {
        let file_correct = File::open("netinfo2.pcap").expect("Error opening file\n");
        let pcap_reader1 = PcapReader::new(file_correct).unwrap();
    
        PcapTester::save_reader_to_new_pcap("new_file_from_reader.pcap", pcap_reader1).unwrap();
        File::open("new_file_from_reader.pcap").expect("Error opening file\n");
    
        fs::remove_file("new_file_from_reader.pcap").unwrap();
    }

    #[test]
    fn save_packets_to_new_pcap_test() {

    }

}

