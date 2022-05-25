
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
        original_file: String,
        processor: ProcessorExample
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
        /// let env = PcapTester::new("netinfo.pcap", processor.clone());
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
        pub fn new (original_file: &str, processor: ProcessorExample) -> PcapTester {
           PcapTester { original_file: original_file.to_string(), processor}
        }

        /// Open and print out encoded packets from file.
        pub fn pcap_print(file: &str) {
            let file = File::open(file).expect("Can`t open file!");
            let pcap_reader = PcapReader::new(file).unwrap();
        
            for pcap in pcap_reader {
                let pcap = pcap.unwrap();                                                                   
                println!("{:?} \n {} \n", pcap.header, hex::encode(pcap.data.as_ref()));
            }
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
            let mut reader = PcapReader::new(&file_from).map_err(|_|())?;
            let mut writer = PcapWriter::new(&file_to).map_err(|_|())?;
        
            while let Some(packet) = reader.next() {
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

        /// Process given file and compare it with original file.
        /// 
        ///  # Examples
        /// 
        /// ```
        /// let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        /// let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset);  //add to end of packet 
        /// 
        /// let env = PcapTester::new("netinfo.pcap", processor.clone());
        /// env.process_and_compare_files("netinfo.pcap", &mut processor);
        /// ```
        /// 
        pub fn process_and_compare_files<Processor: PacketProcessor> (&self, file: &str, processor: &mut Processor) -> Result<bool,()> {
            let file_lhs = File::open(&self.original_file).map_err(|_|())?;
            let file_rhs = File::open(file).map_err(|_|())?;
            let mut reader_lhs = PcapReader::new(&file_lhs).map_err(|_|())?;
            let mut reader_rhs = PcapReader::new(&file_rhs).map_err(|_|())?;
            
            let mut index: usize = 0;
            let mut packet_lhs_opt = reader_lhs.next();

            while let Some(packet_rhs) = reader_rhs.next() { 
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
                        println!("Packet {}: {} \n {}", index + 1, "FAIL".red().bold(), Self::compare_pakets_data(data_lhs, data_rhs));
                    }

                    index += 1;
                    packet_lhs_opt = reader_lhs.next();
                }                
            }

            Ok(reader_rhs.next().is_none()) 
        }
        
        /// Compare data from 2 vectors and return hex string with result.
        fn compare_pakets_data(data_lhs: Vec<u8>, data_rhs: Vec<u8>) -> String { 
            let data_lhs = hex::encode(data_lhs);
            let data_rhs = hex::encode(data_rhs);
            let mut result = "".to_string();

            match data_lhs.len().cmp(&data_rhs.len()) {
                Ordering::Greater => {
                    result.push_str(&format!("{} \n ", data_lhs));
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
                        } else {
                            result.push_str(&String::from_utf8_lossy(&[data_rhs.as_bytes()[j]]));
                        }
                    }
                }
            }
         
            result
        }

        /// Save 'PcapReader' to  given file.
        pub fn save_reader_to_new_pcap(file_to: &File, pcap_reader: PcapReader<File>) -> Result<(),()>  {
            let mut pcap_writer = PcapWriter::new(file_to).map_err(|_|())?;
            
            for pcap in pcap_reader {
                let pcap = pcap.unwrap();
                pcap_writer.write_packet(&pcap).unwrap();
            }
            Ok(())
        }
        
        /// Save 'PacketHeader' and packets to given file.
        pub fn save_data_to_new_pcap (file_to: &File, pcap_header: PcapHeader, packets: Vec<Packet>) -> Result<(),()> {
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
    fn peocessor_example_test() {
        let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset.clone());
        let mut processor2 = ProcessorExample::new(0, 0, dataset.clone());
        let mut processor3 = ProcessorExample::new(5, 8, dataset.clone());
        let mut processor4 = ProcessorExample::new(2, 8, dataset);
        let env = PcapTester::new("netinfo.pcap", processor2.clone());

        env.process_and_compare_files("netinfo.pcap", &mut processor);
        env.process_and_compare_files("netinfo.pcap", &mut processor2);
        env.process_and_compare_files("netinfo.pcap", &mut processor3);
        env.process_and_compare_files("netinfo.pcap", &mut processor4);
    }

    #[test]
    fn process_and_save_test() {
        let dataset: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        let mut processor = ProcessorExample::new(dataset.len(), dataset.len(), dataset.clone());
        let env = PcapTester::new("netinfo.pcap", processor.clone());

        env.process_and_save("new_file_test.pcap", &mut processor);
        File::open("new_file_test.pcap").expect("Can`t open file!");
    }

    #[test]
    fn get_new_file_from_reader() {
        let file_correct = File::open("netinfo2.pcap").expect("Error opening file\n");
        let new_file = File::create("new_file_from_reader.pcap").expect("Error opening file\n");
        let pcap_reader1 = PcapReader::new(file_correct).unwrap();
    
        PcapTester::save_reader_to_new_pcap(&new_file, pcap_reader1);
        File::open("new_file_from_reader.pcap").expect("Error opening file\n");
    
        fs::remove_file("new_file_from_reader.pcap");
    }


}

