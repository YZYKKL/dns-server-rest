use std::env;
// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use std::net::Ipv4Addr;

#[derive(Debug)]
struct DNSHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: u8,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSHeader  {
    fn from_bytes(bytes: &[u8]) -> Option<DNSHeader> {
        let mut u16s = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()));
        let id = u16s.next()?;
        let flags = u16s.next()?;
        let qdcount = u16s.next()?;
        let ancount = u16s.next()?;
        let nscount = u16s.next()?;
        let arcount = u16s.next()?;
        Some(DNSHeader {
            id,
            // qr: (flags >> 15) & 1 == 1,
            qr : true,
            opcode: ((flags >> 11) & 0b1111) as u8,
            aa: (flags >> 10) & 1 == 1,
            tc: (flags >> 9) & 1 == 1,
            rd: (flags >> 8) & 1 == 1,
            ra: (flags >> 7) & 1 == 1,
            z: ((flags >> 4) & 0b111) as u8,
            rcode: (flags & 0b1111) as u8,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        let mut flags = 0u16;
        flags |= (self.qr as u16) << 15;
        flags |= (self.opcode as u16) << 11;
        flags |= (self.aa as u16) << 10;
        flags |= (self.tc as u16) << 9;
        flags |= (self.rd as u16) << 8;
        flags |= (self.ra as u16) << 7;
        flags |= (self.z as u16) << 4;
        flags |= self.rcode as u16;
        bytes[2..4].copy_from_slice(&flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}
#[derive(Debug)]
struct DNSQuestion {
    pub domain_name: String,
    query_type: u16,
    query_class: u16,
}
impl DNSQuestion {
    fn read_domain(bytes: &[u8], offset: usize, s: &mut String) -> Option<usize> {
        let mut i = offset;
        loop {
            let len = bytes.get(i).copied()? as usize;
            if len == 0 {
                break Some(i + 1);
            }
            if len & 0b1100_0000 == 0b1100_0000 {
                let offset = u16::from_be_bytes([(len & !0b1100_0000) as u8, bytes[i + 1]]);
                let offset = offset as usize;
                s.push('.');
                DNSQuestion::read_domain(bytes, offset, s)?;
                break Some(i + 2);
            }
            if i > offset {
                s.push('.');
            }
            s.push_str(
                String::from_utf8_lossy(bytes.get(i + 1..i + 1 + len)?)
                    .to_lowercase()
                    .as_ref(),
            );
            i += 1 + len;
        }
    }

    fn from_bytes(bytes: &[u8], offset: usize) -> Option<(DNSQuestion, usize)> {
        let mut domain_name = String::new();
        let next_offset = DNSQuestion::read_domain(bytes, offset, &mut domain_name)?;
        let query_type = u16::from_be_bytes(bytes[next_offset..next_offset + 2].try_into().unwrap());
        let query_class = u16::from_be_bytes(bytes[next_offset + 2..next_offset + 4].try_into().unwrap());
        Some((DNSQuestion {domain_name, query_type, query_class },next_offset +4))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // write the name
        for part in self.domain_name.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        // write the null terminator byte
        bytes.push(0);
        // write the type
        bytes.extend_from_slice(&(self.query_type as u16).to_be_bytes());
        // write the class
        bytes.extend_from_slice(&(self.query_class as u16).to_be_bytes());
        bytes
    }

}

struct Message {
    pub header: DNSHeader,
    questions: Vec<DNSQuestion>,
    anwsers: Vec<DNSAnwser>,
}

impl Message {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.to_bytes());

        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }

        for anwser in &self.anwsers {
            bytes.extend_from_slice(&anwser.to_bytes());
        }
        bytes
    }

    fn read_message(bytes: &[u8]) -> Option<(DNSHeader, Vec<DNSQuestion>, Vec<DNSAnwser>)> {
        let header = DNSHeader::from_bytes(bytes)?;
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut offset = 12;
        for _ in 0..header.qdcount {
            let (question, next_offset) = DNSQuestion::from_bytes(bytes, offset)?;
            let answer= DNSAnwser::from_bytes(bytes, offset)?;
            questions.push(question);
            answers.push(answer);
            offset = next_offset;
        }
        Some((header, questions, answers))
    }

}

#[derive(Debug)]
pub struct DNSAnwser {
    pub domain_name: String,
    pub anwser_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}
impl DNSAnwser {
    pub fn ipv4_to_bytes(ip: Ipv4Addr) -> Vec<u8> {
        let octets = ip.octets();
        octets.to_vec()
    }

    fn default() -> Vec<DNSAnwser> {
        let mut answers = Vec::new();
        let anwser =  DNSAnwser{
            domain_name: "codecrafters.io".to_owned(),
            anwser_type: 1,
            class: 1,
            ttl: 60,
            rdlength: 4,
            rdata: vec![0x08, 0x08, 0x08, 0x08],
        };
        answers.push(anwser);
        answers
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.domain_name.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0 as u8);
        bytes.extend_from_slice(&(self.anwser_type as u16).to_be_bytes());
        bytes.extend_from_slice(&(self.class as u16).to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());
        bytes.extend_from_slice(&self.rdlength.to_be_bytes());
        bytes.extend_from_slice(&self.rdata);
        bytes
    }

    fn from_bytes(bytes: &[u8], offset: usize) -> Option<DNSAnwser> {
        let mut domain_name = String::new();
        let _ = DNSQuestion::read_domain(bytes, offset, &mut domain_name)?;
        // let anwser_type = u16::from_be_bytes(bytes[next_offset..next_offset + 2].try_into().unwrap());
        // let class = u16::from_be_bytes(bytes[next_offset + 2..next_offset + 4].try_into().unwrap());
        // let ttl = u32::from_be_bytes(bytes[next_offset + 4..next_offset + 8].try_into().unwrap());
        // let rdlength =
        //     u16::from_be_bytes(bytes[next_offset + 8..next_offset + 10].try_into().unwrap());
        // let rdata = bytes[next_offset + 10..next_offset + 10 + rdlength as usize].to_vec();
        Some(DNSAnwser {
                domain_name,
                anwser_type:1,
                class:1,
                ttl: 60,
                rdlength: 4,
                rdata: vec![0x08, 0x08, 0x08, 0x08],
            })
    }

}

#[allow(dead_code)]
#[repr(u16)] // 2 bytes
pub enum QuestionType {
    /// a host address
    A = 1_u16,
    /// an authoritative name server
    NS = 2,
    /// a mail destination (Obsolete - use MX)
    MD = 3,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,
}
#[allow(dead_code)]
#[repr(u16)] // 2 bytes
pub enum QuestionClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    let args: Vec<String> = env::args().collect();
    let resolver_socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind resolver socket");
    //resolver_socket.connect(&args[2]).expect("Failed to connect to resolver address");
    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                //let response = [];
                let (header, questions, anwsers) = Message::read_message(&buf[..size]).expect("Failed to parse header");

                println!("Recieved {:?}", &header );
                println!("Recieved {:?}", &questions );
                println!("Recieved {:?}", &anwsers );

                let mut resp_answer = Vec::new();

                for question in questions.iter(){
                    let forward_dns_message = Message {
                        header: DNSHeader {
                            id: header.id,
                            qr: true,
                            opcode: header.opcode,
                            aa: header.aa,
                            tc: header.tc,
                            rd: header.rd,
                            ra: header.ra,
                            z: header.z,
                            rcode: if header.opcode == 0 {
                                0
                            } else {
                                4
                            },
                            qdcount: header.qdcount,
                            ancount: anwsers.len() as u16,
                            nscount: header.nscount,
                            arcount: header.arcount,
                        },
                        questions: vec![DNSQuestion{
                            domain_name: question.domain_name.clone(),
                            query_type: question.query_type,
                            query_class: question.query_class, 
                        }],
                        anwsers: DNSAnwser::default(),
                    };
                    let mut f_buf = [0; 512];
                    resolver_socket.send(&forward_dns_message.to_bytes()).expect("Failed to send query");
                    let (f_size, f_source) = resolver_socket.recv_from(&mut f_buf).expect("Failed to receive response");
                    println!("Received {} bytes from {}", f_size, f_source);
                    let f_received_data = String::from_utf8_lossy(&f_buf[12..f_size]);
                    println!("received head: {:?}", &f_buf[0..11]);
                    println!("received data: {:?}", f_received_data);

                    let (header, questions, mut anwsers) = 
                        Message::read_message(&f_buf[..size]).expect("Failed to parse header");
                    
                    println!("Recieved {:?}", &header );
                    println!("Recieved {:?}", &questions );
                    println!("Recieved {:?}", &anwsers );
                    resp_answer.push(anwsers.pop().unwrap());
                }
                let (header, questions, _) = Message::read_message(&buf[..size]).expect("Failed to parse header");

                let resp = Message {
                    header: header,
                    questions: questions,
                    anwsers: resp_answer,
                };

                udp_socket
                    .send_to(&resp.to_bytes(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
