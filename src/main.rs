extern crate ansi_term;
extern crate dns_parser;
extern crate ip;
extern crate rand;
extern crate resolv_conf;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate prettytable;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;

use std::collections::BTreeMap;
use std::io::{Read};
use std::fs::File;
use std::net::UdpSocket;
use rand::Rng;
use ansi_term::Colour::{Red, Green};

quick_error! {
    #[derive(Debug)]
    pub enum DnsIoError {
        Io(err: std::io::Error) {
            from()
        }
        Parser(err: dns_parser::Error) {
            from()
        }
    }
}

#[derive(Debug, Clone)]
struct SrvResult {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

fn send_query<'a>(buf: &'a mut [u8], nameserver: &ip::IpAddr, query: &[u8])
-> Result<dns_parser::Packet<'a>, DnsIoError> {
    let socket = match nameserver {
        &ip::IpAddr::V4(addr) => {
            let socket = try!(UdpSocket::bind("0.0.0.0:0"));
            try!(socket.send_to(&query[..], (addr, 53)));
            socket
        }
        &ip::IpAddr::V6(addr) => {
            let socket = try!(UdpSocket::bind(":::0"));
            try!(socket.send_to(&query[..], (addr, 53)));
            socket
        }
    };

    let (size, _) = try!(socket.recv_from(buf));

    let packet = try!(dns_parser::Packet::parse(&buf[..size]));

    Ok(packet)
}


fn main() {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf[..]).unwrap();

    let server_name = "jki.re".to_string();
    let srv_host = "_matrix._tcp.".to_string() + &server_name;

    let mut buf = [0u8; 4096];
    let packet = {
        let id = rand::thread_rng().gen();
        let mut builder = dns_parser::Builder::new_query(id, true);
        builder.add_question(
            &srv_host[..],
            dns_parser::QueryType::SRV,
            dns_parser::QueryClass::IN
        );
        let query = builder.build().unwrap();
        send_query(&mut buf, &cfg.nameservers[0], &query[..]).unwrap()
    };
    // println!("packat {:?}", packet);

    if packet.header.response_code != dns_parser::ResponseCode::NoError {
        println!(
            "{}: Got DNS error: {:?}",
            Red.bold().paint("FAILURE"),
            packet.header.response_code
        );
        return;
    }

    let mut srv_results = vec![];
    for answer in packet.answers {
        if let dns_parser::RRData::SRV{ priority, weight, port, target } = answer.data {
            // println!("Record: {} {} {} {}", priority, weight, port, target);
            srv_results.push(SrvResult{
                priority: priority,
                weight: weight,
                port: port,
                target: target.to_string(),
            });
        } else {
            panic!("Unexpected response: {:#?}", answer);
        }
    }

    let mut host_to_ips = BTreeMap::new();
    let mut cname_to_host = BTreeMap::new();

    // TODO: Currently the dns parser doesn't parse additional sections.
    for additional in packet.additional {
        match additional.data {
            dns_parser::RRData::A(ip) => {
                host_to_ips.entry(additional.name.to_string()).or_insert(vec![]).push(ip);
            }
            dns_parser::RRData::CNAME(name) => {
                cname_to_host.insert(additional.name.to_string(), name.to_string());
            }
            _ => {}
        }
    }

    let mut hosts_to_resolve = vec![];
    while {
        hosts_to_resolve.clear();

        for srv_result in &srv_results {
            if host_to_ips.contains_key(&srv_result.target) {
                continue;
            } else if let Some(host) = cname_to_host.get(&srv_result.target) {
                if !host_to_ips.contains_key(host) {
                    hosts_to_resolve.push(host.clone());
                }
            } else {
                hosts_to_resolve.push(srv_result.target.clone());
            }
        }

        hosts_to_resolve.len() > 0
    } {
        let mut buf2 = [0u8; 4096];

        let id = rand::thread_rng().gen();
        let mut builder = dns_parser::Builder::new_query(id, true);
        for host in &hosts_to_resolve {
            builder.add_question(
                &host[..],
                dns_parser::QueryType::A,
                dns_parser::QueryClass::IN
            );
        }
        let query = builder.build().unwrap();
        let packet = send_query(&mut buf2, &cfg.nameservers[0], &query[..]).unwrap();

        let mut changed = false;
        for answer in packet.answers {
            match answer.data {
                dns_parser::RRData::A(ip) => {
                    host_to_ips.entry(answer.name.to_string()).or_insert(vec![]).push(ip);
                    changed = true;
                }
                dns_parser::RRData::CNAME(name) => {
                    cname_to_host.insert(answer.name.to_string(), name.to_string());
                    changed = true;
                }
                _ => {}
            }
        }

        for additional in packet.additional {
            match additional.data {
                dns_parser::RRData::A(ip) => {
                    host_to_ips.entry(additional.name.to_string()).or_insert(vec![]).push(ip);
                }
                dns_parser::RRData::CNAME(name) => {
                    cname_to_host.insert(additional.name.to_string(), name.to_string());
                }
                _ => {}
            }
        }

        if !changed {
            for host in &hosts_to_resolve {
                println!(
                    "{}: Failed to resolve record: {:?}",
                    Red.bold().paint("FAILURE"),
                    host
                );
            }
            return;
        }
    }

    let mut table = Table::new();

    table.add_row(row![
        "priority", "weight", "target", "port", "ip"
    ]);

    for srv_result in &srv_results {
        for ip in &host_to_ips[&srv_result.target] {
            table.add_row(Row::new(vec![
                Cell::new(&srv_result.priority.to_string()),
                Cell::new(&srv_result.weight.to_string()),
                Cell::new(&srv_result.port.to_string()),
                Cell::new(&srv_result.target),
                Cell::new(&ip.to_string()),
            ]));
        }
    }

    table.printstd();

    println!(
        "{}: Resolved domain.",
        Green.bold().paint("SUCCESS"),
    );
}
