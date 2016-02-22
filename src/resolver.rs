
use dns_parser;
use ip;
use rand;

use std;
use std::collections::BTreeMap;
use std::iter::IntoIterator;
use std::net::UdpSocket;
use rand::Rng;
use itertools::Itertools;

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

quick_error! {
    #[derive(Debug)]
    pub enum ResolveError {
        DnsError(err: DnsIoError) {
            from()
        }
        SrvDnsFailure(rcode: dns_parser::ResponseCode) {}
        HostResolveFailure(ip: Vec<String>) {}
    }
}

#[derive(Debug, Clone)]
pub struct SrvResult {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub ips: Vec<ip::IpAddr>,
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


fn load_answers(
    host_to_ips: &mut BTreeMap<String, Vec<ip::IpAddr>>,
    cname_to_host: &mut BTreeMap<String, String>,
    answers: &Vec<dns_parser::ResourceRecord>,
) -> bool {
    let mut changed = false;
    for answer in answers {
        match answer.data {
            dns_parser::RRData::A(ip) => {
                host_to_ips.entry(answer.name.to_string())
                    .or_insert(vec![])
                    .push(ip::IpAddr::V4(ip));
                changed = true;
            }
            dns_parser::RRData::AAAA(ip) => {
                host_to_ips.entry(answer.name.to_string())
                    .or_insert(vec![])
                    .push(ip::IpAddr::V6(ip));
                changed = true;
            }
            dns_parser::RRData::CNAME(name) => {
                cname_to_host.insert(answer.name.to_string(), name.to_string());
                changed = true;
            }
            _ => {}
        }
    }

    changed
}

fn get_unresolved_hosts<'a, U>(
    host_to_ips: &BTreeMap<String, Vec<ip::IpAddr>>,
    cname_to_host: &BTreeMap<String, String>,
    unresolved: &mut Vec<String>,
    hosts: U,
) where U: Iterator<Item=&'a String> {
    for host in hosts {
        if host_to_ips.contains_key(host) {
            continue;
        } else if let Some(cname) = cname_to_host.get(host) {
            get_unresolved_hosts(
                host_to_ips, cname_to_host, unresolved, Some(cname).into_iter()
            );
        } else {
            unresolved.push(host.clone());
        }
    }
}

fn get_resolved_hosts<'a, U>(
    host_to_ips: &BTreeMap<String, Vec<ip::IpAddr>>,
    cname_to_host: &BTreeMap<String, String>,
    resolved: &mut BTreeMap<String, Vec<ip::IpAddr>>,
    hosts: U,
) where U: Iterator<Item=&'a String> {
    for host in hosts {
        if let Some(ip) = host_to_ips.get(host) {
            resolved.insert(host.clone(), ip.clone());
        } else if let Some(cname) = cname_to_host.get(host) {
            get_resolved_hosts(
                host_to_ips, cname_to_host, resolved, Some(cname).into_iter()
            );
        }
    }
}


pub fn resolve_matrix_srv(server_name: &String, nameserver: &ip::IpAddr)
-> Result<Vec<SrvResult>, ResolveError> {
    let srv_host = "_matrix._tcp.".to_string() + server_name;

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
        send_query(&mut buf, nameserver, &query[..]).unwrap()
    };

    if packet.header.response_code != dns_parser::ResponseCode::NoError {
        return Err(ResolveError::SrvDnsFailure(packet.header.response_code));
    }

    let mut srv_results = vec![];
    for answer in packet.answers {
        if let dns_parser::RRData::SRV{ priority, weight, port, target } = answer.data {
            srv_results.push(SrvResult{
                priority: priority,
                weight: weight,
                port: port,
                target: target.to_string(),
                ips: vec![],
            });
        } else {
            panic!("Unexpected response: {:#?}", answer);
        }
    }

    let mut host_to_ips = BTreeMap::new();
    let mut cname_to_host = BTreeMap::new();

    // TODO: Currently the dns parser doesn't parse additional sections.
    load_answers(&mut host_to_ips, &mut cname_to_host, &packet.additional);

    let mut hosts_to_resolve = vec![];
    while {
        hosts_to_resolve.clear();

        get_unresolved_hosts(
            &host_to_ips,
            &cname_to_host,
            &mut hosts_to_resolve,
            srv_results.iter().map(|s| &s.target),
        );

        hosts_to_resolve.len() > 0
    } {
        let mut changed = false;

        let types : [dns_parser::QueryType; 2] = [dns_parser::QueryType::A, dns_parser::QueryType::AAAA];
        for (qtype, host) in types.iter().cartesian_product(hosts_to_resolve.iter()) {
            let mut buf2 = [0u8; 4096];

            let id = rand::thread_rng().gen();
            let mut builder = dns_parser::Builder::new_query(id, true);

            builder.add_question(
                &host[..],
                *qtype,
                dns_parser::QueryClass::IN
            );

            let query = builder.build().unwrap();
            let packet = send_query(&mut buf2, nameserver, &query[..]).unwrap();

            if packet.header.response_code != dns_parser::ResponseCode::NoError {
                return Err(ResolveError::SrvDnsFailure(packet.header.response_code));
            }

            changed |= load_answers(&mut host_to_ips, &mut cname_to_host, &packet.answers);
            changed |= load_answers(&mut host_to_ips, &mut cname_to_host, &packet.additional);
        }

        if !changed {
            return Err(ResolveError::HostResolveFailure(hosts_to_resolve.clone()));
        }
    }

    let mut resolved = BTreeMap::new();

    get_resolved_hosts(
        &host_to_ips,
        &cname_to_host,
        &mut resolved,
        srv_results.iter().map(|s| &s.target),
    );

    for srv_result in &mut srv_results {
        srv_result.ips = resolved[&srv_result.target].clone();
    }

    Ok(srv_results)
}


// pub fn resolve_a(hosts: &Vec<u8>) -> Result<
