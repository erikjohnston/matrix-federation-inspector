
use dns_parser;
use dns_parser::{QueryType, QueryClass, RRData};
use rand;

use std;
use std::error::Error;
use std::collections::{BTreeMap, HashSet};
use std::iter::IntoIterator;
use std::net::{IpAddr, UdpSocket};
use rand::Rng;


quick_error! {
    #[derive(Debug)]
    pub enum DnsIoError {
        Io(err: std::io::Error) {
            from()
            description(err.description())
            display("IoError: {}", err)
        }
        Parser(err: dns_parser::Error) {
            from()
            description(err.description())
            display("ParserError: {}", err)
        }
        UnexpectedPacket
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ResolveError {
        DnsError(err: DnsIoError) {
            from()
            description(err.description())
            display("DnsError: {}", err)
        }
        ServerFailure(rcode: dns_parser::ResponseCode) {
            description("NameServer responded with error")
            display(x) -> ("DnsServerFailure: {}, rcode: {:?}", x.description(), rcode)
        }
    }
}

impl ResolveError {
    pub fn is_name_error(&self) -> bool {
        match *self {
            ResolveError::ServerFailure(dns_parser::ResponseCode::NameError) => true,
            _ => false
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SrvResult {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

pub fn resolve_target_to_ips(target: &str, maps: &ResolveResultMap) -> Vec<IpAddr> {
    let mut result_ips = Vec::new();

    let mut queued_targets = vec![target];

    while let Some(target) = queued_targets.pop() {
        if let Some(&Ok(ref results)) = maps.host_map.get(target) {
            result_ips.extend(results.iter().filter_map(|r| r.as_ip().cloned()));
            queued_targets.extend(
                results.iter().filter_map(|r| r.as_cname()).map(|string| string as &str)
            );
        }
    }

    result_ips
}


fn send_query<'a>(buf: &'a mut [u8], nameserver: &IpAddr, query_type: QueryType, host: &str)
-> Result<dns_parser::Packet<'a>, DnsIoError> {
    let id = rand::thread_rng().gen();
    let mut builder = dns_parser::Builder::new_query(id, true);
    builder.add_question(
        host,
        query_type,
        QueryClass::IN
    );
    let query = builder.build().unwrap();

    let socket = match *nameserver {
        IpAddr::V4(addr) => {
            let socket = try!(UdpSocket::bind("0.0.0.0:0"));
            try!(socket.send_to(&query[..], (addr, 53)));
            socket
        }
        IpAddr::V6(addr) => {
            let socket = try!(UdpSocket::bind(":::0"));
            try!(socket.send_to(&query[..], (addr, 53)));
            socket
        }
    };

    let (size, _) = try!(socket.recv_from(buf));

    let packet = try!(dns_parser::Packet::parse(&buf[..size]));

    if packet.header.id != id {
        return Err(DnsIoError::UnexpectedPacket);
    }

    Ok(packet)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolveRequestType {
    SRV, Host,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostResult {
    CNAME(String),
    IP(IpAddr),
}

impl HostResult {
    pub fn as_cname(&self) -> Option<&String> {
        if let HostResult::CNAME(ref target) = *self {
            Some(target)
        } else {
            None
        }
    }

    pub fn as_ip(&self) -> Option<&IpAddr> {
        if let HostResult::IP(ref ip) = *self {
            Some(ip)
        } else {
            None
        }
    }
}

impl std::fmt::Display for HostResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            HostResult::CNAME(ref target) => target.fmt(f),
            HostResult::IP(ref ip) => ip.fmt(f),
        }
    }
}

#[derive(Debug)]
pub struct ResolveResultMap {
    pub srv_map: BTreeMap<String, Result<HashSet<SrvResult>, ResolveError>>,
    pub host_map: BTreeMap<String, Result<HashSet<HostResult>, ResolveError>>,
}


/// Uses the given nameserver to recursively resolve a target. Returns each query performed and
/// the result.
pub fn resolve(nameserver: &IpAddr, rtype: ResolveRequestType, target: String)
    -> ResolveResultMap
{
    let mut pending_queries = Vec::new();
    match rtype {
        ResolveRequestType::SRV => {
            pending_queries.push((QueryType::SRV, target));
        }
        ResolveRequestType::Host => {
            pending_queries.push((QueryType::A, target.clone()));
            pending_queries.push((QueryType::AAAA, target));
        }
    }

    let mut srv_result_map = BTreeMap::new();
    let mut host_result_map = BTreeMap::new();

    let mut buf = [0u8; 4096];

    while let Some((qtype, target)) = pending_queries.pop() {
        let res = resolve_internal(nameserver, &mut buf, qtype, &target[..]);
        match res {
            Ok(rtype_map) => {
                let ResolveResultMapInternal{srv_map, host_map} = rtype_map;

                // The following block works out if we need to continue resolving
                // anything, e.g. CNAMEs
                {
                    let target_srv_iter = srv_map.values()
                        .flat_map(|r| r.iter())
                        .map(|r| &r.target);

                    for target in target_srv_iter {
                        if host_map.contains_key(target) || host_result_map.contains_key(target) {
                            continue;
                        }

                        if !pending_queries.contains(&(QueryType::A, target.clone())) {
                            pending_queries.push((QueryType::A, target.clone()));
                        }
                        if !pending_queries.contains(&(QueryType::AAAA, target.clone())) {
                            pending_queries.push((QueryType::AAAA, target.clone()));
                        }
                    }
                }

                // Update each map one by one. If we find one that is in an error
                // state we *don't* clobber

                for (k, vec) in srv_map {
                    let entry = srv_result_map.entry(k).or_insert_with(|| Ok(HashSet::new()));
                    if let Ok(ref mut curr_vec) = *entry {
                        curr_vec.extend(vec.into_iter());
                    }
                }

                for (k, vec) in host_map {
                    let entry = host_result_map.entry(k).or_insert_with(|| Ok(HashSet::new()));
                    if let Ok(ref mut curr_vec) = *entry {
                        curr_vec.extend(vec.into_iter());
                    }
                }
            }
            Err(e) => {
                match qtype {
                    QueryType::A | QueryType::AAAA => {
                        host_result_map.insert(target, Err(e));
                    }
                    QueryType::SRV => {
                        srv_result_map.insert(target, Err(e));
                    }
                    _ => {}
                }
            }
        }
    }

    ResolveResultMap {
        srv_map: srv_result_map,
        host_map: host_result_map,
    }
}


struct ResolveResultMapInternal {
    pub srv_map: BTreeMap<String, HashSet<SrvResult>>,
    pub host_map: BTreeMap<String, HashSet<HostResult>>,
}


fn resolve_internal(nameserver: &IpAddr, buf: &mut [u8], qtype: QueryType, target: &str)
    -> Result<ResolveResultMapInternal, ResolveError>
{
    let packet = try!(send_query(buf, nameserver, qtype, target));

    if packet.header.response_code != dns_parser::ResponseCode::NoError {
        return Err(ResolveError::ServerFailure(packet.header.response_code));
    }

    let mut srv_map = BTreeMap::new();
    let mut host_map = BTreeMap::new();

    for answer in packet.answers {
        match answer.data {
            RRData::A(ip) => {
                host_map.entry(answer.name.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(HostResult::IP(IpAddr::V4(ip)));
            }
            RRData::AAAA(ip) => {
                host_map.entry(answer.name.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(HostResult::IP(IpAddr::V6(ip)));
            }
            RRData::CNAME(name) => {
                host_map.entry(answer.name.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(HostResult::CNAME(name.to_string()));
            }
            RRData::SRV{priority, weight, port, target} => {
                srv_map.entry(answer.name.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(SrvResult {
                        priority: priority,
                        weight: weight,
                        port: port,
                        target: target.to_string(),
                    });
            }
            _ => {}
        }
    }

    Ok(ResolveResultMapInternal {
        srv_map: srv_map,
        host_map: host_map,
    })
}
