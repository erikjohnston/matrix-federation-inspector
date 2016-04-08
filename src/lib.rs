#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]


extern crate ansi_term;
extern crate chrono;
#[macro_use] extern crate clap;
extern crate dns_parser;
extern crate itertools;
extern crate hyper;
extern crate openssl;
extern crate rand;
extern crate resolv_conf;
extern crate rustc_serialize;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate prettytable;

pub mod resolver;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::error::Error;

use openssl::ssl::{SslContext, SslStream, SslMethod, Ssl};
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;

use hyper::http::RawStatus;
use hyper::http::h1::Http11Message;
use hyper::http::message::{HttpMessage, RequestHead};
use hyper::net::HttpStream;
use hyper::header::{Host, Headers, Server};
use hyper::method::Method;

use itertools::Itertools;


quick_error!{
    #[derive(Debug)]
    pub enum SslStreamError {
        Io(err: std::io::Error) {
            from()
            description(err.description())
            display("I/O error: {}", err)
        }
        Ssl(err: SslError) {
            from()
            description(err.description())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateInfo {
    pub cert_sha256: Vec<u8>,
    pub common_name: String,
}


#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ip: IpAddr,
    pub port: u16,
    pub server_name: String,
    pub cipher_name: &'static str,
    pub cipher_version: &'static str,
    pub cipher_bits: i32,
    pub cert_info: CertificateInfo,
}

#[derive(Debug, Clone)]
pub struct ServerResponse {
    pub status_code: RawStatus,
    pub server_header: Option<String>,
    pub body: Vec<u8>,
}

pub fn get_ssl_info(server_name: &str, ipaddr: IpAddr, port: u16)
    -> Result<(ConnectionInfo, ServerResponse), SslStreamError>
{
    let stream = try!(match ipaddr {
        IpAddr::V4(ip) => TcpStream::connect((ip, port)),
        IpAddr::V6(ip) => TcpStream::connect((ip, port)),
    });

    let ssl_context = try!(SslContext::new(SslMethod::Sslv23));
    let ssl = try!(Ssl::new(&ssl_context));
    try!(ssl.set_hostname(server_name));

    // hyper requires we wrap the tcp stream in a HttpStream
    let ssl_stream = try!(SslStream::connect(ssl, HttpStream(stream)));

    let conn_info = {
        let peer_cert = ssl_stream.ssl().peer_certificate().unwrap();
        let cipher = ssl_stream.ssl().get_current_cipher().unwrap();
        let server_name = ssl_stream.ssl().get_servername().unwrap();

        let common_name = peer_cert.subject_name().text_by_nid(Nid::CN).unwrap().to_string();

        ConnectionInfo{
            ip: ipaddr,
            port: port,
            cipher_name: cipher.name(),
            cipher_version: ssl_stream.ssl().version(),
            cipher_bits: cipher.bits().secret,
            server_name: server_name,
            cert_info: CertificateInfo{
                common_name: common_name,
                cert_sha256: peer_cert.fingerprint(HashType::SHA256).unwrap(),
            }
        }
    };

    let mut msg = Http11Message::with_stream(Box::new(ssl_stream));

    let mut headers = Headers::new();
    headers.set(Host{
        hostname: server_name.to_string(),
        port: None,
    });

    let url = format!("https://{}/_matrix/key/v2/server/", server_name).parse().unwrap();

    msg.set_outgoing(RequestHead{
        headers: headers,
        method: Method::Get,
        url: url,
    }).unwrap();

    let resp_headers = msg.get_incoming().unwrap();

    let mut body = Vec::new();
    msg.read_to_end(&mut body).unwrap();

    let server_response = ServerResponse {
        status_code: resp_headers.raw_status,
        server_header: resp_headers.headers.get::<Server>().map(|s| s.0.clone()),
        body: body,
    };

    Ok((conn_info, server_response))
}


pub fn resolve_matrix_server(server_name: String, nameservers: &[IpAddr])
    -> (resolver::ResolveResultMap, Vec<(u16, u16, u16, IpAddr)>)
{
    let srv_name = "_matrix._tcp.".to_string() + &server_name;

    let mut srv_results_map = resolver::resolve(
        &nameservers[0],
        resolver::ResolveRequestType::SRV, srv_name.clone()
    );

    let was_soa_response = match srv_results_map.srv_map.get(&srv_name) {
        Some(&Err(ref e)) if e.is_name_error() => true,
        None => true,
        _ => false,
    };

    let ip_ports = if was_soa_response {
        srv_results_map = resolver::resolve(
            &nameservers[0],
            resolver::ResolveRequestType::Host, server_name.clone()
        );

        let ips = resolver::resolve_target_to_ips(&server_name, &srv_results_map);

        ips.into_iter().map(|ip| (0, 0, 8448, ip)).collect_vec()
    } else {
        srv_results_map.srv_map
            .values()  // -> iter of Result<HashSet<SrvResult>, ResolveError>
            .flat_map(|result| result) // -> iter of HashSet<SrvResult>
            .flat_map(|srv_results_set| srv_results_set.iter())  // -> iter of SrvResult
            .map(|srv_result| (
                resolver::resolve_target_to_ips(&srv_result.target, &srv_results_map),
                srv_result.priority,
                srv_result.weight,
                srv_result.port,
            ))  // -> (Vec<IpAddr>, port)
            .flat_map(
                |(ips, priority, weight, port)| ips.into_iter().map(move |ip|
                    (priority, weight, port, ip)
                )
            )
            .sorted_by(|a, b| (&a.1, &a.2).cmp(&(&b.1, &b.2)))
    };

    (srv_results_map, ip_ports)
}

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsFingerprint {
    pub sha256: String
}

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifyKey {
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyApiResponse {
    pub server_name: String,
    pub valid_until_ts: u64,
    pub verify_keys: BTreeMap<String, VerifyKey>,
    pub tls_fingerprints: Vec<TlsFingerprint>,
}
