extern crate ansi_term;
extern crate chrono;
extern crate dns_parser;
extern crate ip;
extern crate itertools;
extern crate hyper;
extern crate openssl;
extern crate rand;
extern crate resolv_conf;
extern crate rustc_serialize;
extern crate serde_json;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate prettytable;

mod resolver;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;
use prettytable::format::consts::FORMAT_CLEAN;

use std::collections::HashSet;
use std::io::{Read};
use std::fs::File;
use std::net::TcpStream;
use ansi_term::Style;
use ansi_term::Colour::{Red, Green};
use chrono::naive::datetime::NaiveDateTime;
use openssl::ssl::{SslContext, SslStream, SslMethod, Ssl};
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;
use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::FromBase64;
use std::error::Error;
use hyper::http::RawStatus;
use hyper::http::h1::Http11Message;
use hyper::http::message::{HttpMessage, RequestHead};
use hyper::net::HttpStream;
use hyper::header::{Host, Headers, Server};
use hyper::method::Method;
use serde_json::Value;



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
struct CertificateInfo {
    cert_sha256: Vec<u8>,
    common_name: String,
}


#[derive(Debug, Clone)]
struct ConnectionInfo {
    ip: ip::IpAddr,
    port: u16,
    server_name: String,
    cipher_name: &'static str,
    cipher_version: &'static str,
    cipher_bits: i32,
    cert_info: CertificateInfo,
}

#[derive(Debug, Clone)]
struct ServerResponse {
    status_code: RawStatus,
    server_header: Option<String>,
    body: Vec<u8>,
}

fn get_ssl_info(server_name: &String, ipaddr: ip::IpAddr, port: u16)
    -> Result<(ConnectionInfo, ServerResponse), SslStreamError>
{
    let stream = try!(match ipaddr {
        ip::IpAddr::V4(ip) => TcpStream::connect((ip, port)),
        ip::IpAddr::V6(ip) => TcpStream::connect((ip, port)),
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
        hostname: server_name.clone(),
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



fn main() {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf[..]).unwrap();

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        panic!("Expected single string argument <server_name>");
    }

    let server_name = args[1].to_string();

    println!("Resolving SRV records...");

    let srv_results_map = resolver::resolve(
        &cfg.nameservers[0],
        resolver::ResolveRequestType::SRV, "_matrix._tcp.".to_string() + &server_name
    );

    println!("Done.\n");

    for (target, result) in &srv_results_map.srv_map {
        println!("{}", Style::new().bold().paint(&target[..]));
        match result {
            &Ok(ref srv_results) => {
                let mut table = Table::new();

                table.add_row(row![
                    "priority", "weight", "port", "target"
                ]);

                for srv_result in srv_results {
                    table.add_row(Row::new(vec![
                        Cell::new(&srv_result.priority.to_string()),
                        Cell::new(&srv_result.weight.to_string()),
                        Cell::new(&srv_result.port.to_string()),
                        Cell::new(&srv_result.target),
                    ]));
                }

                table.printstd();
                println!("");
            }
            &Err(ref e) => {
                println!(
                    "{}: DNS Error: {}",
                    Red.bold().paint("FAILURE"), e
                );
                return;
            }
        }
    }

    if !srv_results_map.cname_map.is_empty() {
        println!("{}:", Style::new().bold().paint("CNAMEs"));

        let mut table = Table::new();

        table.add_row(row![
            "name", "target"
        ]);

        for (name, result) in &srv_results_map.cname_map {
            match result {
                &Ok(ref targets) => {
                    for target in targets {
                        table.add_row(Row::new(vec![
                            Cell::new(&name),
                            Cell::new(target),
                        ]));
                    }
                }
                &Err(ref e) => {
                    println!(
                        "{}: DNS Error: {}",
                        Red.bold().paint("FAILURE"), e
                    );
                    return;
                }
            }
        }

        table.printstd();
        println!("");
    }

    println!("{}:", Style::new().bold().paint("Hosts"));

    let mut table = Table::new();

    table.add_row(row![
        "Host", "IP"
    ]);

    for (name, result) in &srv_results_map.host_map {
        match result {
            &Ok(ref targets) => {
                for target in targets {
                    table.add_row(Row::new(vec![
                        Cell::new(&name),
                        Cell::new(&format!("{}", target)),
                    ]));
                }
            }
            &Err(ref e) => {
                println!(
                    "{}: DNS Error: {}",
                    Red.bold().paint("FAILURE"), e
                );

                table.add_row(Row::new(vec![
                    Cell::new(&name),
                    Cell::new(&format!("DNS Error: {}", e)).style_spec("Fr"),
                ]));
            }
        }
    }

    table.printstd();
    println!("");


    let mut srv_results : Vec<resolver::ResolvedSrvResult> = srv_results_map.srv_map
        .values()
        .flat_map(|v| v)
        .flat_map(|v| v.iter())
        .map(|v| v.resolve_from_maps(&srv_results_map))
        .collect();

    srv_results.sort_by_key(
        |srv: &resolver::ResolvedSrvResult| (srv.priority, !srv.weight)
    );

    let ip_ports : Vec<(ip::IpAddr, u16)> = srv_results.iter()
        .map(|s| (s.ips.iter(), s.port))
        .flat_map(
            |(ips, port)| ips.map(move |ip| (*ip, port))
        )
        .collect();

    println!("Testing TLS connections...\n");

    let mut conn_table = Table::new();
    conn_table.add_row(row![
        "IP", "Port", "Name", "Certificate", "Cipher Name", "Version", "Bits"
    ]);

    let mut err_table = Table::new();
    err_table.add_row(row![
        "IP", "Port", "Error"
    ]);

    let mut certificates = HashSet::new();
    let mut server_responses = Vec::new();

    for (ip, port) in ip_ports {
        match get_ssl_info(
            &server_name,
            ip,
            port,
        ) {
            Ok((conn_info, server_response)) => {
                certificates.insert(conn_info.cert_info.clone());

                let split_fingerprint = {
                    let s = conn_info.cert_info.cert_sha256.chunks(8)
                        .map(|chunk| chunk.to_hex().to_uppercase())
                        .collect::<Vec<String>>()
                        .join("\n");
                    s
                };

                let val : Value = serde_json::from_slice(&server_response.body).unwrap();
                let sn = val.find("server_name").and_then(|v| v.as_string()).unwrap_or("");

                // Should probably print if this is None
                let server_name_matching = sn == server_name;

                conn_table.add_row(Row::new(vec![
                    Cell::new(&conn_info.ip.to_string()).style_spec("Fgb"),
                    Cell::new(&conn_info.port.to_string()),
                    Cell::new(&conn_info.server_name),
                    Cell::new(&split_fingerprint),
                    Cell::new(conn_info.cipher_name),
                    Cell::new(conn_info.cipher_version),
                    Cell::new(&conn_info.cipher_bits.to_string()),
                ]));

                server_responses.push(((ip, port), server_response));
            }
            Err(e) => {
                err_table.add_row(Row::new(vec![
                    Cell::new(&ip.to_string()).style_spec("Frb"),
                    Cell::new(&port.to_string()),
                    Cell::new(&format!("{}", e)),
                ]));
            }
        }

    }


    // Headers count as a row.
    if conn_table.len() > 1 {
        conn_table.printstd();
        println!("");
    }

    if err_table.len() > 1 {
        err_table.printstd();
        println!("");
    }

    if !certificates.is_empty() {
        let mut cert_table = Table::new();
        cert_table.add_row(row![
            "Fingerprint SHA256", "CN"
        ]);

        for cert in certificates {
            let split_fingerprint = {
                let s = cert.cert_sha256.chunks(8)
                    .map(|chunk| chunk.to_hex().to_uppercase())
                    .collect::<Vec<String>>()
                    .join("\n");
                s
            };

            cert_table.add_row(Row::new(vec![
                Cell::new(&split_fingerprint),
                Cell::new(&cert.common_name),
            ]));
        }

        cert_table.printstd();
        println!("");
    }


    for ((ip, port), server_response) in server_responses {
        let val : Value = serde_json::from_slice(&server_response.body).unwrap();

        let mut server_table = Table::new();

        server_table.add_row(row![
            "IP/Port", &match ip {
                ip::IpAddr::V4(ref ipv4) => format!("{}:{}", ipv4, port),
                ip::IpAddr::V6(ref ipv6) => format!("[{}]:{}", ipv6, port),
            }
        ]);

        let sn = val.find("server_name").and_then(|v| v.as_string()).unwrap_or("");
        server_table.add_row(row![
            "Server Name ", &sn
        ]);

        let vu = val.find("valid_until_ts").and_then(|v| v.as_u64()).unwrap_or(0u64);
        let date = NaiveDateTime::from_timestamp(
            (vu / 1000) as i64, ((vu % 1000) * 1000000) as u32
        );
        server_table.add_row(row![
            "Valid until ", &format!("{}", date)
        ]);

        let ver = server_response.server_header.unwrap_or(String::new());
        server_table.add_row(row![
            "Server Header ", &ver
        ]);

        let verify_keys : Vec<(&String, &str)> = val.find("verify_keys").and_then(|v| v.as_object()).map(
            |v| v.iter().filter_map(
                |(k,v)| v.find("key").and_then(|s| s.as_string()).map(|s| (k,s))
            ).collect()
        ).unwrap();

        for (key, value) in verify_keys {
            server_table.add_row(row![
                "Verify key ", &format!("{}: {}", key, value)
            ]);
        }

        let tls_fingerprints = val.find("tls_fingerprints").and_then(|v| v.as_array())
            .map(|v| v.iter().filter_map(
                |o| o.find("sha256").and_then(|s| s.as_string())
            )).unwrap();

        for fingerprint in tls_fingerprints {
            server_table.add_row(row![
                "TLS fingerprint ", &fingerprint.from_base64().unwrap().to_hex().to_uppercase()
            ]);
        }

        server_table.set_format(*FORMAT_CLEAN);
        server_table.printstd();
        println!("");
    }
}
