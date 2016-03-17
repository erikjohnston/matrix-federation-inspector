extern crate ansi_term;
extern crate chrono;
#[macro_use] extern crate clap;
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

use std::collections::{HashSet, BTreeMap};
use std::fmt::Display;
use std::io::{Read};
use std::fs::File;
use std::net::TcpStream;
use std::error::Error;

use clap::{App, AppSettings, Arg, SubCommand};

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;
use prettytable::format::{FormatBuilder, LinePosition, LineSeparator};
use prettytable::format::consts::FORMAT_CLEAN;

use ansi_term::Style;
// use ansi_term::Colour::{Red, Green};

use chrono::naive::datetime::NaiveDateTime;

use openssl::ssl::{SslContext, SslStream, SslMethod, Ssl};
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type as HashType;
use openssl::nid::Nid;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::FromBase64;

use hyper::http::RawStatus;
use hyper::http::h1::Http11Message;
use hyper::http::message::{HttpMessage, RequestHead};
use hyper::net::HttpStream;
use hyper::header::{Host, Headers, Server};
use hyper::method::Method;

use serde_json::Value;

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


fn print_table<'a, 'b, C, Q, T, E, F>(collection: C, header: Row, mut func: F)
    where C: IntoIterator<Item=(Q, &'a Result<T, E>)>, E: Error + 'a, T: 'a, Q: 'a + Display, 'a: 'b,
    F: FnMut(Q, &'b T) -> Vec<Row>
{
    let mut success_table = Table::new();
    success_table.set_titles(header);

    let mut failure_table = Table::new();
    failure_table.set_titles(row!["Query", "Error"]);

    for (query, result) in collection {
        match result {
            &Ok(ref items) => {
                for row in func(query, items) {
                    success_table.add_row(row);
                }
            }
            &Err(ref e) => {
                failure_table.add_row(Row::new(vec![
                    Cell::new(&format!("{}", query)).style_spec("Fr"),
                    Cell::new(&format!("{}", e))
                ]));
            }
        }
    }

    if success_table.len() > 0 {
        success_table.printstd();
        println!("");
    }

    if failure_table.len() > 0 {
        failure_table.printstd();
        println!("");
    }
}


#[derive(Debug, Clone, Copy)]
enum ResolveOutput { Simple, Full, Graph }


fn resolve(server_name: String, nameservers: &[ip::IpAddr], output: ResolveOutput) {
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

    let ip_ports = if !was_soa_response {
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
                    (priority.to_string(), weight.to_string(), port, ip)
                )
            )
            .sorted_by(|a, b| (&a.1, &a.2).cmp(&(&b.1, &b.2)))
    } else {
        srv_results_map = resolver::resolve(
            &nameservers[0],
            resolver::ResolveRequestType::Host, server_name.clone()
        );

        let ips = resolver::resolve_target_to_ips(&server_name, &srv_results_map);

        ips.into_iter().map(|ip| (String::new(), String::new(), 8448, ip)).collect_vec()
    };

    match output {
        ResolveOutput::Full => {
            let format = FormatBuilder::new()
                .padding(1, 1)
                .column_separator(' ')
                .borders(' ')
                .separators(
                    &[LinePosition::Top, LinePosition::Intern, LinePosition::Bottom],
                    LineSeparator::new(' ', ' ', ' ', ' ')
                )
                .separator(LinePosition::Title, LineSeparator::new('-', '-', '-', '-'))
                .build();

            let mut success_table = Table::new();
            success_table.set_titles(row!["Query", "Priority", "Weight", "Port", "Target"]);
            success_table.set_format(format);

            let mut failure_table = Table::new();
            failure_table.set_titles(row!["Query", "Error"]);
            failure_table.set_format(format);

            for (query, result) in &srv_results_map.srv_map {
                match result {
                    &Ok(ref srv_results) => {
                        for srv_result in srv_results {
                            success_table.add_row(Row::new(vec![
                                Cell::new(&query),
                                Cell::new(&srv_result.priority.to_string()),
                                Cell::new(&srv_result.weight.to_string()),
                                Cell::new(&srv_result.port.to_string()),
                                Cell::new(&srv_result.target),
                            ]));
                        }
                    }
                    &Err(ref e) => {
                        failure_table.add_row(Row::new(vec![
                            Cell::new(&format!("{}", query)).style_spec("Fr"),
                            Cell::new(&format!("{}", e))
                        ]));
                    }
                }
            }

            for (query, result) in &srv_results_map.host_map {
                match result {
                    &Ok(ref host_results) => {
                        for host_result in host_results {
                            success_table.add_row(match host_result {
                                &resolver::HostResult::CNAME(ref target) => {
                                    Row::new(vec![
                                        Cell::new(&query),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(&target),
                                    ])
                                }
                                &resolver::HostResult::IP(ref ip) => {
                                    Row::new(vec![
                                        Cell::new(&query),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(&format!("{}", ip)),
                                    ])
                                }
                            });
                        }
                    }
                    &Err(ref e) => {
                        failure_table.add_row(Row::new(vec![
                            Cell::new(&format!("{}", query)).style_spec("Fr"),
                            Cell::new(&format!("{}", e))
                        ]));
                    }
                }
            }

            if success_table.len() > 0 {
                success_table.printstd();
                println!("");
            }

            if failure_table.len() > 0 {
                failure_table.printstd();
                println!("");
            }
        }
        ResolveOutput::Simple => {
            if ip_ports.is_empty() {
                std::process::exit(1);
            }

            for (_, _, port, ip) in ip_ports {
                match ip {
                    ip::IpAddr::V4(ip4) => println!("{}:{}", ip4, port),
                    ip::IpAddr::V6(ip6) => println!("[{}]:{}", ip6, port),
                }
            }
        }
        ResolveOutput::Graph => {
            let mut nodes = BTreeMap::new();
            let mut edges = Vec::new();

            for (query, result) in &srv_results_map.srv_map {
                match result {
                    &Ok(ref srv_results) => {
                        let srv_label = format!("{} (SRV)", &query);
                        nodes.insert(query.clone(), srv_label);

                        for srv_result in srv_results {
                            let label = format!("{} {}", &srv_result.target, srv_result.port);

                            nodes.insert(srv_result.target.clone(), label);
                            edges.push((query.clone(), srv_result.target.clone()))
                        }
                    }
                    &Err(ref e) => {
                        let name = format!("{}-error", query);
                        nodes.insert(name.clone(), format!("{}", e));
                        edges.push((query.clone(), name))
                    }
                }
            }

            for (query, result) in &srv_results_map.host_map {
                match result {
                    &Ok(ref host_results) => {
                        for host_result in host_results {
                            let host = format!("{}", host_result);
                            nodes.insert(host.clone(), host.clone());
                            edges.push((query.clone(), host))
                        }
                    }
                    &Err(ref e) => {
                        let name = format!("{}-error", query);
                        nodes.insert(name.clone(), format!("{}", e));
                        edges.push((query.clone(), name))
                    }
                }
            }

            println!("digraph dns {{");

            for (name, label) in nodes {
                println!("\t\"{}\" [label=\"{}\"];", name, label);
            }

            for (start, end) in edges {
                println!("\t\"{}\" -> \"{}\";", start, end);
            }

            println!("}}");
        }
    }
}


fn report(server_name: String, nameservers: &[ip::IpAddr]) {
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

    let ip_ports : Vec<(ip::IpAddr, u16)> = if !was_soa_response {
        srv_results_map.srv_map
            .values()  // -> iter of Result<HashSet<SrvResult>, ResolveError>
            .flat_map(|result| result) // -> iter of HashSet<SrvResult>
            .flat_map(|srv_results_set| srv_results_set.iter())  // -> iter of SrvResult
            .map(|srv_result| (
                resolver::resolve_target_to_ips(&srv_result.target, &srv_results_map),
                srv_result.port,
            ))  // -> (Vec<IpAddr>, port)
            .flat_map(
                |(ips, port)| ips.into_iter().map(move |ip| (ip, port))
            )
            .collect()
    } else {
        srv_results_map = resolver::resolve(
            &nameservers[0],
            resolver::ResolveRequestType::Host, server_name.clone()
        );

        let ips = resolver::resolve_target_to_ips(&server_name, &srv_results_map);

        ips.into_iter().map(|ip| (ip, 8448)).collect()
    };

    println!("{}...", Style::new().bold().paint("SRV Records"));

    print_table(
        &srv_results_map.srv_map,
        row!["Query", "Priority", "Weight", "Port", "Target"],
        |query, srv_results| srv_results.iter().map(|srv_result| Row::new(vec![
            Cell::new(&query),
            Cell::new(&srv_result.priority.to_string()),
            Cell::new(&srv_result.weight.to_string()),
            Cell::new(&srv_result.port.to_string()),
            Cell::new(&srv_result.target),
        ])).collect_vec()
    );

    println!("{}...", Style::new().bold().paint("Hosts"));

    print_table(
        &srv_results_map.host_map,
        row!["Host", "Target"],
        |query, host_results| host_results.iter().map(|host_result| match host_result {
            &resolver::HostResult::CNAME(ref target) => {
                Row::new(vec![
                    Cell::new(&query),
                    Cell::new(&target),
                ])
            }
            &resolver::HostResult::IP(ref ip) => {
                Row::new(vec![
                    Cell::new(&query),
                    Cell::new(&format!("{}", ip)),
                ])
            }
        }).collect_vec()
    );


    if ip_ports.is_empty() {
        println!("Failed to resolve. Exiting.");
        return;
    }


    println!("Testing TLS connections...\n");

    let mut conn_table = Table::new();
    conn_table.set_titles(row![
        "IP", "Port", "Name", "Certificate", "Cipher Name", "Version", "Bits"
    ]);

    let mut err_table = Table::new();
    err_table.set_titles(row![
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

                let split_fingerprint = conn_info.cert_info.cert_sha256.chunks(8)
                    .map(|chunk| chunk.to_hex().to_uppercase())
                    .collect::<Vec<String>>()
                    .join("\n");

                // let val : Value = serde_json::from_slice(&server_response.body).unwrap();
                // let sn = val.find("server_name").and_then(|v| v.as_string()).unwrap_or("");

                // Should probably print if this is None
                // let server_name_matching = sn == server_name;

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


    if conn_table.len() > 0 {
        conn_table.printstd();
        println!("");
    }

    if err_table.len() > 0 {
        err_table.printstd();
        println!("");
    }

    if !certificates.is_empty() {
        let mut cert_table = Table::new();
        cert_table.set_titles(row![
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
                "Verify key ", &format!("{} {}", key, value)
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


fn main() {
    let matches = App::new("mxfedtest")
        .version(crate_version!())
        .author("Erik Johnston <mxfedtest@jki.re>")
        .about("Diagnostic tool for Matrix federation")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::GlobalVersion)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(Arg::with_name("nameserver")
            .short("n")
            .long("nameserver")
            .value_name("IP")
            .takes_value(true)
            .help("Sets the nameserver to use")
            .required(false)
        )
        .subcommand(SubCommand::with_name("report")
            .about("Generates a full report about a server")
            .arg_from_usage("<server_name>   'Server name to report on'")
        )
        .subcommand(SubCommand::with_name("resolve")
            .about("Resolves server name to IP/port")
            .arg_from_usage("<server_name>   'Server name to report on'")
            .arg(Arg::with_name("full")
                .short("f")
                .long("full")
                .help("Return each resolution step, including errors.")
                .required(false)
                .conflicts_with("graph")
            )
            .arg(Arg::with_name("graph")
                .short("g")
                .long("graph")
                .help("Output each resolution step in DOT format.")
                .required(false)
                .conflicts_with("full")
            )
        )
        .get_matches();

    let nameservers = if matches.is_present("nameserver") {
        values_t!(matches, "nameserver", ip::IpAddr).unwrap_or_else(|e| e.exit())
    } else {
        let mut buf = Vec::with_capacity(4096);
        let mut f = File::open("/etc/resolv.conf").unwrap();
        f.read_to_end(&mut buf).unwrap();
        let cfg = resolv_conf::Config::parse(&buf[..]).unwrap();
        cfg.nameservers
    };

    match matches.subcommand() {
        ("report", Some(submatches)) => {
            let server_name = submatches.value_of("server_name").unwrap().to_string();

            report(server_name, &nameservers);
        }
        ("resolve", Some(submatches)) => {
            let server_name = submatches.value_of("server_name").unwrap().to_string();
            let resolve_output = if submatches.is_present("full") {
                ResolveOutput::Full
            } else if submatches.is_present("graph") {
                ResolveOutput::Graph
            } else {
                ResolveOutput::Simple
            };

            resolve(server_name, &nameservers, resolve_output);
        }
        _ => {}
    }
}
