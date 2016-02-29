extern crate ansi_term;
extern crate dns_parser;
extern crate ip;
extern crate itertools;
extern crate openssl;
extern crate rand;
extern crate resolv_conf;
extern crate rustc_serialize;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate prettytable;

mod resolver;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;

use std::io::{Read};
use std::fs::File;
use std::net::TcpStream;
use ansi_term::Style;
use ansi_term::Colour::{Red, Green};
use openssl::ssl::{SslContext, SslStream, SslMethod, Ssl};
use openssl::ssl::error::SslError;
use openssl::crypto::hash::Type as HashType;
use rustc_serialize::hex::ToHex;
use std::error::Error;
// use std::slice::SliceConcatExt;


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


#[derive(Debug, Clone)]
struct ConnectionInfo {
    ip: ip::IpAddr,
    port: u16,
    cert_sha256: Vec<u8>,
    cipher_name: &'static str,
    cipher_version: &'static str,
    cipher_bits: i32,
}

fn get_ssl_info(server_name: &String, ipaddr: ip::IpAddr, port: u16) -> Result<ConnectionInfo, SslStreamError> {
    let stream = try!(match ipaddr {
        ip::IpAddr::V4(ip) => TcpStream::connect((ip, port)),
        ip::IpAddr::V6(ip) => TcpStream::connect((ip, port)),
    });

    let ssl_context = try!(SslContext::new(SslMethod::Sslv23));
    let ssl = try!(Ssl::new(&ssl_context));
    try!(ssl.set_hostname(server_name));
    let ssl_stream = try!(SslStream::connect(ssl, stream));

    let peer_cert = ssl_stream.ssl().peer_certificate().unwrap();
    let cipher = ssl_stream.ssl().get_current_cipher().unwrap();

    Ok(ConnectionInfo{
        ip: ipaddr,
        port: port,
        cert_sha256: peer_cert.fingerprint(HashType::SHA256).unwrap(),
        cipher_name: cipher.name(),
        cipher_version: ssl_stream.ssl().version(),
        cipher_bits: cipher.bits().0,
    })
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

    println!("\nTesting configuration of {}.\n\n----\n", server_name);
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

    println!(
        "{}: Resolved domain.\n\n----\n",
        Green.bold().paint("SUCCESS"),
    );


    let srv_results : Vec<resolver::ResolvedSrvResult> = srv_results_map.srv_map
        .values()
        .flat_map(|v| v)
        .flat_map(|v| v.iter())
        .map(|v| v.resolve_from_maps(&srv_results_map))
        .collect();

    println!("Testing TLS connections...");

    let mut ip_ports = vec![]; // Vec<(ip::IpAddr, u16)>

    for srv_result in &srv_results {
        for ip in &srv_result.ips {
            ip_ports.push((ip, srv_result.port));
        }
    }

    let mut conn_table = Table::new();
    conn_table.add_row(row![
        "IP", "Port", "Certificate", "Cipher Name", "Version", "Bits"
    ]);

    let mut err_table = Table::new();
    err_table.add_row(row![
        "IP", "Port", "Error"
    ]);

    for (ip, port) in ip_ports {
        match get_ssl_info(
            &server_name,
            *ip,
            port,
        ) {
            Ok(conn_info) => {
                let split_fingerprint = {
                    let s = conn_info.cert_sha256.chunks(8)
                        .map(|chunk| chunk.to_hex().to_uppercase())
                        .collect::<Vec<String>>()
                        .join("\n");
                    s
                };

                conn_table.add_row(Row::new(vec![
                    Cell::new(&conn_info.ip.to_string()).style_spec("Fgb"),
                    Cell::new(&conn_info.port.to_string()),
                    Cell::new(&split_fingerprint),
                    Cell::new(conn_info.cipher_name),
                    Cell::new(conn_info.cipher_version),
                    Cell::new(&conn_info.cipher_bits.to_string()),
                ]));
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

    println!(
        "{}: Connected to all associated IPs.\n\n----\n",
        Green.bold().paint("SUCCESS"),
    );
}
