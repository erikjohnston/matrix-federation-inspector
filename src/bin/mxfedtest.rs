#![feature(proc_macro, custom_derive)]

#[macro_use] extern crate clap;
extern crate chrono;
extern crate mxfedtest;
extern crate resolv_conf;
#[macro_use] extern crate prettytable;
extern crate serde_json;
extern crate itertools;
extern crate rustc_serialize;

use mxfedtest::{
    resolver, resolve_matrix_server, get_ssl_info, KeyApiResponse,
};

use chrono::naive::datetime::NaiveDateTime;

use std::fs::File;
use std::borrow::Cow;
use std::collections::{HashSet, BTreeMap};
use std::fmt::Display;
use std::io::{Read, Write, stderr};
use std::net::IpAddr;
use std::error::Error;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;
use prettytable::format::{FormatBuilder, LinePosition, LineSeparator};
use prettytable::format::consts::FORMAT_CLEAN;

use clap::{App, AppSettings, Arg, SubCommand};

use itertools::Itertools;

use rustc_serialize::hex::ToHex;
use rustc_serialize::base64::FromBase64;


fn bool_to_spec(b: bool) -> &'static str {
    if b {
        "Fgb"
    } else {
        "Frb"
    }
}


fn print_table<'a, 'b, C, Q, T, E, F>(collection: C, header: Row, mut func: F)
    where C: IntoIterator<Item=(Q, &'a Result<T, E>)>,
          E: Error + 'a,
          T: 'a,
          Q: 'a + Display,
          F: FnMut(Q, &'b T) -> Vec<Row>,
          'a: 'b,
{
    let mut success_table = Table::new();
    success_table.set_titles(header);

    let mut failure_table = Table::new();
    failure_table.set_titles(row!["Query", "Error"]);

    for (query, result) in collection {
        match *result {
            Ok(ref items) => {
                for row in func(query, items) {
                    success_table.add_row(row);
                }
            }
            Err(ref e) => {
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

fn resolve_command(server_name: String, nameservers: &[IpAddr], output: ResolveOutput) {
    let (srv_results_map, ip_ports) = resolve_matrix_server(server_name, nameservers);

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
                match *result {
                    Ok(ref srv_results) => {
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
                    Err(ref e) => {
                        failure_table.add_row(Row::new(vec![
                            Cell::new(&query).style_spec("Fr"),
                            Cell::new(&format!("{}", e))
                        ]));
                    }
                }
            }

            for (query, result) in &srv_results_map.host_map {
                match *result {
                    Ok(ref host_results) => {
                        for host_result in host_results {
                            success_table.add_row(match *host_result {
                                resolver::HostResult::CNAME(ref target) => {
                                    Row::new(vec![
                                        Cell::new(&query),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(""),
                                        Cell::new(&target),
                                    ])
                                }
                                resolver::HostResult::IP(ref ip) => {
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
                    Err(ref e) => {
                        failure_table.add_row(Row::new(vec![
                            Cell::new(&query).style_spec("Fr"),
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
                failure_table.printstd();;
                println!("");
            }
        }
        ResolveOutput::Simple => {
            if ip_ports.is_empty() {
                writeln!(stderr(), "Failed to resolve host.").unwrap();
                std::process::exit(1);
            }

            for (_, _, port, ip) in ip_ports {
                match ip {
                    IpAddr::V4(ip4) => println!("{}:{}", ip4, port),
                    IpAddr::V6(ip6) => println!("[{}]:{}", ip6, port),
                }
            }
        }
        ResolveOutput::Graph => {
            let mut nodes = BTreeMap::new();
            let mut edges = Vec::new();

            for (query, result) in &srv_results_map.srv_map {
                match *result {
                    Ok(ref srv_results) => {
                        let srv_label = format!("{} (SRV)", &query);
                        nodes.insert(query.clone(), srv_label);

                        for srv_result in srv_results {
                            let label = format!("{} {}", &srv_result.target, srv_result.port);

                            nodes.insert(srv_result.target.clone(), label);
                            edges.push((query.clone(), srv_result.target.clone()))
                        }
                    }
                    Err(ref e) => {
                        let name = format!("{}-error", query);
                        nodes.insert(name.clone(), format!("{}", e));
                        edges.push((query.clone(), name))
                    }
                }
            }

            for (query, result) in &srv_results_map.host_map {
                match *result {
                    Ok(ref host_results) => {
                        for host_result in host_results {
                            let host = format!("{}", host_result);
                            nodes.insert(host.clone(), host.clone());
                            edges.push((query.clone(), host))
                        }
                    }
                    Err(ref e) => {
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


fn report_command(server_name: String, nameservers: &[IpAddr], sni: bool) {
    let (srv_results_map, ip_ports) = resolve_matrix_server(server_name.clone(), nameservers);

    println!("SRV Records...");

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

    println!("Hosts...");

    print_table(
        &srv_results_map.host_map,
        row!["Host", "Target"],
        |query, host_results| host_results.iter().map(|host_result| match *host_result {
            resolver::HostResult::CNAME(ref target) => {
                Row::new(vec![
                    Cell::new(&query),
                    Cell::new(&target),
                ])
            }
            resolver::HostResult::IP(ref ip) => {
                Row::new(vec![
                    Cell::new(&query),
                    Cell::new(&format!("{}", ip)),
                ])
            }
        }).collect_vec()
    );


    if ip_ports.is_empty() {
        writeln!(stderr(), "Failed to resolve host.").unwrap();
        std::process::exit(1);
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

    for (_, _, port, ip) in ip_ports {
        match get_ssl_info(
            &server_name,
            ip,
            port,
            sni,
        ) {
            Ok((conn_info, server_response)) => {
                certificates.insert(conn_info.cert_info.clone());

                let split_fingerprint = conn_info.cert_info.cert_sha256.chunks(8)
                    .map(|chunk| chunk.to_hex().to_uppercase())
                    .collect::<Vec<String>>()
                    .join("\n");

                conn_table.add_row(Row::new(vec![
                    Cell::new(&conn_info.ip.to_string()).style_spec("Fgb"),
                    Cell::new(&conn_info.port.to_string()),
                    Cell::new(&conn_info.server_name),
                    Cell::new(&split_fingerprint),
                    Cell::new(conn_info.cipher_name),
                    Cell::new(conn_info.cipher_version),
                    Cell::new(&conn_info.cipher_bits.to_string()),
                ]));

                server_responses.push(((ip, port), (server_response, conn_info.cert_info)));
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
            "Fingerprint SHA256", "CN", "Alt Names"
        ]);

        for cert in certificates {
            let split_fingerprint = cert.cert_sha256.chunks(8)
                .map(|chunk| chunk.to_hex().to_uppercase())
                .collect::<Vec<String>>()
                .join("\n");

            cert_table.add_row(Row::new(vec![
                Cell::new(&split_fingerprint),
                Cell::new(&cert.common_name),
                Cell::new(&cert.alt_names.join("\n"))
            ]));
        }

        cert_table.printstd();
        println!("");
    }


    for ((ip, port), (server_response, conn_info)) in server_responses {
        let mut server_table = Table::new();

        server_table.add_row(row![
            "IP/Port", &match ip {
                IpAddr::V4(ref ipv4) => format!("{}:{}", ipv4, port),
                IpAddr::V6(ref ipv6) => format!("[{}]:{}", ipv6, port),
            }
        ]);

        let val : KeyApiResponse = match serde_json::from_slice(&server_response.body) {
            Ok(v) => v,
            Err(e) => {
                server_table.add_row(Row::new(vec![
                    Cell::new("Invalid response "),
                    Cell::new(&format!("{}", e)).style_spec("Frb")
                ]));

                server_table.set_format(*FORMAT_CLEAN);
                server_table.printstd();
                println!("");

                continue;
            },
        };

        server_table.add_row(Row::new(vec![
            Cell::new("Server Name "),
            Cell::new(&val.server_name).style_spec(bool_to_spec(val.server_name == server_name))
        ]));

        let vu = val.valid_until_ts;
        let date = NaiveDateTime::from_timestamp(
            (vu / 1000) as i64, ((vu % 1000) * 1000000) as u32
        );
        server_table.add_row(row![
            "Valid until ", &format!("{}", date)
        ]);

        let ver = server_response.server_header.unwrap_or_default();
        server_table.add_row(row![
            "Server Header ", &ver
        ]);

        for (key_id, key) in val.verify_keys {
            server_table.add_row(row![
                "Verify key ", &format!("{} {}", key_id, key.key)
            ]);
        }

        for fingerprint in val.tls_fingerprints {
            let allowed_fingerprint = fingerprint.sha256.from_base64().unwrap();
            server_table.add_row(Row::new(vec![
                Cell::new("TLS fingerprint "),
                Cell::new(
                        &allowed_fingerprint.to_hex().to_uppercase()
                ).style_spec(bool_to_spec(conn_info.cert_sha256 == allowed_fingerprint))
            ]));
        }

        server_table.set_format(*FORMAT_CLEAN);
        server_table.printstd();
        println!("");
    }
}



enum WhatToFetch { Certs, Keys }

#[derive(Clone, Copy)]
enum FetchFormat { Base64, Hex }

fn fetch_command(
    server_name: String, nameservers: &[IpAddr], what_to_fetch: WhatToFetch,
    format: FetchFormat, sni: bool,
) {
    let (_, ip_ports) = resolve_matrix_server(server_name.clone(), nameservers);

    if ip_ports.is_empty() {
        writeln!(stderr(), "Failed to resolve host.").unwrap();
        std::process::exit(1);
    }

    for (_, _, port, ip) in ip_ports {
        match get_ssl_info(
            &server_name,
            ip,
            port,
            sni,
        ) {
            Ok((_, server_response)) => {
                let val : KeyApiResponse = match serde_json::from_slice(&server_response.body) {
                    Ok(v) => v,
                    Err(e) => {
                        writeln!(stderr(), "Invalid server response from {} {}, {}", ip, port, e).unwrap();
                        continue;
                    },
                };

                match what_to_fetch {
                    WhatToFetch::Certs => {
                        for fingerprint in val.tls_fingerprints {
                            println!("sha256 {}", format_value(&fingerprint.sha256, format));
                        }
                    }
                    WhatToFetch::Keys => {
                        for (key_id, key) in val.verify_keys {
                            println!("{} {}", key_id, format_value(&key.key, format));
                        }
                    }
                }

                return;
            }
            Err(e) => {
                writeln!(stderr(), "Failed to connect to {} {}, {}", ip, port, e).unwrap();
            }
        }
    }

    writeln!(stderr(), "Failed to connect to any host").unwrap();

    std::process::exit(1);
}

fn format_value(value: & str, format: FetchFormat) -> Cow<str> {
    match format {
        FetchFormat::Base64 => value.into(),
        FetchFormat::Hex => {
            value.from_base64().unwrap()
            .chunks(1)
            .map(|chunk| chunk.to_hex().to_uppercase())
            .collect_vec()
            .join(" ")
            .into()
        },
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
            .arg_from_usage("--sni 'Use SNI when connecting'")
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
        .subcommand(SubCommand::with_name("fetch")
            .about("Fetches information about a server")
            .setting(AppSettings::ArgRequiredElseHelp)
            .setting(AppSettings::GlobalVersion)
            .setting(AppSettings::VersionlessSubcommands)
            .setting(AppSettings::SubcommandRequiredElseHelp)
            .arg_from_usage("<server_name>   'Server name to report on'")
            .arg_from_usage("--sni 'Use SNI when connecting'")
            .arg(Arg::with_name("format")
                .short("f")
                .long("format")
                .takes_value(true)
                .possible_values(&["base64", "hex"])
                .help("Format of output.")
                .default_value("base64")
                .required(false)
            )
            .subcommand(SubCommand::with_name("certs")
                .about("Fetch tls certificates advertised by server")
            )
            .subcommand(SubCommand::with_name("keys")
                .about("Fetch signing keys advertised by server")
            )
        )
        .get_matches();

    let nameservers = if matches.is_present("nameserver") {
        values_t!(matches, "nameserver", IpAddr).unwrap_or_else(|e| e.exit())
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
            let sni = submatches.is_present("sni");

            report_command(server_name, &nameservers, sni);
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

            resolve_command(server_name, &nameservers, resolve_output);
        }
        ("fetch", Some(submatches)) => {
            let server_name = submatches.value_of("server_name").unwrap().to_string();
            let sni = submatches.is_present("sni");

            let format = match submatches.value_of("format").unwrap() {
                "base64" => FetchFormat::Base64,
                "hex" => FetchFormat::Hex,
                _ => panic!("Unrecognized format"),
            };

            match submatches.subcommand() {
                ("certs", Some(_)) => {
                    fetch_command(server_name, &nameservers, WhatToFetch::Certs, format, sni);
                }
                ("keys", Some(_)) => {
                    fetch_command(server_name, &nameservers, WhatToFetch::Keys, format, sni);
                }
                _ => panic!("Unrecognized subcommand.")
            }
        }
        _ => panic!("Unrecognized subcommand.")
    }
}
