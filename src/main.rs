extern crate ansi_term;
extern crate dns_parser;
extern crate ip;
extern crate rand;
extern crate resolv_conf;
#[macro_use] extern crate quick_error;
#[macro_use] extern crate prettytable;

mod resolver;

use prettytable::Table;
use prettytable::row::Row;
use prettytable::cell::Cell;

use std::io::{Read};
use std::fs::File;
use ansi_term::Colour::{Red, Green};


fn main() {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").unwrap();
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf[..]).unwrap();

    let server_name = "jki.re".to_string();

    let srv_results = match resolver::resolve_matrix_srv(&server_name, &cfg.nameservers[0]) {
        Ok(res) => res,
        Err(resolver::ResolveError::DnsError(e)) => {
            println!(
                "{}: DNS Error: {}",
                Red.bold().paint("FAILURE"), e
            );
            return;
        }
        Err(resolver::ResolveError::SrvDnsFailure(e)) => {
            println!(
                "{}: DNS Error: {:?}",
                Red.bold().paint("FAILURE"), e
            );
            return;
        }
        Err(resolver::ResolveError::HostResolveFailure(hosts)) => {
            for host in hosts {
                println!(
                    "{}: Failed to resolve: {}",
                    Red.bold().paint("FAILURE"), host
                );
            }
            return;
        }
    };

    let mut table = Table::new();

    table.add_row(row![
        "priority", "weight", "target", "port", "ip"
    ]);

    for srv_result in &srv_results {
        for ip in &srv_result.ips {
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
