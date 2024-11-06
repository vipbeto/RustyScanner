use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use ipnetwork::IpNetwork;
use structopt::StructOpt;
use futures::stream::{self, StreamExt};
use tokio::time::timeout;

#[derive(StructOpt)]
struct Cli {
    /// CIDR range to scan (e.g., "104.16.51.0/23")
    #[structopt(help = "CIDR range to scan")]
    cidr: String,

    /// Number of concurrent scans
    #[structopt(short, long, default_value = "100")]
    concurrent: usize,

    /// Timeout in milliseconds for each connection attempt
    #[structopt(short, long, default_value = "1000")]
    timeout_ms: u64,

    /// Port to scan
    #[structopt(short, long, default_value = "80")]
    port: u16,
}

#[tokio::main]
async fn main() {
    let args = Cli::from_args();
    
    // Parse CIDR
    let network = match IpNetwork::from_str(&args.cidr) {
        Ok(net) => net,
        Err(e) => {
            eprintln!("Error parsing CIDR: {}", e);
            return;
        }
    };

    println!("Iniciando scan em {} na porta {}", args.cidr, args.port);
    // Corrigido: usando len() para contar o número de IPs
    let ips: Vec<IpAddr> = network.iter().collect();
    println!("Hosts totais a serem verificados: {}", ips.len());

    let results = stream::iter(ips)
        .map(|ip| {
            let port = args.port;
            let timeout_duration = Duration::from_millis(args.timeout_ms);
            
            async move {
                let addr = format!("{}:{}", ip, port);
                match timeout(timeout_duration, TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => {
                        println!("[+] Host ativo: {}", ip);
                        Some(ip)
                    }
                    _ => None
                }
            }
        })
        // Corrigido: usando buffer_unordered em vez de buffer_unwind
        .buffer_unordered(args.concurrent)
        .collect::<Vec<Option<IpAddr>>>()
        .await;

    let active_hosts: Vec<IpAddr> = results.into_iter().filter_map(|x| x).collect();
    
    println!("\nResultados do scan:");
    println!("Total de hosts ativos: {}", active_hosts.len());
    println!("Hosts ativos:");
    for host in active_hosts {
        println!("{}", host);
    }
}
