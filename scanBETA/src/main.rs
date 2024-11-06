use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use ipnetwork::IpNetwork;
use structopt::StructOpt;
use futures::stream::{self, StreamExt};
use tokio::time::timeout;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(StructOpt)]
struct Cli {
    /// Arquivo contendo lista de CIDRs (um por linha)
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    file: PathBuf,

    /// Number of concurrent scans
    #[structopt(short, long, default_value = "1000")]
    concurrent: usize,

    /// Timeout in milliseconds for each connection attempt
    #[structopt(short, long, default_value = "1000")]
    timeout_ms: u64,

    /// Port to scan
    #[structopt(short, long, default_value = "80")]
    port: u16,
}

fn read_cidrs(file_path: &PathBuf) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let mut networks = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            networks.push(trimmed.to_string());
        }
    }

    Ok(networks)
}

async fn scan_ip(ip: IpAddr, port: u16, timeout_ms: u64) -> Option<IpAddr> {
    let addr = format!("{}:{}", ip, port);
    let timeout_duration = Duration::from_millis(timeout_ms);
    
    match timeout(timeout_duration, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            println!("[+] Host ativo: {}", ip);
            Some(ip)
        }
        _ => None
    }
}

async fn scan_network(cidr_str: &str, port: u16, concurrent: usize, timeout_ms: u64) -> io::Result<Vec<IpAddr>> {
    let network = match IpNetwork::from_str(cidr_str) {
        Ok(net) => net,
        Err(e) => {
            eprintln!("Erro ao processar CIDR {}: {}", cidr_str, e);
            return Ok(Vec::new());
        }
    };

    println!("\nIniciando scan de {} na porta {}", cidr_str, port);
    println!("Range de IPs: {} - {}", network.network(), network.broadcast());
    
    let mut active_hosts = Vec::new();
    let mut batch = Vec::new();
    let mut total_processed = 0;
    
    for ip in network.iter() {
        batch.push(ip);
        
        if batch.len() >= concurrent {
            let results = stream::iter(batch.drain(..))
                .map(|ip| scan_ip(ip, port, timeout_ms))
                .buffer_unordered(concurrent)
                .collect::<Vec<Option<IpAddr>>>()
                .await;
            
            active_hosts.extend(results.into_iter().filter_map(|x| x));
            total_processed += concurrent;
            
            if total_processed % (concurrent * 10) == 0 {
                println!("Progresso: aproximadamente {} IPs verificados em {}", total_processed, cidr_str);
            }
        }
    }
    
    // Processar IPs restantes
    if !batch.is_empty() {
        let results = stream::iter(batch.drain(..))
            .map(|ip| scan_ip(ip, port, timeout_ms))
            .buffer_unordered(concurrent)
            .collect::<Vec<Option<IpAddr>>>()
            .await;
        
        active_hosts.extend(results.into_iter().filter_map(|x| x));
    }

    println!("Finalizado scan de {} - {} hosts ativos encontrados", cidr_str, active_hosts.len());
    Ok(active_hosts)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Cli::from_args();
    
    let cidrs = read_cidrs(&args.file)?;
    println!("Carregados {} CIDRs do arquivo", cidrs.len());
    
    let mut all_active_hosts = Vec::new();
    
    for cidr in &cidrs {
        match scan_network(
            cidr,
            args.port,
            args.concurrent,
            args.timeout_ms
        ).await {
            Ok(hosts) => {
                println!("CIDR {} finalizado - {} hosts ativos", cidr, hosts.len());
                all_active_hosts.extend(hosts);
            },
            Err(e) => eprintln!("Erro ao escanear {}: {}", cidr, e),
        }
    }

    // Relatório final
    println!("\n=== Relatório Final ===");
    println!("CIDRs escaneados: {}", cidrs.len());
    println!("Total de hosts ativos encontrados: {}", all_active_hosts.len());
    println!("\nHosts ativos:");
    for host in all_active_hosts {
        println!("{}", host);
    }

    Ok(())
}
