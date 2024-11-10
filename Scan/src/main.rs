use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use ipnetwork::IpNetwork;
use structopt::StructOpt;
use futures::stream::{self, StreamExt};
use tokio::time::timeout;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use chrono::Local;

#[derive(StructOpt)]
struct Cli {
    /// File containing CIDR ranges (one per line)
    #[structopt(short, long, help = "File containing CIDR ranges")]
    file: Option<PathBuf>,

    /// Single CIDR range to scan (e.g., "104.16.51.0/23")
    #[structopt(help = "CIDR range to scan", required_unless = "file")]
    cidr: Option<String>,

    /// Output file for results
    #[structopt(short, long, help = "Output file for results")]
    output: Option<PathBuf>,

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

fn read_cidrs(path: &PathBuf) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut cidrs = Vec::new();
    
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            cidrs.push(trimmed.to_string());
        }
    }
    
    Ok(cidrs)
}

fn write_results(path: &PathBuf, results: &[IpAddr], scan_info: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    
    writeln!(file, "Resultado do Scan - {}", timestamp)?;
    writeln!(file, "Informações do Scan: {}", scan_info)?;
    writeln!(file, "Total de hosts ativos: {}\n", results.len())?;
    writeln!(file, "Hosts ativos:")?;
    
    for host in results {
        writeln!(file, "{}", host)?;
    }
    
    Ok(())
}

async fn scan_network(
    network: IpNetwork,
    port: u16,
    concurrent: usize,
    timeout_ms: u64
) -> Vec<IpAddr> {
    let ips: Vec<IpAddr> = network.iter().collect();
    println!("Verificando {} hosts em {}", ips.len(), network);

    let results = stream::iter(ips)
        .map(|ip| {
            let timeout_duration = Duration::from_millis(timeout_ms);
            
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
        .buffer_unordered(concurrent)
        .collect::<Vec<Option<IpAddr>>>()
        .await;

    results.into_iter().filter_map(|x| x).collect()
}

#[tokio::main]
async fn main() {
    let args = Cli::from_args();
    
    let cidrs = if let Some(file_path) = args.file.as_ref() {
        match read_cidrs(file_path) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Erro ao ler arquivo de CIDRs: {}", e);
                return;
            }
        }
    } else if let Some(cidr) = args.cidr.as_ref() {
        vec![cidr.clone()]
    } else {
        eprintln!("É necessário fornecer um CIDR ou um arquivo com lista de CIDRs");
        return;
    };

    println!("Iniciando scan de {} ranges CIDR na porta {}", cidrs.len(), args.port);
    
    let mut all_active_hosts = Vec::new();
    
    for cidr_str in cidrs.iter() {
        match IpNetwork::from_str(cidr_str) {
            Ok(network) => {
                let active_hosts = scan_network(
                    network,
                    args.port,
                    args.concurrent,
                    args.timeout_ms
                ).await;
                all_active_hosts.extend(active_hosts);
            }
            Err(e) => {
                eprintln!("Erro ao processar CIDR {}: {}", cidr_str, e);
                continue;
            }
        }
    }

    // Preparar informações do scan para o relatório
    let scan_info = format!(
        "Porta: {}, CIDRs escaneados: {}, Timeout: {}ms, Conexões concorrentes: {}", 
        args.port, 
        cidrs.join(", "), 
        args.timeout_ms,
        args.concurrent
    );
    
    // Exibir resultados no console
    println!("\nResultados finais do scan:");
    println!("Total de hosts ativos: {}", all_active_hosts.len());
    println!("Hosts ativos:");
    for host in &all_active_hosts {
        println!("{}", host);
    }

    // Salvar resultados em arquivo se especificado
    if let Some(output_path) = args.output {
        match write_results(&output_path, &all_active_hosts, &scan_info) {
            Ok(_) => println!("\nResultados salvos em: {}", output_path.display()),
            Err(e) => eprintln!("Erro ao salvar resultados: {}", e)
        }
    }
}