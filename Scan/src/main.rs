use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use ipnetwork::IpNetwork;
use structopt::StructOpt;
use futures::stream::{self, StreamExt};
use tokio::time::timeout;
use std::fs::{self, File, create_dir_all};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};

const PROVIDERS_URL: &str = "https://adfastltda.com.br/scan/providerv4.json";

#[derive(StructOpt)]
struct Cli {
    /// File containing CIDR ranges (one per line)
    #[structopt(short, long, help = "File containing CIDR ranges")]
    file: Option<PathBuf>,

    /// Single CIDR range to scan (e.g., "104.16.51.0/23")
    #[structopt(help = "CIDR range to scan", conflicts_with = "file", conflicts_with = "only")]
    cidr: Option<String>,

    /// Scan CIDRs from specific provider
    #[structopt(long, help = "Scan CIDRs from specific provider")]
    only: Option<String>,

    /// List available providers
    #[structopt(long, help = "List all available providers")]
    only_list: bool,

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

    /// Verbose output
    #[structopt(short, long)]
    verbose: bool,
}

#[derive(Debug)]
struct ScanResult {
    ip: IpAddr,
    latency: Duration,
}

#[derive(Debug)]
struct Provider {
    name: String,
    cidrs: Vec<String>,
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

fn write_results(path: &PathBuf, results: &[ScanResult], scan_info: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    
    writeln!(file, "Resultado do Scan - {}", timestamp)?;
    writeln!(file, "Informações do Scan: {}", scan_info)?;
    writeln!(file, "Total de hosts ativos: {}\n", results.len())?;
    writeln!(file, "Hosts ativos:")?;
    
    for result in results {
        writeln!(file, "{} (latência: {:?})", result.ip, result.latency)?;
    }
    
    Ok(())
}

async fn download_providers_file() -> Result<String, Box<dyn std::error::Error>> {
    let prefix = std::env::var("PREFIX").unwrap_or_else(|_| String::from("/data/data/com.termux/files/usr"));
    let config_dir = format!("{}/etc/.scanconfig", prefix);
    create_dir_all(&config_dir)?;
    
    let providers_path = format!("{}/providers.json", config_dir);
    
    // Download file
    let response = reqwest::get(PROVIDERS_URL).await?.text().await?;
    
    // Save to file
    fs::write(&providers_path, &response)?;
    
    Ok(providers_path)
}

fn parse_providers(content: &str) -> Vec<Provider> {
    let mut providers = Vec::new();
    let mut current_provider: Option<String> = None;
    let mut current_cidrs = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("Provider: ") {
            // Save previous provider if exists
            if let Some(name) = current_provider.take() {
                providers.push(Provider {
                    name,
                    cidrs: current_cidrs.clone(),
                });
                current_cidrs.clear();
            }
            
            // Start new provider
            current_provider = Some(line.trim_start_matches("Provider: ").to_string());
        } else if !line.is_empty() && current_provider.is_some() {
            // Add CIDR to current provider
            current_cidrs.push(line.to_string());
        }
    }

    // Add last provider
    if let Some(name) = current_provider {
        providers.push(Provider {
            name,
            cidrs: current_cidrs,
        });
    }

    providers
}

async fn get_provider_cidrs(provider_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let providers_path = download_providers_file().await?;
    let content = fs::read_to_string(providers_path)?;
    
    let providers = parse_providers(&content);
    
    if let Some(provider) = providers.into_iter().find(|p| p.name.to_lowercase() == provider_name.to_lowercase()) {
        Ok(provider.cidrs)
    } else {
        Err("Provider not found".into())
    }
}

async fn list_providers() -> Result<(), Box<dyn std::error::Error>> {
    let providers_path = download_providers_file().await?;
    let content = fs::read_to_string(providers_path)?;
    let providers = parse_providers(&content);
    
    println!("\nProvedores disponíveis:");
    println!("=====================");
    
    for provider in providers {
        println!("\nProvider: {}", provider.name);
        println!("CIDRs disponíveis: {}", provider.cidrs.len());
        println!("Ranges:");
        for cidr in provider.cidrs {
            println!("  - {}", cidr);
        }
    }
    
    Ok(())
}

async fn scan_network(
    network: IpNetwork,
    port: u16,
    concurrent: usize,
    timeout_ms: u64,
    verbose: bool,
) -> Vec<ScanResult> {
    let ips: Vec<IpAddr> = network.iter().collect();
    let total_ips = ips.len();
    
    let pb = ProgressBar::new(total_ips as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let results = stream::iter(ips)
        .map(|ip| {
            let pb = pb.clone();
            let timeout_duration = Duration::from_millis(timeout_ms);
            
            async move {
                let addr = format!("{}:{}", ip, port);
                let start = tokio::time::Instant::now();
                
                let result = match timeout(timeout_duration, TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => {
                        let latency = start.elapsed();
                        if verbose {
                            println!("[+] Host ativo: {} (latência: {:?})", ip, latency);
                        }
                        Some(ScanResult { ip, latency })
                    }
                    _ => None
                };
                
                pb.inc(1);
                result
            }
        })
        .buffer_unordered(concurrent)
        .collect::<Vec<Option<ScanResult>>>()
        .await;

    pb.finish_with_message("Scan completo");
    results.into_iter().filter_map(|x| x).collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::from_args();
    
    // Verifica se o usuário quer listar os providers
    if args.only_list {
        return list_providers().await;
    }
    
    let cidrs = if let Some(provider) = args.only {
        match get_provider_cidrs(&provider).await {
            Ok(cidrs) => cidrs,
            Err(e) => {
                eprintln!("Erro ao obter CIDRs do provider {}: {}", provider, e);
                eprintln!("Use --only-list para ver os providers disponíveis");
                return Ok(());
            }
        }
    } else if let Some(file_path) = args.file.as_ref() {
        match read_cidrs(file_path) {
            Ok(list) => list,
            Err(e) => {
                eprintln!("Erro ao ler arquivo de CIDRs: {}", e);
                return Ok(());
            }
        }
    } else if let Some(cidr) = args.cidr.as_ref() {
        vec![cidr.clone()]
    } else {
        eprintln!("É necessário fornecer um CIDR, um arquivo com lista de CIDRs, ou um provider (-only)");
        eprintln!("Use --only-list para ver os providers disponíveis");
        return Ok(());
    };

    let scan_info = format!(
        "Scan para a porta {} com timeout de {} ms, {} conexões simultâneas",
        args.port, args.timeout_ms, args.concurrent
    );

    let mut all_results = Vec::new();
    
    for cidr in cidrs {
        let network = IpNetwork::from_str(&cidr)?;
        let results = scan_network(network, args.port, args.concurrent, args.timeout_ms, args.verbose).await;
        all_results.extend(results);
    }

    if let Some(output_path) = args.output {
        write_results(&output_path, &all_results, &scan_info)?;
    }

    Ok(())
}
