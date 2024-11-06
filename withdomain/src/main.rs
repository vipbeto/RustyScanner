use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::sync::{Arc, Mutex};
use std::thread;
use colored::*;
use clearscreen;
use ipnetwork::IpNetwork;

#[derive(Debug)]
struct ScanResult {
    ip: String,
    status: u16,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    clearscreen::clear()?;
    
    println!("{}\n", "ATENÇÃO FERRAMENTA APENAS PARA HACKERS ☠".yellow().bold());
    println!("{}\n", "Essa ferramenta irá fazer solicitações para um domínio específico...".dimmed());

    loop {
        println!("{}", "Coloque o IP/Proxy que deseja utilizar (exemplo: 10.10.0.0/24)".white().bold());
        print!("IP/Proxy: ");
        io::stdout().flush()?;
        let mut ip = String::new();
        io::stdin().read_line(&mut ip)?;
        let ip = ip.trim().to_string();

        println!("{}", "Coloque a PORTA que deseja utilizar".white().bold());
        print!("PORTA: ");
        io::stdout().flush()?;
        let mut porta = String::new();
        io::stdin().read_line(&mut porta)?;
        let porta = porta.trim().to_string();

        println!("{}", "Coloque o seu DOMÍNIO".white().bold());
        print!("Domínio: ");
        io::stdout().flush()?;
        let mut dominio = String::new();
        io::stdin().read_line(&mut dominio)?;
        let dominio = dominio.trim().to_string();

        println!("{}", "Coloque o número de threads".white().bold());
        print!("Threads: ");
        io::stdout().flush()?;
        let mut threads_input = String::new();
        io::stdin().read_line(&mut threads_input)?;
        let num_threads: usize = threads_input.trim().parse().unwrap_or(4);

        // Verifica se o IP está no formato CIDR
        match ip.parse::<IpNetwork>() {
            Ok(network) => {
                let results = scan_with_cidr(network, &porta, &dominio, num_threads)?;
                save_results(&results)?;
                display_results(&results);
                break;
            }
            Err(_) => {
                println!("{}\n", "Formato de IP inválido. Use CIDR, como 10.10.0.0/24".red().bold());
                continue;
            }
        }
    }

    Ok(())
}

fn scan_with_cidr(
    network: IpNetwork,
    porta: &str,
    dominio: &str,
    num_threads: usize
) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let ip_list: Vec<_> = network.iter().collect();
    let chunk_size = (ip_list.len() + num_threads - 1) / num_threads;

    let mut handles = vec![];

    for chunk in ip_list.chunks(chunk_size) {
        let results = Arc::clone(&results);
        let porta = porta.to_string();
        let dominio = dominio.to_string();
        let chunk = chunk.to_vec();

        let handle = thread::spawn(move || {
            for ip in chunk {
                let ip_str = ip.to_string();
                if let Ok(status) = check_ip(&ip_str, &porta, &dominio) {
                    if (100..=299).contains(&status) || (400..=499).contains(&status) {
                        let mut results = results.lock().unwrap();
                        results.push(ScanResult { ip: ip_str.clone(), status });
                        println!("{} | {} {}", 
                            ip_str.yellow().bold(),
                            "IP OK - STATUS".white().bold(),
                            status.to_string().white().bold()
                        );
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(Arc::try_unwrap(results).unwrap().into_inner().unwrap())
}

fn check_ip(ip: &str, porta: &str, dominio: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let url = if !dominio.starts_with("http") {
        format!("http://{}", dominio)
    } else {
        dominio.to_string()
    };

    let agent = ureq::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build();

    match agent.get(&url)
        .set("Upgrade", "websocket")
        .call() {
            Ok(response) => Ok(response.status()),
            Err(ureq::Error::Status(code, _)) => Ok(code),
            Err(_) => Ok(0)
    }
}

fn save_results(results: &[ScanResult]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("OK.txt")?;

    for result in results {
        writeln!(file, "{}|{}", result.ip, result.status)?;
    }
    writeln!(file, "==================")?;

    Ok(())
}

fn display_results(results: &[ScanResult]) {
    for result in results {
        println!("{} | {} {}", 
            result.ip.yellow().bold(),
            "IP OK - STATUS".white().bold(),
            result.status.to_string().white().bold()
        );
    }
}
