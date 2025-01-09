use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;
use tokio::time::timeout;
use tokio::net::TcpSocket;
use std::error::Error;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::OnceCell;


// 定義port
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct PortInfo {
    port: u16,
    service: String,
    category: String,
}

impl PortInfo {
    fn new(port: u16, service: &str, category: &str) -> Self {
        PortInfo {
            port,
            service: service.to_string(),
            category: category.to_string(),
        }
    }
}

// 定義掃描結果結構
#[derive(Debug)]
struct ScanResult {
    inbound: bool,
    outbound: bool,
}

// 定義常用port和服務
fn get_common_ports() -> Vec<PortInfo> {
    vec![
        // Web 服務
        PortInfo::new(80, "HTTP", "Web"),
        PortInfo::new(443, "HTTPS", "Web"),
        PortInfo::new(8080, "HTTP-ALT", "Web"),
        PortInfo::new(8443, "HTTPS-ALT", "Web"),
        
        // 郵件服務
        PortInfo::new(25, "SMTP", "Mail"),
        PortInfo::new(465, "SMTPS", "Mail"),
        PortInfo::new(587, "Submission", "Mail"),
        PortInfo::new(110, "POP3", "Mail"),
        PortInfo::new(995, "POP3S", "Mail"),
        PortInfo::new(143, "IMAP", "Mail"),
        PortInfo::new(993, "IMAPS", "Mail"),
        
        // 資料庫
        PortInfo::new(3306, "MySQL", "Database"),
        PortInfo::new(5432, "PostgreSQL", "Database"),
        PortInfo::new(27017, "MongoDB", "Database"),
        PortInfo::new(6379, "Redis", "Database"),
        
        // 遠端連線
        PortInfo::new(22, "SSH", "Remote"),
        PortInfo::new(3389, "RDP", "Remote"),
        PortInfo::new(5900, "VNC", "Remote"),
        
        // 文件傳輸
        PortInfo::new(21, "FTP", "File"),
        PortInfo::new(69, "TFTP", "File"),
        PortInfo::new(115, "SFTP", "File"),
        
        // 集群和容器
        PortInfo::new(2375, "Docker", "Container"),
        PortInfo::new(2376, "Docker-TLS", "Container"),
        PortInfo::new(6443, "Kubernetes", "Container"),

        // 其他 
        PortInfo::new(53, "DNS", "Other"),
        PortInfo::new(123, "NTP", "Other"),
        PortInfo::new(161, "SNMP", "Other"),
        PortInfo::new(389, "LDAP", "Other"),
        PortInfo::new(445, "SMB", "Other"),
        PortInfo::new(548, "AFP", "Other"),
        PortInfo::new(12345, "NetBus", "Other"),
        PortInfo::new(31337, "Back Orifice", "Other"),
        PortInfo::new(6667, "IRC", "Other"),
        PortInfo::new(6697, "IRC-TLS", "Other"),
        PortInfo::new(8080, "Proxy", "Other"),
        PortInfo::new(8443, "Proxy-SSL", "Other"),
        PortInfo::new(9050, "Tor", "Other"),
        PortInfo::new(9150, "Tor-SSL", "Other"),
        PortInfo::new(9999, "Urchin", "Other"),
        PortInfo::new(10000, "Webmin", "Other"),
        PortInfo::new(11211, "Memcached", "Other"), 

    ]
}
    

// 主函數
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_header();
    show_network_info().await?;
    let scan_results = perform_scan().await;
    display_results(&scan_results);
    
    println!("\n按 'q' 後Enter 離開程序...");
    
    let mut buffer = String::new();
    while let Ok(_) = std::io::stdin().read_line(&mut buffer) {
        if buffer.trim().to_lowercase() == "q" {
            break;
        }
        buffer.clear();
    }
    
    Ok(())
}

// 顯示程序標題
fn print_header() {
    println!("\n{}", "=== 端口掃描工具 ===".bold());
    println!("{}", "檢測端口狀態和服務可用性\n".italic());
}

// 顯示網絡
async fn show_network_info() -> Result<(), Box<dyn Error>> {
    // 本地IP
    if let Ok(local_ip) = local_ip_address::local_ip() {
        println!("{} {}", "本地 IP:".bold(), local_ip);
    } else {
        println!("{}", "無法取得本地 IP".red());
    }

    // 獲取外部IP
    print!("{}", "外部 IP: ".bold());
    match reqwest::get("https://api.ipify.org").await?.text().await {
        Ok(ip) => {
            println!("{}", ip.green());
            // 使用OnceCell存儲外部IP
            EXTERNAL_IP.set(ip).unwrap_or_else(|_| println!("警告：外部ip已經設置"));
        },
        Err(_) => println!("{}", "無法取得".red()),
    }

    Ok(())
}


static EXTERNAL_IP: OnceCell<String> = OnceCell::const_new();

// 執行掃描
async fn perform_scan() -> HashMap<PortInfo, ScanResult> {
    let ports = get_common_ports();
    let pb = create_progress_bar(ports.len());
    let mut results = HashMap::new();

    for port_info in ports {
        let scan_result = scan_port(&port_info.port).await;
        results.insert(port_info, scan_result);
        pb.inc(1);
    }

    pb.finish_with_message("掃描完成");
    results
}

// 進度條
fn create_progress_bar(len: usize) -> ProgressBar {
    let pb = ProgressBar::new(len as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );
    pb
}

// 掃描單個端口
async fn scan_port(port: &u16) -> ScanResult {
    let inbound = test_inbound_port(*port).await;
    let outbound = test_outbound_port(*port).await;
    
    ScanResult {
        inbound,
        outbound,
    }
}

// 測試入站連接
async fn test_inbound_port(port: u16) -> bool {
    if let Some(ip) = EXTERNAL_IP.get() {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            return TcpListener::bind((addr, port)).is_ok();
        }
    }
    
    // 如果外部IP不可用,回退到使用"0.0.0.0"
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

// 測試出站連接
async fn test_outbound_port(port: u16) -> bool {
    if let Ok(socket) = TcpSocket::new_v4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(208,67,222,222)), port);
        match timeout(Duration::from_secs(1), socket.connect(addr)).await {
            Ok(Ok(_)) => return true,
            _ => return false,
        }
    }
    false
}

// 顯示掃描結果
fn display_results(results: &HashMap<PortInfo, ScanResult>) {
    println!("\n{}", "=== 掃描結果 ===".bold());

    // 按類別分組顯示結果
    let categories: HashSet<_> = results.keys().map(|p: &PortInfo| &p.category).collect();
    
    for category in categories {
        println!("\n{}", format!("--- {} ---", category).bold());
        
        for (port_info, result) in results.iter().filter(|(p, _)| &p.category == category) {
            print!("Port {:5} ({:15}): ", port_info.port, port_info.service);
            
            match (result.inbound, result.outbound) {
                (true, true) => println!("{}", "✓ 雙向可用".green()),
                (true, false) => println!("{}", "↓ 只能接收".yellow()),
                (false, true) => println!("{}", "↑ 只能發送".yellow()),
                (false, false) => println!("{}", "✗ 不可用".red()),
            }
        }
    }


    // 顯示圖例
    print_legend();
}

// 顯示圖例說明
fn print_legend() {
    println!("\n{}", "圖例說明：".bold());
    println!("✓ {}: 端口可以接收和發送連接", "雙向可用".green());
    println!("↓ {}: 端口只接受入站連接", "只能接收".yellow());
    println!("↑ {}: 端口只允許出站連接", "只能發送".yellow());
    println!("✗ {}: 端口完全不可用", "不可用".red());
    
    println!("\n{}", "注意事項：".bold());
    println!("1. 某些端口可能需要管理員權限");
    println!("2. 防火牆設置可能影響掃描結果");
    println!("3. 網絡延遲可能導致誤報");
}
