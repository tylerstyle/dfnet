use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Row, Table, TableState, Tabs},
    Terminal,
};
use std::{
    io,
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(
    name = "dfnet",
    version,
    about = "Modern Forensic Network Triage, Stealth MAC Cloaking, Share Ingest & Wi-Fi AP TUI"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Randomize and spoof MAC address on network interface
    Mac { iface: String },
    /// Restore permanent factory MAC address
    Restore { iface: String },
    /// Scan local subnet for active hosts, NAS appliances and storage ports
    Scan { iface: Option<String> },
    /// Mount an on-premise SMB/CIFS share read-only into /media/target/
    Smb {
        remote: String,
        name: String,
        user: Option<String>,
    },
    /// Mount an on-premise NFS export read-only into /media/target/
    Nfs { remote: String, name: String },
    /// Listen on network port to receive raw streamed disk image
    Receive {
        port: Option<u16>,
        out: Option<String>,
    },
    /// Create, stop, or inspect forensic Wi-Fi Access Point (Hotspot)
    Hotspot {
        #[command(subcommand)]
        action: Option<HotspotAction>,
    },
}

#[derive(Subcommand, Debug)]
enum HotspotAction {
    /// Start Wi-Fi hotspot with specified or default SSID and password
    Start {
        #[arg(short, long)]
        iface: Option<String>,
        #[arg(short, long, default_value = "dfnix-hotspot")]
        ssid: String,
        #[arg(short, long, default_value = "forensics123")]
        password: String,
    },
    /// Stop currently running Wi-Fi hotspot
    Stop {
        #[arg(short, long)]
        iface: Option<String>,
    },
    /// Display status of Wi-Fi hotspot and connected clients
    Status,
}

#[derive(Debug, Clone)]
struct NetInterface {
    name: String,
    state: String,
    mac: String,
    ip: String,
}

#[derive(Debug, Clone)]
struct WifiDevice {
    name: String,
    state: String,
    connection: String,
}

fn fetch_interfaces() -> Vec<NetInterface> {
    let output = Command::new("ip").args(["-br", "addr", "show"]).output();
    let mut ifaces = Vec::new();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let state = parts[1].to_string();
                let ip = if parts.len() >= 3 {
                    parts[2].to_string()
                } else {
                    "-".to_string()
                };

                // Get MAC
                let link_out = Command::new("ip")
                    .args(["-br", "link", "show", &name])
                    .output();
                let mac = if let Ok(lout) = link_out {
                    let ltext = String::from_utf8_lossy(&lout.stdout);
                    let lparts: Vec<&str> = ltext.split_whitespace().collect();
                    if lparts.len() >= 3 {
                        lparts[2].to_string()
                    } else {
                        "-".to_string()
                    }
                } else {
                    "-".to_string()
                };

                ifaces.push(NetInterface {
                    name,
                    state,
                    mac,
                    ip,
                });
            }
        }
    }
    ifaces
}

fn fetch_wifi_devices() -> Vec<WifiDevice> {
    let mut devs = Vec::new();
    if let Ok(output) = Command::new("nmcli")
        .args(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[1] == "wifi" {
                let name = parts[0].to_string();
                let state = parts[2].to_string();
                let connection = if parts.len() >= 4 {
                    parts[3].to_string()
                } else {
                    String::new()
                };
                devs.push(WifiDevice {
                    name,
                    state,
                    connection,
                });
            }
        }
    }

    // Fallback: sysfs check
    if devs.is_empty() {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.join("wireless").exists() || path.join("phy80211").exists() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        devs.push(WifiDevice {
                            name: name.to_string(),
                            state: "available".to_string(),
                            connection: String::new(),
                        });
                    }
                }
            }
        }
    }
    devs
}

fn spoof_mac(iface: &str) -> Result<String> {
    let _ = Command::new("ip")
        .args(["link", "set", "dev", iface, "down"])
        .status();
    let res = Command::new("macchanger").args(["-r", iface]).output();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", iface, "up"])
        .status();

    if let Ok(out) = res {
        if out.status.success() {
            return Ok(format!("Randomized and cloaked MAC address on {}", iface));
        }
    }
    anyhow::bail!(
        "Failed to spoof MAC on {}. Ensure macchanger is installed.",
        iface
    )
}

fn restore_mac(iface: &str) -> Result<String> {
    let _ = Command::new("ip")
        .args(["link", "set", "dev", iface, "down"])
        .status();
    let res = Command::new("macchanger").args(["-p", iface]).output();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", iface, "up"])
        .status();

    if let Ok(out) = res {
        if out.status.success() {
            return Ok(format!("Restored permanent hardware MAC on {}", iface));
        }
    }
    anyhow::bail!("Failed to restore permanent MAC on {}", iface)
}

fn scan_subnet(iface: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("arp-scan");
    if let Some(i) = iface {
        cmd.args(["--interface", i]);
    }
    cmd.arg("--localnet");
    let out = cmd.output().context("Failed to run arp-scan")?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn start_hotspot(iface: &str, ssid: &str, password: &str) -> Result<String> {
    if password.len() < 8 {
        anyhow::bail!("Wi-Fi WPA2 password must be at least 8 characters long.");
    }
    let _ = Command::new("nmcli")
        .args(["connection", "delete", "id", "dfnet-hotspot"])
        .output();
    let output = Command::new("nmcli")
        .args([
            "device",
            "wifi",
            "hotspot",
            "ifname",
            iface,
            "con-name",
            "dfnet-hotspot",
            "ssid",
            ssid,
            "password",
            password,
        ])
        .output()
        .context("Failed to run nmcli device wifi hotspot")?;

    if output.status.success() {
        Ok(format!("Hotspot '{}' started on {} (WPA2)", ssid, iface))
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to activate hotspot: {}", err.trim())
    }
}

fn stop_hotspot(iface: Option<&str>) -> Result<String> {
    let _ = Command::new("nmcli")
        .args(["connection", "down", "id", "dfnet-hotspot"])
        .output();
    let _ = Command::new("nmcli")
        .args(["connection", "delete", "id", "dfnet-hotspot"])
        .output();
    if let Some(i) = iface {
        let _ = Command::new("nmcli")
            .args(["device", "disconnect", i])
            .output();
    }
    Ok("Wi-Fi Hotspot stopped.".to_string())
}

fn is_hotspot_active(iface: Option<&str>) -> (bool, Option<String>, Option<String>) {
    if let Ok(output) = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && (parts[1] == "802-11-wireless" || parts[1] == "wifi") {
                let dev_name = parts[2];
                if iface.is_none_or(|i| i == dev_name) {
                    let ip = get_interface_ip(dev_name);
                    return (true, ip, Some(parts[0].to_string()));
                }
            }
        }
    }
    (false, None, None)
}

fn get_interface_ip(iface: &str) -> Option<String> {
    if let Ok(output) = Command::new("ip")
        .args(["-br", "addr", "show", iface])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = text.lines().next() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return Some(parts[2].to_string());
            }
        }
    }
    None
}

fn fetch_connected_clients(iface: &str) -> Vec<(String, String)> {
    let mut clients = Vec::new();
    if let Ok(output) = Command::new("ip")
        .args(["neigh", "show", "dev", iface])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Some(pos) = parts.iter().position(|&x| x == "lladdr") {
                    if pos + 1 < parts.len() {
                        clients.push((parts[0].to_string(), parts[pos + 1].to_string()));
                    }
                }
            }
        }
    }
    clients
}

fn run_tui() -> Result<()> {
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        default_panic(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut current_tab = 0;

    struct TabCategory {
        badge: &'static str,
        icon: &'static str,
        title: &'static str,
    }

    let tab_categories = [
        TabCategory {
            badge: "1",
            icon: "🌐",
            title: "Interfaces & MAC Cloaking",
        },
        TabCategory {
            badge: "2",
            icon: "🔍",
            title: "Subnet Discovery & ARP",
        },
        TabCategory {
            badge: "3",
            icon: "⚡",
            title: "Stream Receiver",
        },
        TabCategory {
            badge: "4",
            icon: "📡",
            title: "Wi-Fi Hotspot / AP",
        },
    ];

    let mut ifaces = fetch_interfaces();
    let mut table_state = TableState::default();
    table_state.select(Some(0));

    let mut status_msg = String::from("Ready. Click tabs or navigate with [1-4], [Tab], or [j/k].");
    let mut is_error = false;
    let mut scan_results = String::from("Press [S] to run local ARP discovery scan.");

    // Hotspot tab state
    let mut wifi_devs = fetch_wifi_devices();
    let mut selected_wifi_idx = 0usize;
    let mut hotspot_ssid = String::from("dfnix-hotspot");
    let mut hotspot_pass = String::from("forensics123");
    let mut hotspot_selected_field = 0usize; // 0=Interface, 1=SSID, 2=Password, 3=Action
    let mut is_editing_text = false;

    let mut tab_bounds: Vec<(u16, u16)> = Vec::new();
    let mut last_chunks = [ratatui::layout::Rect::default(); 5];

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), // Title
                    Constraint::Length(3), // Tab navigation
                    Constraint::Min(8),    // Content
                    Constraint::Length(3), // Status Box
                    Constraint::Length(2), // Bottom Hotkeys
                ])
                .split(f.area());

            last_chunks[0] = chunks[0];
            last_chunks[1] = chunks[1];
            last_chunks[2] = chunks[2];
            last_chunks[3] = chunks[3];
            last_chunks[4] = chunks[4];

            // 1. Title
            let title = Paragraph::new(Line::from(vec![
                Span::styled(" dfnet ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("— Forensic Network Triage, Stealth Cloaking, Share Ingest & Wi-Fi AP TUI"),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(title, chunks[0]);

            // 2. Tabs
            let tabs_block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(Line::from(vec![
                    Span::styled(" ◈ CATEGORIES ◈ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(" [Click tab or press 1-4 / Tab] ", Style::default().fg(Color::DarkGray)),
                ]))
                .border_style(Style::default().fg(Color::DarkGray));

            let inner_tabs = tabs_block.inner(chunks[1]);
            tab_bounds.clear();
            let mut cur_x = inner_tabs.x;

            let tab_lines: Vec<Line> = tab_categories
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let is_sel = i == current_tab;
                    let line = if is_sel {
                        Line::from(vec![
                            Span::raw(" "),
                            Span::styled(
                                format!(" {} ", t.badge),
                                Style::default()
                                    .bg(Color::Cyan)
                                    .fg(Color::Black)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(" ", Style::default().bg(Color::Rgb(20, 50, 75))),
                            Span::styled(
                                format!("{} ", t.icon),
                                Style::default().bg(Color::Rgb(20, 50, 75)),
                            ),
                            Span::styled(
                                format!("{} ", t.title),
                                Style::default()
                                    .fg(Color::White)
                                    .bg(Color::Rgb(20, 50, 75))
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::styled("● ", Style::default().fg(Color::Cyan).bg(Color::Rgb(20, 50, 75))),
                        ])
                    } else {
                        Line::from(vec![
                            Span::raw(" "),
                            Span::styled(
                                format!(" {} ", t.badge),
                                Style::default()
                                    .bg(Color::Rgb(35, 40, 50))
                                    .fg(Color::DarkGray)
                                    .add_modifier(Modifier::BOLD),
                            ),
                            Span::raw(" "),
                            Span::styled(
                                format!("{} ", t.icon),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(
                                format!("{} ", t.title),
                                Style::default().fg(Color::Gray),
                            ),
                            Span::raw(" "),
                        ])
                    };

                    let w = line.width() as u16;
                    tab_bounds.push((cur_x, cur_x + w));
                    cur_x += w + 3; // +3 for divider " │ "
                    line
                })
                .collect();

            let tabs_widget = Tabs::new(tab_lines)
                .select(current_tab)
                .divider(Span::styled(" │ ", Style::default().fg(Color::Rgb(60, 70, 85))))
                .block(tabs_block);
            f.render_widget(tabs_widget, chunks[1]);

            // 3. Tab Content
            match current_tab {
                0 => {
                    // Interface Table
                    let rows: Vec<Row> = ifaces
                        .iter()
                        .map(|iface| {
                            let state_color = if iface.state == "UP" { Color::Green } else { Color::Red };
                            Row::new(vec![
                                Span::raw(&iface.name),
                                Span::styled(&iface.state, Style::default().fg(state_color).add_modifier(Modifier::BOLD)),
                                Span::raw(&iface.mac),
                                Span::raw(&iface.ip),
                            ])
                        })
                        .collect();

                    let header = Row::new(vec![
                        Span::styled("INTERFACE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::styled("STATE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::styled("MAC ADDRESS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Span::styled("IP ADDRESS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    ]);

                    let table = Table::new(
                        rows,
                        [
                            Constraint::Percentage(20),
                            Constraint::Percentage(15),
                            Constraint::Percentage(35),
                            Constraint::Percentage(30),
                        ],
                    )
                    .header(header)
                    .block(Block::default().borders(Borders::ALL).title(" Network Adapters ").border_style(Style::default().fg(Color::DarkGray)))
                    .row_highlight_style(Style::default().bg(Color::Rgb(30, 45, 55)).fg(Color::White).add_modifier(Modifier::BOLD));

                    f.render_stateful_widget(table, chunks[2], &mut table_state);
                }
                1 => {
                    let scan_p = Paragraph::new(scan_results.as_str())
                        .block(Block::default().borders(Borders::ALL).title(" Local Subnet ARP / Host Scan ").border_style(Style::default().fg(Color::DarkGray)));
                    f.render_widget(scan_p, chunks[2]);
                }
                2 => {
                    let stream_info = vec![
                        Line::from(vec![
                            Span::styled("Live Network Disk Stream Receiver", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        ]),
                        Line::from(""),
                        Line::from("Listens on TCP port 9999 and streams incoming raw disk stream to:"),
                        Line::from(Span::styled("  /media/target/network_stream.raw", Style::default().fg(Color::Yellow))),
                        Line::from(""),
                        Line::from("Remote Evidence Command (with live SHA-256 hash):"),
                        Line::from(Span::styled("  sudo dd if=/dev/nvme0n1 bs=64K status=progress | tee >(sha256sum > source.sha256) | nc <this-ip> 9999", Style::default().fg(Color::Green))),
                        Line::from(""),
                        Line::from("Press [L] to start listening now."),
                    ];
                    let p = Paragraph::new(stream_info)
                        .block(Block::default().borders(Borders::ALL).title(" Live Disk Receiver ").border_style(Style::default().fg(Color::DarkGray)));
                    f.render_widget(p, chunks[2]);
                }
                _ => {
                    // Tab 3: Wi-Fi Hotspot / AP
                    if wifi_devs.is_empty() {
                        let no_wifi_text = vec![
                            Line::from(""),
                            Line::from(vec![
                                Span::styled("  [!] No Wi-Fi Hardware Detected", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                            ]),
                            Line::from(""),
                            Line::from("  No wireless networking interfaces (802.11 Wi-Fi) were discovered on this system."),
                            Line::from(""),
                            Line::from("  Common troubleshooting steps:"),
                            Line::from("   • The machine does not have an internal wireless network card."),
                            Line::from("   • The hardware Wi-Fi kill switch or airplane mode is enabled on the laptop."),
                            Line::from("   • The wireless interface kernel driver / firmware is not loaded."),
                            Line::from(""),
                            Line::from("  Forensic Field Recommendation:"),
                            Line::from(vec![
                                Span::raw("   • Connect an external USB Wi-Fi dongle and press "),
                                Span::styled("[R]", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                                Span::raw(" to rescan for wireless adapters."),
                            ]),
                            Line::from(""),
                        ];
                        let p = Paragraph::new(no_wifi_text)
                            .block(Block::default().borders(Borders::ALL).title(" Wi-Fi Hotspot / Access Point ").border_style(Style::default().fg(Color::Yellow)));
                        f.render_widget(p, chunks[2]);
                    } else {
                        let h_chunks = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
                            .split(chunks[2]);

                        let cur_dev = wifi_devs.get(selected_wifi_idx);
                        let cur_iface = cur_dev.map(|d| d.name.as_str()).unwrap_or("-");
                        let cur_dev_info = cur_dev.map(|d| {
                            if !d.connection.is_empty() && d.connection != "--" {
                                format!(" (state: {}, conn: {})", d.state, d.connection)
                            } else {
                                format!(" (state: {})", d.state)
                            }
                        }).unwrap_or_default();
                        let (is_active, active_ip, _) = is_hotspot_active(Some(cur_iface));
                        let clients = if is_active { fetch_connected_clients(cur_iface) } else { Vec::new() };

                        // Left: Configuration & Controls
                        let mut left_lines = vec![
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(if hotspot_selected_field == 0 { " ▶ " } else { "   " }, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                                Span::styled("Wi-Fi Interface:  ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(format!("[ {} ]", cur_iface), Style::default().fg(if hotspot_selected_field == 0 { Color::Cyan } else { Color::Yellow }).add_modifier(Modifier::BOLD)),
                                Span::raw(format!("  ({}/{} - use ←/→)", selected_wifi_idx + 1, wifi_devs.len())),
                                Span::styled(cur_dev_info, Style::default().fg(Color::DarkGray)),
                            ]),
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(if hotspot_selected_field == 1 { " ▶ " } else { "   " }, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                                Span::styled("Network (SSID):   ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(format!("[ {} ]", hotspot_ssid), Style::default().fg(if hotspot_selected_field == 1 { Color::Cyan } else { Color::Yellow }).add_modifier(Modifier::BOLD)),
                                Span::raw(if hotspot_selected_field == 1 && is_editing_text { "  [EDITING - Enter to save]" } else { "  (Enter to edit)" }),
                            ]),
                            Line::from(""),
                            Line::from(vec![
                                Span::styled(if hotspot_selected_field == 2 { " ▶ " } else { "   " }, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                                Span::styled("WPA2 Password:    ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(format!("[ {} ]", hotspot_pass), Style::default().fg(if hotspot_selected_field == 2 { Color::Cyan } else { Color::Yellow }).add_modifier(Modifier::BOLD)),
                                Span::raw(if hotspot_selected_field == 2 && is_editing_text { "  [EDITING - Enter to save]" } else { "  (Enter to edit, ≥8 chars)" }),
                            ]),
                            Line::from(""),
                            Line::from("────────────────────────────────────────────────────────"),
                            Line::from(""),
                        ];

                        if !is_active {
                            left_lines.push(Line::from(vec![
                                Span::styled(if hotspot_selected_field == 3 { " ▶ " } else { "   " }, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                                Span::styled(
                                    "  [ START WI-FI HOTSPOT ]  ",
                                    Style::default()
                                        .bg(if hotspot_selected_field == 3 { Color::Green } else { Color::Rgb(20, 60, 30) })
                                        .fg(Color::White)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                Span::raw("   Press [Space] or [Enter]"),
                            ]));
                        } else {
                            left_lines.push(Line::from(vec![
                                Span::styled(if hotspot_selected_field == 3 { " ▶ " } else { "   " }, Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                                Span::styled(
                                    "  [ STOP WI-FI HOTSPOT ]   ",
                                    Style::default()
                                        .bg(if hotspot_selected_field == 3 { Color::Red } else { Color::Rgb(80, 20, 20) })
                                        .fg(Color::White)
                                        .add_modifier(Modifier::BOLD),
                                ),
                                Span::raw("   Press [Space] or [Enter]"),
                            ]));
                        }

                        left_lines.extend(vec![
                            Line::from(""),
                            Line::from(""),
                            Line::from(Span::styled("  Navigation: [↑/↓] Select field  [←/→] Select adapter  [Enter] Edit/Apply", Style::default().fg(Color::DarkGray))),
                        ]);

                        let p_left = Paragraph::new(left_lines)
                            .block(Block::default().borders(Borders::ALL).title(" Hotspot Configuration & Controls ").border_style(Style::default().fg(Color::Cyan)));
                        f.render_widget(p_left, h_chunks[0]);

                        // Right: Active Status & Connected Clients
                        let mut right_lines = vec![Line::from("")];

                        if is_active {
                            right_lines.push(Line::from(vec![
                                Span::styled("  Status:      ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled("● ACTIVE (Broadcasting)", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                            ]));
                            right_lines.push(Line::from(vec![
                                Span::styled("  SSID:        ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(&hotspot_ssid, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                            ]));
                            right_lines.push(Line::from(vec![
                                Span::styled("  Password:    ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(&hotspot_pass, Style::default().fg(Color::Yellow)),
                            ]));
                            right_lines.push(Line::from(vec![
                                Span::styled("  Gateway IP:  ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled(active_ip.as_deref().unwrap_or("10.42.0.1/24"), Style::default().fg(Color::Green)),
                            ]));
                            right_lines.push(Line::from(vec![
                                Span::styled("  Security:    ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::raw("WPA2-Personal (Shared NAT) • 802.11 AP"),
                            ]));
                        } else {
                            right_lines.push(Line::from(vec![
                                Span::styled("  Status:      ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                                Span::styled("○ INACTIVE (Ready to enable)", Style::default().fg(Color::DarkGray)),
                            ]));
                            right_lines.push(Line::from("  Hotspot is disabled. Configure settings on the left and start."));
                        }

                        right_lines.push(Line::from(""));
                        right_lines.push(Line::from("────────────────────────────────────────────────────────"));
                        right_lines.push(Line::from(Span::styled("  Connected Evidence & Client Devices:", Style::default().fg(Color::White).add_modifier(Modifier::BOLD))));
                        right_lines.push(Line::from(""));

                        if clients.is_empty() {
                            right_lines.push(Line::from(Span::styled("  No client devices currently associated.", Style::default().fg(Color::DarkGray))));
                        } else {
                            right_lines.push(Line::from(vec![
                                Span::styled(format!("  {:<18} {:<20} {}", "IP ADDRESS", "MAC ADDRESS", "STATUS"), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                            ]));
                            for (ip, mac) in &clients {
                                right_lines.push(Line::from(vec![
                                    Span::raw("  "),
                                    Span::styled(format!("{:<18}", ip), Style::default().fg(Color::Green)),
                                    Span::raw(format!("{:<20}", mac)),
                                    Span::styled("CONNECTED", Style::default().fg(Color::Green)),
                                ]));
                            }
                        }

                        let p_right = Paragraph::new(right_lines)
                            .block(Block::default().borders(Borders::ALL).title(" Live Hotspot Status & Ingest Clients ").border_style(Style::default().fg(if is_active { Color::Green } else { Color::DarkGray })));
                        f.render_widget(p_right, h_chunks[1]);
                    }
                }
            }

            // 4. Status Box
            let status_color = if is_error { Color::Red } else { Color::Green };
            let status_p = Paragraph::new(Line::from(vec![
                Span::styled(" >> ", Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                Span::styled(&status_msg, Style::default().fg(status_color)),
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(status_p, chunks[3]);

            // 5. Hotkeys Footer
            let footer = if current_tab == 3 {
                Paragraph::new(Line::from(vec![
                    Span::styled(" [Click / 1-4 / Tab] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Category  "),
                    Span::styled(" [↑/↓] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Field  "),
                    Span::styled(" [←/→] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Adapter  "),
                    Span::styled(" [Enter] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Edit/Apply  "),
                    Span::styled(" [Space/H] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Start/Stop Hotspot  "),
                    Span::styled(" [R] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Refresh  "),
                    Span::styled(" [Q] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Quit"),
                ]))
            } else {
                Paragraph::new(Line::from(vec![
                    Span::styled(" [Click / 1-4 / Tab] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Category  "),
                    Span::styled(" [M] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Random MAC  "),
                    Span::styled(" [P] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Restore MAC  "),
                    Span::styled(" [N] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("nmtui  "),
                    Span::styled(" [S] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Scan Subnet  "),
                    Span::styled(" [R] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Refresh  "),
                    Span::styled(" [Q] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw("Quit"),
                ]))
            };
            f.render_widget(footer, chunks[4]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Mouse(mouse) => {
                    match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => {
                            // 1. Check if clicked inside Tab Categories (last_chunks[1])
                            if mouse.row >= last_chunks[1].y
                                && mouse.row < last_chunks[1].y + last_chunks[1].height
                            {
                                for (idx, (start_x, end_x)) in tab_bounds.iter().enumerate() {
                                    let min_x = if idx == 0 {
                                        0
                                    } else {
                                        start_x.saturating_sub(1)
                                    };
                                    let max_x = if idx + 1 < tab_bounds.len() {
                                        tab_bounds[idx + 1].0
                                    } else {
                                        (*end_x + 3).min(last_chunks[1].x + last_chunks[1].width)
                                    };
                                    if mouse.column >= min_x && mouse.column < max_x {
                                        current_tab = idx;
                                        is_editing_text = false;
                                        status_msg =
                                            format!("Switched to: {}", tab_categories[idx].title);
                                        is_error = false;
                                        break;
                                    }
                                }
                            } else if current_tab == 0 {
                                // 2. Check if clicked on Network Adapters table (last_chunks[2])
                                let table_content_start = last_chunks[2].y + 2;
                                let table_content_end =
                                    last_chunks[2].y + last_chunks[2].height.saturating_sub(1);
                                if mouse.row >= table_content_start && mouse.row < table_content_end
                                {
                                    let clicked_row = (mouse.row - table_content_start) as usize;
                                    if clicked_row < ifaces.len() {
                                        table_state.select(Some(clicked_row));
                                        status_msg = format!(
                                            "Selected interface: {}",
                                            ifaces[clicked_row].name
                                        );
                                        is_error = false;
                                    }
                                }
                            } else if current_tab == 3 {
                                // 3. Check if clicked in Wi-Fi Hotspot configuration fields
                                let h_chunks = Layout::default()
                                    .direction(Direction::Horizontal)
                                    .constraints([
                                        Constraint::Percentage(50),
                                        Constraint::Percentage(50),
                                    ])
                                    .split(last_chunks[2]);
                                if mouse.column >= h_chunks[0].x
                                    && mouse.column < h_chunks[0].x + h_chunks[0].width
                                {
                                    let top = h_chunks[0].y + 1;
                                    if mouse.row == top + 1 {
                                        hotspot_selected_field = 0;
                                        is_editing_text = false;
                                    } else if mouse.row == top + 3 {
                                        hotspot_selected_field = 1;
                                        is_editing_text = true;
                                        status_msg =
                                            "Type new SSID. Press Enter to confirm, Esc to cancel."
                                                .to_string();
                                    } else if mouse.row == top + 5 {
                                        hotspot_selected_field = 2;
                                        is_editing_text = true;
                                        status_msg = "Type new Password (≥8 chars). Press Enter to confirm, Esc to cancel.".to_string();
                                    } else if mouse.row == top + 7 || mouse.row == top + 8 {
                                        hotspot_selected_field = 3;
                                        is_editing_text = false;
                                    }
                                }
                            }
                        }
                        MouseEventKind::ScrollDown => {
                            if mouse.row >= last_chunks[1].y
                                && mouse.row < last_chunks[1].y + last_chunks[1].height
                            {
                                current_tab = (current_tab + 1) % tab_categories.len();
                                is_editing_text = false;
                                status_msg =
                                    format!("Switched to: {}", tab_categories[current_tab].title);
                            } else if current_tab == 0 {
                                let i = match table_state.selected() {
                                    Some(i) if i + 1 < ifaces.len() => i + 1,
                                    _ => 0,
                                };
                                table_state.select(Some(i));
                            }
                        }
                        MouseEventKind::ScrollUp => {
                            if mouse.row >= last_chunks[1].y
                                && mouse.row < last_chunks[1].y + last_chunks[1].height
                            {
                                current_tab = if current_tab > 0 {
                                    current_tab - 1
                                } else {
                                    tab_categories.len() - 1
                                };
                                is_editing_text = false;
                                status_msg =
                                    format!("Switched to: {}", tab_categories[current_tab].title);
                            } else if current_tab == 0 {
                                let i = match table_state.selected() {
                                    Some(i) => {
                                        if i > 0 {
                                            i - 1
                                        } else {
                                            ifaces.len().saturating_sub(1)
                                        }
                                    }
                                    None => 0,
                                };
                                table_state.select(Some(i));
                            }
                        }
                        _ => {}
                    }
                }
                Event::Key(key) => {
                    if current_tab == 3 && is_editing_text {
                        match key.code {
                            KeyCode::Esc => {
                                is_editing_text = false;
                                status_msg = "Editing cancelled.".to_string();
                            }
                            KeyCode::Enter => {
                                is_editing_text = false;
                                status_msg = "Configuration value saved.".to_string();
                                is_error = false;
                            }
                            KeyCode::Backspace => {
                                if hotspot_selected_field == 1 {
                                    hotspot_ssid.pop();
                                } else if hotspot_selected_field == 2 {
                                    hotspot_pass.pop();
                                }
                            }
                            KeyCode::Char(c) => {
                                if hotspot_selected_field == 1 {
                                    hotspot_ssid.push(c);
                                } else if hotspot_selected_field == 2 {
                                    hotspot_pass.push(c);
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Tab => {
                            current_tab = (current_tab + 1) % tab_categories.len();
                            is_editing_text = false;
                        }
                        KeyCode::BackTab => {
                            current_tab = if current_tab > 0 {
                                current_tab - 1
                            } else {
                                tab_categories.len() - 1
                            };
                            is_editing_text = false;
                        }
                        KeyCode::Char('1') => {
                            current_tab = 0;
                            is_editing_text = false;
                            status_msg = format!("Switched to: {}", tab_categories[0].title);
                            is_error = false;
                        }
                        KeyCode::Char('2') => {
                            current_tab = 1;
                            is_editing_text = false;
                            status_msg = format!("Switched to: {}", tab_categories[1].title);
                            is_error = false;
                        }
                        KeyCode::Char('3') => {
                            current_tab = 2;
                            is_editing_text = false;
                            status_msg = format!("Switched to: {}", tab_categories[2].title);
                            is_error = false;
                        }
                        KeyCode::Char('4') => {
                            current_tab = 3;
                            is_editing_text = false;
                            status_msg = format!("Switched to: {}", tab_categories[3].title);
                            is_error = false;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if current_tab == 0 {
                                let i = match table_state.selected() {
                                    Some(i) => {
                                        if i > 0 {
                                            i - 1
                                        } else {
                                            ifaces.len().saturating_sub(1)
                                        }
                                    }
                                    None => 0,
                                };
                                table_state.select(Some(i));
                            } else if current_tab == 3 {
                                hotspot_selected_field = if hotspot_selected_field > 0 {
                                    hotspot_selected_field - 1
                                } else {
                                    3
                                };
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if current_tab == 0 {
                                let i = match table_state.selected() {
                                    Some(i) if i < ifaces.len().saturating_sub(1) => i + 1,
                                    _ => 0,
                                };
                                table_state.select(Some(i));
                            } else if current_tab == 3 {
                                hotspot_selected_field = if hotspot_selected_field < 3 {
                                    hotspot_selected_field + 1
                                } else {
                                    0
                                };
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') if current_tab == 3 => {
                            if hotspot_selected_field == 0 && !wifi_devs.is_empty() {
                                selected_wifi_idx = if selected_wifi_idx > 0 {
                                    selected_wifi_idx - 1
                                } else {
                                    wifi_devs.len() - 1
                                };
                            }
                        }
                        KeyCode::Right | KeyCode::Char('l') if current_tab == 3 => {
                            if hotspot_selected_field == 0 && !wifi_devs.is_empty() {
                                selected_wifi_idx = if selected_wifi_idx + 1 < wifi_devs.len() {
                                    selected_wifi_idx + 1
                                } else {
                                    0
                                };
                            }
                        }
                        KeyCode::Enter if current_tab == 3 => {
                            if hotspot_selected_field == 1 || hotspot_selected_field == 2 {
                                is_editing_text = true;
                                status_msg =
                                    "Type new value. Press Enter to confirm, Esc to cancel."
                                        .to_string();
                            } else if hotspot_selected_field == 3 {
                                let cur_iface =
                                    wifi_devs.get(selected_wifi_idx).map(|d| d.name.as_str());
                                if let Some(iface) = cur_iface {
                                    let (is_active, _, _) = is_hotspot_active(Some(iface));
                                    if is_active {
                                        match stop_hotspot(Some(iface)) {
                                            Ok(msg) => {
                                                status_msg = msg;
                                                is_error = false;
                                            }
                                            Err(e) => {
                                                status_msg = format!("Failed to stop: {}", e);
                                                is_error = true;
                                            }
                                        }
                                    } else {
                                        match start_hotspot(iface, &hotspot_ssid, &hotspot_pass) {
                                            Ok(msg) => {
                                                status_msg = msg;
                                                is_error = false;
                                            }
                                            Err(e) => {
                                                status_msg = format!("Failed to start: {}", e);
                                                is_error = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        KeyCode::Char(' ') if current_tab == 3 => {
                            let cur_iface =
                                wifi_devs.get(selected_wifi_idx).map(|d| d.name.as_str());
                            if let Some(iface) = cur_iface {
                                let (is_active, _, _) = is_hotspot_active(Some(iface));
                                if is_active {
                                    match stop_hotspot(Some(iface)) {
                                        Ok(msg) => {
                                            status_msg = msg;
                                            is_error = false;
                                        }
                                        Err(e) => {
                                            status_msg = format!("Failed to stop: {}", e);
                                            is_error = true;
                                        }
                                    }
                                } else {
                                    match start_hotspot(iface, &hotspot_ssid, &hotspot_pass) {
                                        Ok(msg) => {
                                            status_msg = msg;
                                            is_error = false;
                                        }
                                        Err(e) => {
                                            status_msg = format!("Failed to start: {}", e);
                                            is_error = true;
                                        }
                                    }
                                }
                            }
                        }
                        KeyCode::Char('r') => {
                            ifaces = fetch_interfaces();
                            wifi_devs = fetch_wifi_devices();
                            if selected_wifi_idx >= wifi_devs.len() && !wifi_devs.is_empty() {
                                selected_wifi_idx = wifi_devs.len() - 1;
                            }
                            status_msg = "Refreshed network and wireless interfaces.".to_string();
                            is_error = false;
                        }
                        KeyCode::Char('m') if current_tab == 0 => {
                            if let Some(idx) = table_state.selected() {
                                if let Some(iface) = ifaces.get(idx) {
                                    match spoof_mac(&iface.name) {
                                        Ok(msg) => {
                                            status_msg = msg;
                                            is_error = false;
                                        }
                                        Err(e) => {
                                            status_msg = e.to_string();
                                            is_error = true;
                                        }
                                    }
                                    ifaces = fetch_interfaces();
                                }
                            }
                        }
                        KeyCode::Char('p') if current_tab == 0 => {
                            if let Some(idx) = table_state.selected() {
                                if let Some(iface) = ifaces.get(idx) {
                                    match restore_mac(&iface.name) {
                                        Ok(msg) => {
                                            status_msg = msg;
                                            is_error = false;
                                        }
                                        Err(e) => {
                                            status_msg = e.to_string();
                                            is_error = true;
                                        }
                                    }
                                    ifaces = fetch_interfaces();
                                }
                            }
                        }
                        KeyCode::Char('n') => {
                            disable_raw_mode()?;
                            execute!(
                                terminal.backend_mut(),
                                LeaveAlternateScreen,
                                DisableMouseCapture
                            )?;
                            let _ = Command::new("nmtui").status();
                            enable_raw_mode()?;
                            execute!(
                                terminal.backend_mut(),
                                EnterAlternateScreen,
                                EnableMouseCapture
                            )?;
                            terminal.clear()?;
                            ifaces = fetch_interfaces();
                            wifi_devs = fetch_wifi_devices();
                        }
                        KeyCode::Char('s') => match scan_subnet(None) {
                            Ok(res) => {
                                scan_results = res;
                                current_tab = 1;
                                status_msg = "Subnet scan complete.".to_string();
                                is_error = false;
                            }
                            Err(e) => {
                                status_msg = format!("Scan failed: {}", e);
                                is_error = true;
                            }
                        },
                        KeyCode::Char('l') if current_tab == 2 => {
                            disable_raw_mode()?;
                            execute!(
                                terminal.backend_mut(),
                                LeaveAlternateScreen,
                                DisableMouseCapture
                            )?;
                            println!("Listening on port 9999 for incoming raw disk stream...");
                            let _ = Command::new("dfnet").args(["receive"]).status();
                            enable_raw_mode()?;
                            execute!(
                                terminal.backend_mut(),
                                EnterAlternateScreen,
                                EnableMouseCapture
                            )?;
                            terminal.clear()?;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Mac { iface }) => {
            let res = spoof_mac(&iface)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Restore { iface }) => {
            let res = restore_mac(&iface)?;
            println!("[✓] {}", res);
        }
        Some(Commands::Scan { iface }) => {
            let res = scan_subnet(iface.as_deref())?;
            println!("{}", res);
        }
        Some(Commands::Smb { remote, name, user }) => {
            let target = format!("/media/target/smb_{}", name);
            let _ = std::fs::create_dir_all(&target);
            let user_arg = format!(
                "username={},ro,noatime",
                user.unwrap_or_else(|| "guest".to_string())
            );
            let status = Command::new("mount.cifs")
                .args([&remote, &target, "-o", &user_arg])
                .status()?;
            if status.success() {
                println!("[✓] Mounted SMB share {} at {}", remote, target);
            } else {
                anyhow::bail!("Failed to mount SMB share");
            }
        }
        Some(Commands::Nfs { remote, name }) => {
            let target = format!("/media/target/nfs_{}", name);
            let _ = std::fs::create_dir_all(&target);
            let status = Command::new("mount")
                .args(["-t", "nfs", "-o", "ro,nolock,noatime", &remote, &target])
                .status()?;
            if status.success() {
                println!("[✓] Mounted NFS export {} at {}", remote, target);
            } else {
                anyhow::bail!("Failed to mount NFS export");
            }
        }
        Some(Commands::Receive { port, out }) => {
            let p = port.unwrap_or(9999).to_string();
            let outfile = out.unwrap_or_else(|| "/media/target/network_stream.raw".to_string());
            println!("[*] Listening on port {} -> {}", p, outfile);
            let mut nc = Command::new("nc")
                .args(["-l", &p])
                .stdout(Stdio::piped())
                .spawn()?;

            if let Some(stdout) = nc.stdout.take() {
                let mut pv = Command::new("pv")
                    .stdin(stdout)
                    .stdout(std::fs::File::create(&outfile)?)
                    .spawn()?;
                let _ = pv.wait();
            }
            let _ = nc.wait();
            println!("[✓] Stream acquisition complete. Saved to {}", outfile);
        }
        Some(Commands::Hotspot { action }) => match action.unwrap_or(HotspotAction::Status) {
            HotspotAction::Start {
                iface,
                ssid,
                password,
            } => {
                let dev = iface.or_else(|| fetch_wifi_devices().into_iter().next().map(|d| d.name));
                match dev {
                    Some(i) => {
                        let res = start_hotspot(&i, &ssid, &password)?;
                        println!("[✓] {}", res);
                    }
                    None => {
                        anyhow::bail!("No Wi-Fi adapter found on this system.");
                    }
                }
            }
            HotspotAction::Stop { iface } => {
                let res = stop_hotspot(iface.as_deref())?;
                println!("[✓] {}", res);
            }
            HotspotAction::Status => {
                let devs = fetch_wifi_devices();
                if devs.is_empty() {
                    println!("[-] No Wi-Fi hardware interfaces detected.");
                } else {
                    println!("[*] Detected Wi-Fi interfaces:");
                    for d in &devs {
                        let (active, ip, ssid) = is_hotspot_active(Some(&d.name));
                        let state_str = if active {
                            format!(
                                "ACTIVE (SSID: {}, IP: {})",
                                ssid.unwrap_or_default(),
                                ip.unwrap_or_default()
                            )
                        } else {
                            "INACTIVE".to_string()
                        };
                        println!(
                            "    - {} (State: {}, Hotspot: {})",
                            d.name, d.state, state_str
                        );
                    }
                }
            }
        },
        None => {
            run_tui()?;
        }
    }

    Ok(())
}
