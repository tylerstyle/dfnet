use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Tabs},
    Terminal,
};
use std::{
    io,
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(name = "dfnet", version, about = "Modern Forensic Network Triage, Stealth MAC Cloaking & Stream Ingest TUI")]
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
    Smb { remote: String, name: String, user: Option<String> },
    /// Mount an on-premise NFS export read-only into /media/target/
    Nfs { remote: String, name: String },
    /// Listen on network port to receive raw streamed disk image
    Receive { port: Option<u16>, out: Option<String> },
}

#[derive(Debug, Clone)]
struct NetInterface {
    name: String,
    state: String,
    mac: String,
    ip: String,
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
                let ip = if parts.len() >= 3 { parts[2].to_string() } else { "-".to_string() };

                // Get MAC
                let link_out = Command::new("ip").args(["-br", "link", "show", &name]).output();
                let mac = if let Ok(lout) = link_out {
                    let ltext = String::from_utf8_lossy(&lout.stdout);
                    let lparts: Vec<&str> = ltext.split_whitespace().collect();
                    if lparts.len() >= 3 { lparts[2].to_string() } else { "-".to_string() }
                } else {
                    "-".to_string()
                };

                ifaces.push(NetInterface { name, state, mac, ip });
            }
        }
    }
    ifaces
}

fn spoof_mac(iface: &str) -> Result<String> {
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "down"]).status();
    let res = Command::new("macchanger").args(["-r", iface]).output();
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "up"]).status();

    if let Ok(out) = res {
        if out.status.success() {
            return Ok(format!("Randomized and cloaked MAC address on {}", iface));
        }
    }
    anyhow::bail!("Failed to spoof MAC on {}. Ensure macchanger is installed.", iface)
}

fn restore_mac(iface: &str) -> Result<String> {
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "down"]).status();
    let res = Command::new("macchanger").args(["-p", iface]).output();
    let _ = Command::new("ip").args(["link", "set", "dev", iface, "up"]).status();

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

fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut current_tab = 0;
    let tabs = vec!["Interfaces & MAC Cloaking", "Local Network Discovery", "Stream Receiver"];

    let mut ifaces = fetch_interfaces();
    let mut table_state = TableState::default();
    table_state.select(Some(0));

    let mut status_msg = String::from("Ready. Select interface with j/k or ↑/↓.");
    let mut is_error = false;
    let mut scan_results = String::from("Press [S] to run local ARP discovery scan.");

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

            // 1. Title
            let title = Paragraph::new(Line::from(vec![
                Span::styled(" dfnet ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("— Forensic Network Triage, Stealth Cloaking & Ingest TUI"),
            ]))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(title, chunks[0]);

            // 2. Tabs
            let tab_titles: Vec<Line> = tabs.iter().map(|t| Line::from(*t)).collect();
            let tabs_widget = Tabs::new(tab_titles)
                .select(current_tab)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)))
                .style(Style::default().fg(Color::Gray))
                .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
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
                _ => {
                    let stream_info = vec![
                        Line::from(vec![
                            Span::styled("Live Network Disk Stream Receiver", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        ]),
                        Line::from(""),
                        Line::from("Listens on TCP port 9999 and streams incoming raw disk stream to:"),
                        Line::from(Span::styled("  /media/target/network_stream.raw", Style::default().fg(Color::Yellow))),
                        Line::from(""),
                        Line::from("Remote Evidence Command:"),
                        Line::from(Span::styled("  sudo dd if=/dev/nvme0n1 bs=64K status=progress | nc <this-ip> 9999", Style::default().fg(Color::Green))),
                        Line::from(""),
                        Line::from("Press [L] to start listening now."),
                    ];
                    let p = Paragraph::new(stream_info)
                        .block(Block::default().borders(Borders::ALL).title(" Live Disk Receiver ").border_style(Style::default().fg(Color::DarkGray)));
                    f.render_widget(p, chunks[2]);
                }
            }

            // 4. Status Box
            let status_color = if is_error { Color::Red } else { Color::Green };
            let status_p = Paragraph::new(Line::from(vec![
                Span::styled(" >> ", Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                Span::styled(&status_msg, Style::default().fg(status_color)),
            ]))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(status_p, chunks[3]);

            // 5. Hotkeys Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" [Tab] ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("Next Tab  "),
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
                Span::raw("Quit "),
            ]));
            f.render_widget(footer, chunks[4]);
        })?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => {
                        current_tab = (current_tab + 1) % tabs.len();
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = match table_state.selected() {
                            Some(i) => if i > 0 { i - 1 } else { ifaces.len().saturating_sub(1) },
                            None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = match table_state.selected() {
                            Some(i) => if i < ifaces.len().saturating_sub(1) { i + 1 } else { 0 },
                            None => 0,
                        };
                        table_state.select(Some(i));
                    }
                    KeyCode::Char('r') => {
                        ifaces = fetch_interfaces();
                        status_msg = "Refreshed network interfaces.".to_string();
                        is_error = false;
                    }
                    KeyCode::Char('m') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(iface) = ifaces.get(idx) {
                                match spoof_mac(&iface.name) {
                                    Ok(msg) => { status_msg = msg; is_error = false; }
                                    Err(e) => { status_msg = e.to_string(); is_error = true; }
                                }
                                ifaces = fetch_interfaces();
                            }
                        }
                    }
                    KeyCode::Char('p') => {
                        if let Some(idx) = table_state.selected() {
                            if let Some(iface) = ifaces.get(idx) {
                                match restore_mac(&iface.name) {
                                    Ok(msg) => { status_msg = msg; is_error = false; }
                                    Err(e) => { status_msg = e.to_string(); is_error = true; }
                                }
                                ifaces = fetch_interfaces();
                            }
                        }
                    }
                    KeyCode::Char('n') => {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        let _ = Command::new("nmtui").status();
                        enable_raw_mode()?;
                        execute!(terminal.backend_mut(), EnterAlternateScreen)?;
                        terminal.clear()?;
                        ifaces = fetch_interfaces();
                    }
                    KeyCode::Char('s') => {
                        match scan_subnet(None) {
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
                        }
                    }
                    KeyCode::Char('l') => {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        println!("Listening on port 9999 for incoming raw disk stream...");
                        let _ = Command::new("dfnet").args(["receive"]).status();
                        enable_raw_mode()?;
                        execute!(terminal.backend_mut(), EnterAlternateScreen)?;
                        terminal.clear()?;
                    }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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
            let user_arg = format!("username={},ro,noatime", user.unwrap_or_else(|| "guest".to_string()));
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
                .args(["-l", "-p", &p])
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
        None => {
            run_tui()?;
        }
    }

    Ok(())
}
