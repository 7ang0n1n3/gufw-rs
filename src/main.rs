use eframe::{egui, App, Frame};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(PartialEq)]
enum Tab {
    Simple,
    Preconfigured,
    Advanced,
}

#[derive(Clone)]
struct UfwStatus {
    enabled: bool,
    rules: Vec<String>,
    error: Option<String>,
    default_incoming: String,
    default_outgoing: String,
}

#[derive(Clone)]
struct AdvancedRule {
    action: String,
    direction: String,
    protocol: String,
    port: String,
    source: String,
    destination: String,
    log: bool,
    comment: String,
}

struct GufwApp {
    ufw_status: Arc<Mutex<UfwStatus>>,
    selected_tab: Tab,
    selected_rule: Option<usize>,
    show_add_dialog: bool,
    add_action: String,
    add_port: String,
    add_protocol: String,
    show_remove_dialog: bool,
    remove_index: Option<usize>,
    authenticated: bool,
    // Advanced tab fields
    show_advanced_dialog: bool,
    advanced_rule: AdvancedRule,
    show_import_dialog: bool,
    import_text: String,
    show_export_dialog: bool,
    export_text: String,
    // Edit dialog fields
    show_edit_dialog: bool,
    edit_action: String,
    edit_port: String,
    edit_protocol: String,
    edit_rule_index: Option<usize>,
    // Policy dialog fields
    show_policy_dialog: bool,
    policy_incoming: String,
    policy_outgoing: String,
}

impl Default for GufwApp {
    fn default() -> Self {
        let ufw_status = Arc::new(Mutex::new(UfwStatus {
            enabled: false,
            rules: vec![],
            error: Some("Initializing...".to_string()),
            default_incoming: "deny".to_string(),
            default_outgoing: "allow".to_string(),
        }));
        Self {
            ufw_status: ufw_status.clone(),
            selected_tab: Tab::Simple,
            selected_rule: None,
            show_add_dialog: false,
            add_action: "Allow".to_string(),
            add_port: String::new(),
            add_protocol: "tcp".to_string(),
            show_remove_dialog: false,
            remove_index: None,
            authenticated: false,
            show_advanced_dialog: false,
            advanced_rule: AdvancedRule {
                action: "allow".to_string(),
                direction: "in".to_string(),
                protocol: "tcp".to_string(),
                port: String::new(),
                source: "any".to_string(),
                destination: "any".to_string(),
                log: false,
                comment: String::new(),
            },
            show_import_dialog: false,
            import_text: String::new(),
            show_export_dialog: false,
            export_text: String::new(),
            show_edit_dialog: false,
            edit_action: String::new(),
            edit_port: String::new(),
            edit_protocol: String::new(),
            edit_rule_index: None,
            show_policy_dialog: false,
            policy_incoming: "deny".to_string(),
            policy_outgoing: "allow".to_string(),
        }
    }
}

impl GufwApp {
    fn authenticate_once(&mut self) {
        if !self.authenticated {
            // Try to authenticate using sudo with timestamp
            let auth_result = Command::new("sudo")
                .arg("-n")
                .arg("true")
                .output();
            
            match auth_result {
                Ok(output) if output.status.success() => {
                    // Already authenticated
                    self.authenticated = true;
                    // Get initial status
                    self.spawn_status_thread();
                }
                _ => {
                    // Need to authenticate - use pkexec for the first time
                    let auth_result = Command::new("pkexec")
                        .arg("true")
                        .output();
                    
                    match auth_result {
                        Ok(output) if output.status.success() => {
                            self.authenticated = true;
                            // Now try to get initial status
                            self.spawn_status_thread();
                        }
                        _ => {
                            let mut status = self.ufw_status.lock().unwrap();
                            status.error = Some("Authentication failed. Please try again.".to_string());
                        }
                    }
                }
            }
        }
    }

    fn run_privileged_command(&self, args: &[&str]) -> Result<String, String> {
        if !self.authenticated {
            return Err("Not authenticated".to_string());
        }

        // Try sudo first (should work if already authenticated)
        let sudo_result = Command::new("sudo")
            .arg("-n")
            .arg("ufw")
            .args(args)
            .output();

        match sudo_result {
            Ok(output) if output.status.success() => {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            }
            _ => {
                // Fallback to pkexec if sudo fails
                let pkexec_result = Command::new("pkexec")
                    .arg("ufw")
                    .args(args)
                    .output();

                match pkexec_result {
                    Ok(output) if output.status.success() => {
                        Ok(String::from_utf8_lossy(&output.stdout).to_string())
                    }
                    Ok(output) => {
                        Err(format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)))
                    }
                    Err(e) => {
                        Err(format!("Failed to run command: {}", e))
                    }
                }
            }
        }
    }

    fn spawn_status_thread(&self) {
        let ufw_status = self.ufw_status.clone();
        let authenticated = self.authenticated;
        thread::spawn(move || {
            if !authenticated {
                let mut status = ufw_status.lock().unwrap();
                status.error = Some("Not authenticated".to_string());
                return;
            }

            let result = get_ufw_status_and_rules();
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok((enabled, rules, default_incoming, default_outgoing)) => {
                    status.enabled = enabled;
                    status.rules = rules;
                    status.default_incoming = default_incoming;
                    status.default_outgoing = default_outgoing;
                    status.error = None;
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn refresh_status(&mut self) {
        if self.authenticated {
            self.spawn_status_thread();
        }
    }

    fn set_ufw_enabled(&mut self, enable: bool) {
        if !self.authenticated {
            return;
        }

        let cmd = if enable { "enable" } else { "disable" };
        let ufw_status = self.ufw_status.clone();
        
        thread::spawn(move || {
            let result = run_privileged_ufw_command(&[cmd]);
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok(_) => {
                    // Refresh status after operation
                    thread::sleep(Duration::from_millis(500));
                    let refresh_result = get_ufw_status_and_rules();
                    match refresh_result {
                        Ok((enabled, rules, default_incoming, default_outgoing)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn add_rule(&mut self, action: &str, port: &str, protocol: &str) {
        if !self.authenticated {
            return;
        }

        let cmd = if action.to_lowercase() == "allow" { "allow" } else { "deny" };
        let rule = format!("{}/{}", port, protocol);
        let ufw_status = self.ufw_status.clone();
        
        thread::spawn(move || {
            let result = run_privileged_ufw_command(&[cmd, &rule]);
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok(_) => {
                    // Refresh status after operation
                    thread::sleep(Duration::from_millis(500));
                    let refresh_result = get_ufw_status_and_rules();
                    match refresh_result {
                        Ok((enabled, rules, default_incoming, default_outgoing)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn remove_rule(&mut self, rule_str: &str) {
        if !self.authenticated {
            return;
        }

        let parts: Vec<&str> = rule_str.split_whitespace().collect();
        if parts.len() < 2 {
            let mut status = self.ufw_status.lock().unwrap();
            status.error = Some("Could not parse rule for removal".to_string());
            return;
        }
        let port_proto = parts[0];
        let action = parts[1].to_lowercase();
        let cmd = format!("delete {} {}", action, port_proto);
        let ufw_status = self.ufw_status.clone();
        
        thread::spawn(move || {
            let result = run_privileged_ufw_command(&cmd.split_whitespace().collect::<Vec<&str>>());
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok(_) => {
                    // Refresh status after operation
                    thread::sleep(Duration::from_millis(500));
                    let refresh_result = get_ufw_status_and_rules();
                    match refresh_result {
                        Ok((enabled, rules, default_incoming, default_outgoing)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn add_advanced_rule(&mut self, rule: &AdvancedRule) {
        if !self.authenticated {
            return;
        }

        let mut cmd_parts = vec![rule.action.clone()];
        
        // Add direction
        if rule.direction != "any" {
            cmd_parts.push(rule.direction.clone());
        }
        
        // Add protocol
        if rule.protocol != "any" {
            cmd_parts.push(rule.protocol.clone());
        }
        
        // Add port if specified
        if !rule.port.is_empty() {
            cmd_parts.push(rule.port.clone());
        }
        
        // Add source
        if rule.source != "any" {
            cmd_parts.push("from".to_string());
            cmd_parts.push(rule.source.clone());
        }
        
        // Add destination
        if rule.destination != "any" {
            cmd_parts.push("to".to_string());
            cmd_parts.push(rule.destination.clone());
        }
        
        // Add logging
        if rule.log {
            cmd_parts.push("log".to_string());
        }
        
        // Add comment if specified
        if !rule.comment.is_empty() {
            cmd_parts.push("comment".to_string());
            cmd_parts.push(rule.comment.clone());
        }

        let ufw_status = self.ufw_status.clone();
        let cmd_parts_clone = cmd_parts.clone();
        
        thread::spawn(move || {
            let result = run_privileged_ufw_command(&cmd_parts_clone.iter().map(|s| s.as_str()).collect::<Vec<&str>>());
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok(_) => {
                    // Refresh status after operation
                    thread::sleep(Duration::from_millis(500));
                    let refresh_result = get_ufw_status_and_rules();
                    match refresh_result {
                        Ok((enabled, rules, default_incoming, default_outgoing)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn export_rules(&self) -> String {
        if !self.authenticated {
            return "Not authenticated".to_string();
        }

        match run_privileged_ufw_command(&["status", "numbered"]) {
            Ok(output) => output,
            Err(e) => format!("Failed to export rules: {}", e),
        }
    }

    fn import_rules(&mut self, rules_text: &str) {
        if !self.authenticated {
            return;
        }

        let ufw_status = self.ufw_status.clone();
        let rules_text = rules_text.to_string();
        
        thread::spawn(move || {
            // Parse and import rules
            for line in rules_text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                
                // Simple rule parsing - in a real implementation, you'd want more robust parsing
                if line.starts_with("ufw") {
                    let cmd = line.strip_prefix("ufw ").unwrap_or(line);
                    let _ = run_privileged_ufw_command(&cmd.split_whitespace().collect::<Vec<&str>>());
                }
            }
            
            // Refresh status after import
            thread::sleep(Duration::from_millis(1000));
            let refresh_result = get_ufw_status_and_rules();
            let mut status = ufw_status.lock().unwrap();
            match refresh_result {
                Ok((enabled, rules, default_incoming, default_outgoing)) => {
                    status.enabled = enabled;
                    status.rules = rules;
                    status.default_incoming = default_incoming;
                    status.default_outgoing = default_outgoing;
                    status.error = None;
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn parse_rule(&self, rule_str: &str) -> Option<(String, String, String)> {
        // Parse rule string like "22/tcp                   ALLOW       Anywhere"
        let parts: Vec<&str> = rule_str.split_whitespace().collect();
        if parts.len() >= 2 {
            let port_proto = parts[0]; // e.g., "22/tcp"
            let action = parts[1].to_lowercase(); // e.g., "ALLOW" -> "allow"
            
            let port_proto_parts: Vec<&str> = port_proto.split('/').collect();
            if port_proto_parts.len() == 2 {
                let port = port_proto_parts[0].to_string();
                let protocol = port_proto_parts[1].to_string();
                return Some((action, port, protocol));
            }
        }
        None
    }

    fn parse_ufw_rule_line(&self, line: &str) -> (String, String, String) {
        // UFW columns: To (22 chars), Action (10 chars), From (rest)
        let to = line.get(0..22).unwrap_or("").trim().to_string();
        let action = line.get(22..32).unwrap_or("").trim().to_string();
        let from = line.get(32..).unwrap_or("").trim().to_string();
        (to, action, from)
    }

    fn parse_rule_for_display(&self, rule: &str) -> (String, String, String, String) {
        let (to, action, from) = self.parse_ufw_rule_line(rule);
        // For compatibility with previous UI, map columns:
        // Port/Protocol = to, Action = action, Direction = "ANY", Source = from
        (to, action, "ANY".to_string(), from)
    }

    fn edit_rule(&mut self, rule_index: usize, new_action: &str, new_port: &str, new_protocol: &str) {
        if !self.authenticated {
            return;
        }

        let ufw_status = self.ufw_status.clone();
        let rules = {
            let status = self.ufw_status.lock().unwrap();
            status.rules.clone()
        };
        
        if rule_index >= rules.len() {
            return;
        }

        let old_rule = &rules[rule_index];
        
        // Parse the old rule to get its components
        if let Some((old_action, old_port, old_protocol)) = self.parse_rule(old_rule) {
            // Remove the old rule
            let old_cmd = format!("delete {} {}/{}", old_action, old_port, old_protocol);
            
            // Add the new rule
            let new_cmd = if new_action.to_lowercase() == "allow" { "allow" } else { "deny" };
            let new_rule = format!("{}/{}", new_port, new_protocol);
            
            thread::spawn(move || {
                // First remove the old rule
                let _ = run_privileged_ufw_command(&old_cmd.split_whitespace().collect::<Vec<&str>>());
                
                // Then add the new rule
                let _ = run_privileged_ufw_command(&[new_cmd, &new_rule]);
                
                // Refresh status after operation
                thread::sleep(Duration::from_millis(500));
                let refresh_result = get_ufw_status_and_rules();
                let mut status = ufw_status.lock().unwrap();
                match refresh_result {
                    Ok((enabled, rules, default_incoming, default_outgoing)) => {
                        status.enabled = enabled;
                        status.rules = rules;
                        status.default_incoming = default_incoming;
                        status.default_outgoing = default_outgoing;
                        status.error = None;
                    }
                    Err(e) => {
                        status.error = Some(e);
                    }
                }
            });
        }
    }

    fn get_default_policies(&mut self) {
        if !self.authenticated {
            return;
        }

        let ufw_status = self.ufw_status.clone();
        thread::spawn(move || {
            // Use "status verbose" to get default policies
            let result = run_privileged_ufw_command(&["status", "verbose"]);
            let mut status = ufw_status.lock().unwrap();
            match result {
                Ok(output) => {
                    // Parse the default policies from output
                    let mut incoming = "deny".to_string();
                    let mut outgoing = "allow".to_string();
                    for line in output.lines() {
                        if line.contains("Default incoming policy") {
                            if line.contains("allow") {
                                incoming = "allow".to_string();
                            } else if line.contains("deny") {
                                incoming = "deny".to_string();
                            }
                        } else if line.contains("Default outgoing policy") {
                            if line.contains("allow") {
                                outgoing = "allow".to_string();
                            } else if line.contains("deny") {
                                outgoing = "deny".to_string();
                            }
                        }
                    }
                    status.default_incoming = incoming;
                    status.default_outgoing = outgoing;
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        });
    }

    fn set_default_policies(&mut self, incoming: &str, outgoing: &str) {
        if !self.authenticated {
            return;
        }

        let ufw_status = self.ufw_status.clone();
        let incoming = incoming.to_string();
        let outgoing = outgoing.to_string();
        
        thread::spawn(move || {
            // Set incoming policy
            let _ = run_privileged_ufw_command(&["default", "incoming", &incoming]);
            
            // Set outgoing policy
            let _ = run_privileged_ufw_command(&["default", "outgoing", &outgoing]);
            
            // Update the status
            let mut status = ufw_status.lock().unwrap();
            status.default_incoming = incoming;
            status.default_outgoing = outgoing;
        });
    }
}

fn run_privileged_ufw_command(args: &[&str]) -> Result<String, String> {
    // Try sudo first (should work if already authenticated)
    let sudo_result = Command::new("sudo")
        .arg("-n")
        .arg("ufw")
        .args(args)
        .output();

    match sudo_result {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
        _ => {
            // Fallback to pkexec if sudo fails
            let pkexec_result = Command::new("pkexec")
                .arg("ufw")
                .args(args)
                .output();

            match pkexec_result {
                Ok(output) if output.status.success() => {
                    Ok(String::from_utf8_lossy(&output.stdout).to_string())
                }
                Ok(output) => {
                    Err(format!("Command failed: {}", String::from_utf8_lossy(&output.stderr)))
                }
                Err(e) => {
                    Err(format!("Failed to run command: {}", e))
                }
            }
        }
    }
}

fn get_ufw_status_and_rules() -> Result<(bool, Vec<String>, String, String), String> {
    let output = run_privileged_ufw_command(&["status"])?;
    let mut enabled = false;
    let mut rules = Vec::new();
    let mut default_incoming = "deny".to_string();
    let mut default_outgoing = "allow".to_string();
    
    for line in output.lines() {
        if line.contains("Status: active") {
            enabled = true;
        }
        if line.contains("Status: inactive") {
            enabled = false;
        }
        // Parse default policies
        if line.contains("Default incoming policy") {
            if line.contains("allow") {
                default_incoming = "allow".to_string();
            } else if line.contains("deny") {
                default_incoming = "deny".to_string();
            }
        } else if line.contains("Default outgoing policy") {
            if line.contains("allow") {
                default_outgoing = "allow".to_string();
            } else if line.contains("deny") {
                default_outgoing = "deny".to_string();
            }
        }
        // Parse rules (skip header lines and separators)
        if line.starts_with("To") || line.starts_with("---") || line.starts_with("Status:") || line.trim().is_empty() || line.chars().all(|c| c == '-' || c.is_whitespace()) {
            continue;
        }
        if enabled && !line.contains("Status:") && !line.trim().is_empty() {
            rules.push(line.trim().to_string());
        }
    }
    Ok((enabled, rules, default_incoming, default_outgoing))
}

impl App for GufwApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Authenticate once at startup
        if !self.authenticated {
            self.authenticate_once();
        }

        // F5 to refresh
        if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
            self.refresh_status();
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("gufw-rs - Firewall Configuration");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Quit").on_hover_text("Exit application").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });

        egui::SidePanel::left("sidebar").min_width(200.0).show(ctx, |ui| {
            let (enabled, error) = {
                let status = self.ufw_status.lock().unwrap();
                (status.enabled, status.error.clone())
            };
            ui.heading("Status");
            ui.add_space(8.0);
            
            if !self.authenticated {
                ui.colored_label(egui::Color32::YELLOW, "⚠️ Authentication required");
                if ui.button("Authenticate").clicked() {
                    self.authenticate_once();
                }
            } else {
                            ui.horizontal(|ui| {
                let icon = if enabled { "🔒" } else { "🔓" };
                ui.label(icon);
                let mut toggle = enabled;
                if ui.checkbox(&mut toggle, "Firewall enabled").on_hover_text("Toggle firewall").changed() {
                    if toggle != enabled {
                        self.set_ufw_enabled(toggle);
                    }
                }
            });
            ui.add_space(4.0);
            if enabled {
                ui.colored_label(egui::Color32::from_rgb(0, 200, 0), "Enabled");
            } else {
                ui.colored_label(egui::Color32::from_rgb(200, 0, 0), "Disabled");
            }
            }
            
            if let Some(error) = &error {
                ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
            }
            ui.separator();
            ui.label("Default Policy:");
            let (default_incoming, default_outgoing) = {
                let status = self.ufw_status.lock().unwrap();
                (status.default_incoming.clone(), status.default_outgoing.clone())
            };
            ui.horizontal(|ui| {
                ui.label("Incoming:");
                ui.strong(&default_incoming);
            });
            ui.horizontal(|ui| {
                ui.label("Outgoing:");
                ui.strong(&default_outgoing);
            });
            if ui.button("Edit Policies").clicked() {
                self.policy_incoming = default_incoming.clone();
                self.policy_outgoing = default_outgoing.clone();
                self.show_policy_dialog = true;
            }
            ui.add_space(16.0);
            ui.label("Version: 0.3.0");
            ui.label("by 7ANG0N1N3");
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let rules = {
                let status = self.ufw_status.lock().unwrap();
                status.rules.clone()
            };
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let mut tab_button = |ui: &mut egui::Ui, tab: Tab, label: &str, icon: &str, tooltip: &str| {
                    let selected = self.selected_tab == tab;
                    let resp = ui.add_sized([
                        120.0, 28.0
                    ], egui::SelectableLabel::new(selected, format!("{} {}", icon, label))).on_hover_text(tooltip);
                    if resp.clicked() {
                        self.selected_tab = tab;
                    }
                };
                tab_button(ui, Tab::Simple, "Simple", "⚡", "Add simple rules");
                tab_button(ui, Tab::Preconfigured, "Preconfigured", "🛠", "Add rules for common services");
                tab_button(ui, Tab::Advanced, "Advanced", "⚙", "Add advanced rules");
            });
            ui.separator();
            ui.add_space(8.0);
            
            match self.selected_tab {
                Tab::Simple => {
                    let rules = {
                        let status = self.ufw_status.lock().unwrap();
                        status.rules.clone()
                    };
                    if rules.is_empty() {
                        ui.label("Loading rules...");
                        return;
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Simple Rules");
                        ui.add_space(4.0);
                        egui::Grid::new("rules_grid").striped(true).show(ui, |ui| {
                            ui.label(egui::RichText::new("Port/Protocol").strong());
                            ui.label(egui::RichText::new("Action").strong());
                            ui.label(egui::RichText::new("Direction").strong());
                            ui.label(egui::RichText::new("Source").strong());
                            ui.label(egui::RichText::new("Actions").strong());
                            ui.end_row();
                            for (i, rule) in rules.iter().enumerate() {
                                // Parse rule for display
                                let (port_proto, action, direction, source) = self.parse_rule_for_display(rule);
                                
                                ui.label(port_proto);
                                ui.label(action);
                                ui.label(direction);
                                ui.label(source);
                                ui.horizontal(|ui| {
                                    if ui.add(egui::Button::new("Edit").fill(egui::Color32::from_rgb(60, 120, 180))).on_hover_text("Edit this rule").clicked() {
                                        if let Some((action, port, protocol)) = self.parse_rule(rule) {
                                            self.edit_action = action;
                                            self.edit_port = port;
                                            self.edit_protocol = protocol;
                                            self.edit_rule_index = Some(i);
                                            self.show_edit_dialog = true;
                                        }
                                    }
                                    if ui.add(egui::Button::new("Remove").fill(egui::Color32::from_rgb(220, 60, 60))).on_hover_text("Remove this rule").clicked() {
                                        self.show_remove_dialog = true;
                                        self.remove_index = Some(i);
                                    }
                                });
                                ui.end_row();
                            }
                        });
                        ui.add_space(8.0);
                        if ui.add(egui::Button::new("Add Rule").fill(egui::Color32::from_rgb(60, 180, 60))).on_hover_text("Add a new rule").clicked() {
                            self.show_add_dialog = true;
                        }
                    });
                }
                Tab::Preconfigured => {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Preconfigured Rules");
                        ui.label("Click on a service to add a rule for it:");
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("Services:");
                            if ui.button("SSH (22)").clicked() {
                                self.add_rule("Allow", "22", "tcp");
                            }
                            if ui.button("HTTP (80)").clicked() {
                                self.add_rule("Allow", "80", "tcp");
                            }
                            if ui.button("HTTPS (443)").clicked() {
                                self.add_rule("Allow", "443", "tcp");
                            }
                            if ui.button("FTP (21)").clicked() {
                                self.add_rule("Allow", "21", "tcp");
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("DNS (53)").clicked() {
                                self.add_rule("Allow", "53", "udp");
                            }
                            if ui.button("SMTP (25)").clicked() {
                                self.add_rule("Allow", "25", "tcp");
                            }
                            if ui.button("POP3 (110)").clicked() {
                                self.add_rule("Allow", "110", "tcp");
                            }
                            if ui.button("IMAP (143)").clicked() {
                                self.add_rule("Allow", "143", "tcp");
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("MySQL (3306)").clicked() {
                                self.add_rule("Allow", "3306", "tcp");
                            }
                            if ui.button("PostgreSQL (5432)").clicked() {
                                self.add_rule("Allow", "5432", "tcp");
                            }
                            if ui.button("Redis (6379)").clicked() {
                                self.add_rule("Allow", "6379", "tcp");
                            }
                            if ui.button("MongoDB (27017)").clicked() {
                                self.add_rule("Allow", "27017", "tcp");
                            }
                        });
                    });
                }
                Tab::Advanced => {
                    let rules = {
                        let status = self.ufw_status.lock().unwrap();
                        status.rules.clone()
                    };
                    if rules.is_empty() {
                        ui.label("Loading rules...");
                        return;
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Advanced Rules");
                        ui.add_space(4.0);
                        // Advanced rule controls
                        ui.horizontal(|ui| {
                            if ui.add(egui::Button::new("Add Advanced Rule").fill(egui::Color32::from_rgb(60, 180, 60))).clicked() {
                                self.show_advanced_dialog = true;
                            }
                            if ui.add(egui::Button::new("Export Rules").fill(egui::Color32::from_rgb(60, 120, 180))).clicked() {
                                self.export_text = self.export_rules();
                                self.show_export_dialog = true;
                            }
                            if ui.add(egui::Button::new("Import Rules").fill(egui::Color32::from_rgb(180, 120, 60))).clicked() {
                                self.show_import_dialog = true;
                            }
                        });
                        ui.add_space(8.0);
                        // Show current rules in advanced format
                        egui::Grid::new("advanced_rules_grid").striped(true).show(ui, |ui| {
                            ui.label(egui::RichText::new("Port/Protocol").strong());
                            ui.label(egui::RichText::new("Action").strong());
                            ui.label(egui::RichText::new("Direction").strong());
                            ui.label(egui::RichText::new("Source").strong());
                            ui.label(egui::RichText::new("Log").strong());
                            ui.label(egui::RichText::new("Actions").strong());
                            ui.end_row();
                            for (i, rule) in rules.iter().enumerate() {
                                let (port_proto, action, direction, source) = self.parse_rule_for_display(rule);
                                let log = if rule.to_lowercase().contains("log") { "Yes" } else { "No" };
                                ui.label(port_proto);
                                ui.label(action);
                                ui.label(direction);
                                ui.label(source);
                                ui.label(log);
                                ui.horizontal(|ui| {
                                    if ui.add(egui::Button::new("Remove").fill(egui::Color32::from_rgb(220, 60, 60))).clicked() {
                                        self.show_remove_dialog = true;
                                        self.remove_index = Some(i);
                                    }
                                });
                                ui.end_row();
                            }
                        });
                    });
                }
            }
        });

        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.label("gufw-rs © 2025 by 7ANG0N1N3 | Inspired by GUFW | ");
                ui.hyperlink("https://github.com/costales/gufw");
            });
        });

        // Add Rule Dialog
        if self.show_add_dialog {
            let mut add_clicked = false;
            let mut add_action = self.add_action.clone();
            let mut add_port = self.add_port.clone();
            let mut add_protocol = self.add_protocol.clone();
            let mut rule_to_add: Option<(String, String, String)> = None;
            egui::Window::new("Add Rule")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        egui::ComboBox::new("action_combo", "")
                            .selected_text(&add_action)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut add_action, "Allow".to_string(), "Allow");
                                ui.selectable_value(&mut add_action, "Deny".to_string(), "Deny");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut add_port);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Protocol:");
                        egui::ComboBox::new("proto_combo", "")
                            .selected_text(&add_protocol)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut add_protocol, "tcp".to_string(), "tcp");
                                ui.selectable_value(&mut add_protocol, "udp".to_string(), "udp");
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked() {
                            if !add_port.trim().is_empty() {
                                add_clicked = true;
                                self.show_add_dialog = false;
                                rule_to_add = Some((add_action.clone(), add_port.clone(), add_protocol.clone()));
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_add_dialog = false;
                        }
                    });
                });
            if add_clicked {
                self.add_action = add_action;
                self.add_port = String::new();
                self.add_protocol = add_protocol;
            } else {
                self.add_action = add_action;
                self.add_port = add_port;
                self.add_protocol = add_protocol;
            }
            if let Some((action, port, protocol)) = rule_to_add {
                self.add_rule(&action, &port, &protocol);
            }
        }

        // Remove Rule Dialog
        if self.show_remove_dialog {
            let rules = {
                let status = self.ufw_status.lock().unwrap();
                status.rules.clone()
            };
            egui::Window::new("Remove Rule?")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Are you sure you want to remove this rule?");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Remove").clicked() {
                            if let Some(idx) = self.remove_index {
                                if idx < rules.len() {
                                    let rule_str = rules[idx].clone();
                                    self.remove_rule(&rule_str);
                                }
                            }
                            self.show_remove_dialog = false;
                            self.remove_index = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_remove_dialog = false;
                            self.remove_index = None;
                        }
                    });
                });
        }

        // Advanced Rule Dialog
        if self.show_advanced_dialog {
            let mut add_clicked = false;
            let mut advanced_rule = self.advanced_rule.clone();
            egui::Window::new("Add Advanced Rule")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        egui::ComboBox::new("advanced_action_combo", "")
                            .selected_text(&advanced_rule.action)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut advanced_rule.action, "allow".to_string(), "Allow");
                                ui.selectable_value(&mut advanced_rule.action, "deny".to_string(), "Deny");
                                ui.selectable_value(&mut advanced_rule.action, "reject".to_string(), "Reject");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Direction:");
                        egui::ComboBox::new("direction_combo", "")
                            .selected_text(&advanced_rule.direction)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut advanced_rule.direction, "in".to_string(), "Incoming");
                                ui.selectable_value(&mut advanced_rule.direction, "out".to_string(), "Outgoing");
                                ui.selectable_value(&mut advanced_rule.direction, "any".to_string(), "Any");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Protocol:");
                        egui::ComboBox::new("advanced_proto_combo", "")
                            .selected_text(&advanced_rule.protocol)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut advanced_rule.protocol, "tcp".to_string(), "TCP");
                                ui.selectable_value(&mut advanced_rule.protocol, "udp".to_string(), "UDP");
                                ui.selectable_value(&mut advanced_rule.protocol, "any".to_string(), "Any");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut advanced_rule.port);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Source:");
                        ui.text_edit_singleline(&mut advanced_rule.source);
                        ui.label("(e.g., 192.168.1.0/24, any)");
                    });
                    ui.horizontal(|ui| {
                        ui.label("Destination:");
                        ui.text_edit_singleline(&mut advanced_rule.destination);
                        ui.label("(e.g., 192.168.1.100, any)");
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut advanced_rule.log, "Log connections");
                    });
                    ui.horizontal(|ui| {
                        ui.label("Comment:");
                        ui.text_edit_singleline(&mut advanced_rule.comment);
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked() {
                            add_clicked = true;
                            self.show_advanced_dialog = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_advanced_dialog = false;
                        }
                    });
                });
            if add_clicked {
                self.add_advanced_rule(&advanced_rule);
            } else {
                self.advanced_rule = advanced_rule;
            }
        }

        // Import Rules Dialog
        if self.show_import_dialog {
            let mut import_clicked = false;
            let mut import_text = self.import_text.clone();
            egui::Window::new("Import Rules")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label("Paste UFW rules (one per line):");
                    ui.add_space(4.0);
                    ui.text_edit_multiline(&mut import_text);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Import").clicked() {
                            import_clicked = true;
                            self.show_import_dialog = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_import_dialog = false;
                        }
                    });
                });
            if import_clicked {
                self.import_rules(&import_text);
            } else {
                self.import_text = import_text;
            }
        }

        // Export Rules Dialog
        if self.show_export_dialog {
            let mut export_text = self.export_text.clone();
            egui::Window::new("Export Rules")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.label("Current UFW rules (copy these to save):");
                    ui.add_space(4.0);
                    ui.text_edit_multiline(&mut export_text);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Copy to Clipboard").clicked() {
                            // Copy to clipboard using the modern API
                            ui.ctx().copy_text(export_text.clone());
                        }
                        if ui.button("Close").clicked() {
                            self.show_export_dialog = false;
                        }
                    });
                });
        }

        // Edit Rule Dialog
        if self.show_edit_dialog {
            let mut edit_clicked = false;
            let mut edit_action = self.edit_action.clone();
            let mut edit_port = self.edit_port.clone();
            let mut edit_protocol = self.edit_protocol.clone();
            let edit_rule_index = self.edit_rule_index;
            egui::Window::new("Edit Rule")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        egui::ComboBox::new("edit_action_combo", "")
                            .selected_text(&edit_action)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_action, "allow".to_string(), "Allow");
                                ui.selectable_value(&mut edit_action, "deny".to_string(), "Deny");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut edit_port);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Protocol:");
                        egui::ComboBox::new("edit_proto_combo", "")
                            .selected_text(&edit_protocol)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_protocol, "tcp".to_string(), "tcp");
                                ui.selectable_value(&mut edit_protocol, "udp".to_string(), "udp");
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            if !edit_port.trim().is_empty() {
                                edit_clicked = true;
                                self.show_edit_dialog = false;
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_edit_dialog = false;
                        }
                    });
                });
            if edit_clicked {
                self.edit_action = edit_action.clone();
                self.edit_port = edit_port.clone();
                self.edit_protocol = edit_protocol.clone();
                if let Some(rule_index) = edit_rule_index {
                    self.edit_rule(rule_index, &edit_action, &edit_port, &edit_protocol);
                }
            } else {
                self.edit_action = edit_action;
                self.edit_port = edit_port;
                self.edit_protocol = edit_protocol;
            }
        }

        // Policy Dialog
        if self.show_policy_dialog {
            let mut policy_clicked = false;
            let mut policy_incoming = self.policy_incoming.clone();
            let mut policy_outgoing = self.policy_outgoing.clone();
            egui::Window::new("Edit Default Policies")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Set the default policies for incoming and outgoing traffic:");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Incoming Policy:");
                        egui::ComboBox::new("incoming_policy_combo", "")
                            .selected_text(&policy_incoming)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut policy_incoming, "deny".to_string(), "Deny");
                                ui.selectable_value(&mut policy_incoming, "allow".to_string(), "Allow");
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Outgoing Policy:");
                        egui::ComboBox::new("outgoing_policy_combo", "")
                            .selected_text(&policy_outgoing)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut policy_outgoing, "allow".to_string(), "Allow");
                                ui.selectable_value(&mut policy_outgoing, "deny".to_string(), "Deny");
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            policy_clicked = true;
                            self.show_policy_dialog = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_policy_dialog = false;
                        }
                    });
                });
            if policy_clicked {
                self.policy_incoming = policy_incoming.clone();
                self.policy_outgoing = policy_outgoing.clone();
                self.set_default_policies(&policy_incoming, &policy_outgoing);
            } else {
                self.policy_incoming = policy_incoming;
                self.policy_outgoing = policy_outgoing;
            }
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "gufw-rs",
        options,
        Box::new(|cc| {
            // Set all font sizes to 25 points
            use egui::{FontFamily, FontId, TextStyle};
            let mut style = (*cc.egui_ctx.style()).clone();
            style.text_styles = [
                (TextStyle::Heading, FontId::new(25.0, FontFamily::Proportional)),
                (TextStyle::Body, FontId::new(25.0, FontFamily::Proportional)),
                (TextStyle::Monospace, FontId::new(25.0, FontFamily::Monospace)),
                (TextStyle::Button, FontId::new(25.0, FontFamily::Proportional)),
                (TextStyle::Small, FontId::new(25.0, FontFamily::Proportional)),
            ].into();
            cc.egui_ctx.set_style(style);
            Ok(Box::new(GufwApp::default()))
        }),
    )
}
