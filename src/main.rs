use eframe::{egui, App, Frame};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
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
struct UfwRule {
    line_number: Option<usize>,
    raw: String,
}

#[derive(Clone)]
struct UfwStatus {
    enabled: bool,
    rules: Vec<UfwRule>,
    error: Option<String>,
    default_incoming: String,
    default_outgoing: String,
    app_profiles: Vec<String>,
}

#[derive(Clone)]
struct AdvancedRule {
    action: String,
    direction: String,
    protocol: String,
    port: String,
    source: String,
    destination: String,
    comment: String,
    log_option: String,
    interface_in: String,
    interface_out: String,
    is_route: bool,
    app_profile: String,
}

struct GufwApp {
    ufw_status: Arc<Mutex<UfwStatus>>,
    operation_in_progress: Arc<AtomicBool>,
    selected_tab: Tab,
    show_add_dialog: bool,
    add_action: String,
    add_port: String,
    add_protocol: String,
    authenticated: bool,
    // Advanced tab fields
    show_advanced_dialog: bool,
    advanced_rule: AdvancedRule,
    // Edit dialog fields (simple)
    show_edit_dialog: bool,
    edit_action: String,
    edit_port: String,
    edit_protocol: String,
    edit_rule_index: Option<usize>,
    // Advanced edit dialog fields
    show_advanced_edit_dialog: bool,
    advanced_edit_rule: AdvancedRule,
    advanced_edit_rule_number: Option<usize>,
    // Policy dialog fields
    show_policy_dialog: bool,
    policy_incoming: String,
    policy_outgoing: String,
    // Error dialog fields
    show_error_dialog: bool,
    current_error: String,
    // Help dialog fields
    show_about_dialog: bool,
}

impl Default for GufwApp {
    fn default() -> Self {
        let ufw_status = Arc::new(Mutex::new(UfwStatus {
            enabled: false,
            rules: vec![],
            error: Some("Initializing...".to_string()),
            default_incoming: "deny".to_string(),
            default_outgoing: "allow".to_string(),
            app_profiles: vec![],
        }));
        let operation_in_progress = Arc::new(AtomicBool::new(false));

        // Spawn authentication in background thread (#5 - off render thread)
        let ufw_status_clone = ufw_status.clone();
        let op_flag = operation_in_progress.clone();
        thread::spawn(move || {
            let authenticated = authenticate();
            if authenticated {
                op_flag.store(true, Ordering::SeqCst);
                let result = get_ufw_status_and_rules();
                if let Ok(mut status) = ufw_status_clone.lock() {
                    match result {
                        Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.app_profiles = app_profiles;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                op_flag.store(false, Ordering::SeqCst);
            } else if let Ok(mut status) = ufw_status_clone.lock() {
                status.error = Some("Authentication failed. Please try again.".to_string());
            }
        });

        Self {
            ufw_status,
            operation_in_progress,
            selected_tab: Tab::Simple,
            show_add_dialog: false,
            add_action: "allow".to_string(),
            add_port: String::new(),
            add_protocol: "tcp".to_string(),
            authenticated: false,
            show_advanced_dialog: false,
            advanced_rule: AdvancedRule {
                action: "allow".to_string(),
                direction: "in".to_string(),
                protocol: "tcp".to_string(),
                port: String::new(),
                source: "any".to_string(),
                destination: "any".to_string(),
                comment: String::new(),
                log_option: "none".to_string(),
                interface_in: String::new(),
                interface_out: String::new(),
                is_route: false,
                app_profile: String::new(),
            },
            show_edit_dialog: false,
            edit_action: String::new(),
            edit_port: String::new(),
            edit_protocol: String::new(),
            edit_rule_index: None,
            show_advanced_edit_dialog: false,
            advanced_edit_rule: AdvancedRule {
                action: "allow".to_string(),
                direction: "in".to_string(),
                protocol: "tcp".to_string(),
                port: String::new(),
                source: "any".to_string(),
                destination: "any".to_string(),
                comment: String::new(),
                log_option: "none".to_string(),
                interface_in: String::new(),
                interface_out: String::new(),
                is_route: false,
                app_profile: String::new(),
            },
            advanced_edit_rule_number: None,
            show_policy_dialog: false,
            policy_incoming: "deny".to_string(),
            policy_outgoing: "allow".to_string(),
            show_error_dialog: false,
            current_error: String::new(),
            show_about_dialog: false,
        }
    }
}

/// Authenticate via sudo or pkexec. Returns true on success.
fn authenticate() -> bool {
    // Try sudo -n first (already authenticated)
    if let Ok(output) = Command::new("sudo").arg("-n").arg("true").output()
        && output.status.success() {
            return true;
        }
    // Fall back to pkexec
    if let Ok(output) = Command::new("pkexec").arg("true").output()
        && output.status.success() {
            return true;
        }
    false
}

/// Validate a port string: must be a number (1-65535), a range like "8000:9000", or an alphanumeric service name.
fn validate_port(port: &str) -> Result<(), String> {
    let port = port.trim();
    if port.is_empty() {
        return Err("Port cannot be empty".to_string());
    }
    // Port range
    if port.contains(':') {
        let parts: Vec<&str> = port.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("Invalid port range format".to_string());
        }
        for p in &parts {
            let n: u16 = p
                .parse()
                .map_err(|_| format!("Invalid port number: {}", p))?;
            if n == 0 {
                return Err("Port must be between 1 and 65535".to_string());
            }
        }
        return Ok(());
    }
    // Single numeric port
    if let Ok(n) = port.parse::<u16>() {
        if n == 0 {
            return Err("Port must be between 1 and 65535".to_string());
        }
        return Ok(());
    }
    // Service name: alphanumeric + hyphens only
    if port
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Ok(());
    }
    Err(format!("Invalid port: {}", port))
}

/// Validate an IP address or CIDR notation. "any" and "Anywhere" are allowed.
fn validate_address(addr: &str) -> Result<(), String> {
    let addr = addr.trim();
    if addr.is_empty() || addr == "any" || addr.eq_ignore_ascii_case("anywhere") {
        return Ok(());
    }
    // Strip CIDR suffix for validation
    let (ip_part, cidr) = if let Some(idx) = addr.find('/') {
        let cidr_str = &addr[idx + 1..];
        let _: u8 = cidr_str
            .parse()
            .map_err(|_| format!("Invalid CIDR prefix: {}", cidr_str))?;
        (&addr[..idx], true)
    } else {
        (addr, false)
    };
    // Validate IPv4
    let octets: Vec<&str> = ip_part.split('.').collect();
    if octets.len() == 4 {
        for octet in &octets {
            let _: u8 = octet
                .parse()
                .map_err(|_| format!("Invalid IPv4 address: {}", addr))?;
        }
        return Ok(());
    }
    // Validate IPv6 (basic check: contains colons, hex digits)
    if ip_part.contains(':')
        && ip_part
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':')
    {
        return Ok(());
    }
    // Hostname-like (alphanumeric + dots + hyphens)
    if ip_part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !cidr
    {
        return Ok(());
    }
    Err(format!("Invalid address: {}", addr))
}

/// Validate an interface name: alphanumeric, hyphens, and dots only (e.g. eth0, wlan0, br-lan).
fn validate_interface(iface: &str) -> Result<(), String> {
    let iface = iface.trim();
    if iface.is_empty() {
        return Ok(());
    }
    if iface
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        Ok(())
    } else {
        Err(format!("Invalid interface name: {}", iface))
    }
}

/// Helper: run a UFW command in a background thread, then refresh status.
/// The `operation_in_progress` flag prevents concurrent operations.
fn spawn_ufw_command_and_refresh(
    ufw_status: Arc<Mutex<UfwStatus>>,
    operation_in_progress: Arc<AtomicBool>,
    args: Vec<String>,
) {
    if operation_in_progress
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        // Another operation is already in progress
        if let Ok(mut status) = ufw_status.lock() {
            status.error = Some("Another operation is in progress, please wait.".to_string());
        }
        return;
    }
    thread::spawn(move || {
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = run_privileged_ufw_command(&arg_refs);
        if let Err(e) = &result {
            if let Ok(mut status) = ufw_status.lock() {
                status.error = Some(e.clone());
            }
            operation_in_progress.store(false, Ordering::SeqCst);
            return;
        }
        thread::sleep(Duration::from_millis(500));
        let refresh_result = get_ufw_status_and_rules();
        if let Ok(mut status) = ufw_status.lock() {
            match refresh_result {
                Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                    status.enabled = enabled;
                    status.rules = rules;
                    status.default_incoming = default_incoming;
                    status.default_outgoing = default_outgoing;
                    status.app_profiles = app_profiles;
                    status.error = None;
                }
                Err(e) => {
                    status.error = Some(e);
                }
            }
        }
        operation_in_progress.store(false, Ordering::SeqCst);
    });
}

impl GufwApp {
    fn check_auth_status(&mut self) {
        // Check if background auth completed by looking at status
        if !self.authenticated
            && let Ok(status) = self.ufw_status.lock()
                && (status.error.is_none() || status.error.as_deref() == Some("Authentication failed. Please try again.")) {
                    // Auth thread finished (either success or failure)
                    self.authenticated = status.error.is_none();
                }
    }

    fn spawn_status_thread(&self) {
        let ufw_status = self.ufw_status.clone();
        let op_flag = self.operation_in_progress.clone();
        thread::spawn(move || {
            if op_flag
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return;
            }
            let result = get_ufw_status_and_rules();
            if let Ok(mut status) = ufw_status.lock() {
                match result {
                    Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                        status.enabled = enabled;
                        status.rules = rules;
                        status.default_incoming = default_incoming;
                        status.default_outgoing = default_outgoing;
                        status.app_profiles = app_profiles;
                        status.error = None;
                    }
                    Err(e) => {
                        status.error = Some(e);
                    }
                }
            }
            op_flag.store(false, Ordering::SeqCst);
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
        spawn_ufw_command_and_refresh(
            self.ufw_status.clone(),
            self.operation_in_progress.clone(),
            vec![cmd.to_string()],
        );
    }

    fn add_rule(&mut self, action: &str, port: &str, protocol: &str) {
        if !self.authenticated {
            return;
        }
        if let Err(e) = validate_port(port) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }
        let cmd = match action.to_lowercase().as_str() {
            "allow" => "allow",
            "deny" => "deny",
            "reject" => "reject",
            "limit" => "limit",
            _ => "deny",
        };
        let rule = format!("{}/{}", port, protocol);
        spawn_ufw_command_and_refresh(
            self.ufw_status.clone(),
            self.operation_in_progress.clone(),
            vec![cmd.to_string(), rule],
        );
    }

    /// Build a UFW command from an AdvancedRule (for add or delete).
    ///
    /// Full UFW syntax:
    /// Full UFW syntax:
    ///   ufw [route] [delete] <action> [in|out [on <iface>]] [log|log-all]
    ///       [from <src> [port <port>]] [to <dst> [port <port>]] [proto <proto>]
    ///       [comment <comment>]
    ///
    /// For app profiles:
    ///   ufw <action> <app_name>
    fn build_ufw_command(&self, rule: &AdvancedRule, is_delete: bool) -> Vec<String> {
        let mut cmd_parts = Vec::new();

        // Trim all string fields to avoid whitespace issues
        let interface_in = rule.interface_in.trim();
        let interface_out = rule.interface_out.trim();
        let app_profile = rule.app_profile.trim();
        let source = rule.source.trim();
        let destination = rule.destination.trim();
        let port = rule.port.trim();
        let protocol = rule.protocol.trim();
        let comment = rule.comment.trim();

        if is_delete {
            cmd_parts.push("delete".to_string());
        }

        // Route/forward rule
        if rule.is_route {
            cmd_parts.push("route".to_string());
        }

        // Action
        cmd_parts.push(rule.action.to_lowercase());

        // App profile shorthand: ufw <action> <app_name>
        if !app_profile.is_empty() {
            cmd_parts.push(app_profile.to_string());
            if !comment.is_empty() {
                cmd_parts.push("comment".to_string());
                cmd_parts.push(comment.to_string());
            }
            return cmd_parts;
        }

        // Direction and interface (must come before log)
        if !interface_in.is_empty() {
            cmd_parts.push("in".to_string());
            cmd_parts.push("on".to_string());
            cmd_parts.push(interface_in.to_string());
        } else if rule.direction == "in" {
            cmd_parts.push("in".to_string());
        }

        if !interface_out.is_empty() {
            cmd_parts.push("out".to_string());
            cmd_parts.push("on".to_string());
            cmd_parts.push(interface_out.to_string());
        } else if rule.direction == "out" {
            cmd_parts.push("out".to_string());
        }

        // Per-rule logging (after direction/interface)
        if rule.log_option != "none" && !rule.log_option.is_empty() {
            cmd_parts.push(rule.log_option.clone());
        }

        // From / source (always include for advanced syntax)
        cmd_parts.push("from".to_string());
        if source.is_empty() || source == "any" {
            cmd_parts.push("any".to_string());
        } else {
            cmd_parts.push(source.to_string());
        }
        // Source port — if port is set and direction is "in" or "any",
        // the port applies to destination; source port is not commonly used
        // so we leave it for the "to" side below.

        // To / destination (always include for advanced syntax)
        cmd_parts.push("to".to_string());
        if destination.is_empty() || destination == "any" {
            cmd_parts.push("any".to_string());
        } else {
            cmd_parts.push(destination.to_string());
        }

        // Port (attached to the "to" clause)
        if !port.is_empty() {
            cmd_parts.push("port".to_string());
            cmd_parts.push(port.to_string());
        }

        // Protocol
        if protocol != "any" && !protocol.is_empty() {
            cmd_parts.push("proto".to_string());
            cmd_parts.push(protocol.to_string());
        }

        // Comment
        if !comment.is_empty() {
            cmd_parts.push("comment".to_string());
            cmd_parts.push(comment.to_string());
        }

        cmd_parts
    }

    /// Parse a UFW rule line into (to, action, from) using whitespace-based splitting.
    fn parse_ufw_rule_line(&self, line: &str) -> (String, String, String) {
        // Strip comment
        let line_no_comment = if let Some(idx) = line.find('#') {
            &line[..idx]
        } else {
            line
        };
        let parts: Vec<&str> = line_no_comment.split_whitespace().collect();

        // Find the action keyword (ALLOW, DENY, REJECT, LIMIT) and optional direction
        let action_keywords = ["ALLOW", "DENY", "REJECT", "LIMIT"];
        let mut action_idx = None;
        for (i, part) in parts.iter().enumerate() {
            let upper = part.to_uppercase();
            if action_keywords.iter().any(|kw| upper == *kw || upper == format!("{} IN", kw) || upper == format!("{} OUT", kw)) {
                action_idx = Some(i);
                break;
            }
        }

        if let Some(ai) = action_idx {
            let to = parts[..ai].join(" ");
            // Check if next part after action keyword is IN/OUT
            let (action, from_start) = if ai + 1 < parts.len() {
                let next = parts[ai + 1].to_uppercase();
                if next == "IN" || next == "OUT" {
                    (format!("{} {}", parts[ai], parts[ai + 1]), ai + 2)
                } else {
                    (parts[ai].to_string(), ai + 1)
                }
            } else {
                (parts[ai].to_string(), ai + 1)
            };
            let from = parts[from_start..].join(" ");
            (to, action, from)
        } else {
            // Fallback: return the whole line as "to"
            (line.trim().to_string(), String::new(), String::new())
        }
    }

    fn remove_rule_by_number(&mut self, line_number: usize) {
        if !self.authenticated {
            return;
        }
        spawn_ufw_command_and_refresh(
            self.ufw_status.clone(),
            self.operation_in_progress.clone(),
            vec![
                "--force".to_string(),
                "delete".to_string(),
                line_number.to_string(),
            ],
        );
    }

    fn parse_rule(&self, rule_str: &str) -> Option<(String, String, String)> {
        let parts: Vec<&str> = rule_str.split_whitespace().collect();
        if parts.len() >= 2 {
            let port_proto = parts[0];
            let action = parts[1].to_lowercase();
            let port_proto_parts: Vec<&str> = port_proto.split('/').collect();
            if port_proto_parts.len() == 2 {
                let port = port_proto_parts[0].to_string();
                let protocol = port_proto_parts[1].to_string();
                return Some((action, port, protocol));
            }
        }
        None
    }

    fn parse_rule_for_display(&self, rule: &str) -> (String, String, String, String) {
        let (to, action, from) = self.parse_ufw_rule_line(rule);
        // Capitalize action for display
        let display_action = capitalize_first(&action);
        (to, display_action, "ANY".to_string(), from)
    }

    /// Parse a UFW rule line into an AdvancedRule for editing.
    /// Example lines from `ufw status numbered`:
    ///   "22/tcp                     ALLOW IN    Anywhere"
    ///   "80/tcp on eth0             ALLOW IN    Anywhere"
    ///   "Anywhere on eth0           ALLOW FWD   Anywhere on eth1"
    fn parse_rule_to_advanced(&self, raw: &str) -> AdvancedRule {
        let mut rule = AdvancedRule {
            action: "allow".to_string(),
            direction: "any".to_string(),
            protocol: "any".to_string(),
            port: String::new(),
            source: "any".to_string(),
            destination: "any".to_string(),
            comment: String::new(),
            log_option: "none".to_string(),
            interface_in: String::new(),
            interface_out: String::new(),
            is_route: false,
            app_profile: String::new(),
        };

        // Extract comment (after #)
        let (line, comment) = if let Some(idx) = raw.find('#') {
            (&raw[..idx], raw[idx + 1..].trim().to_string())
        } else {
            (raw, String::new())
        };
        rule.comment = comment;

        let parts: Vec<&str> = line.split_whitespace().collect();

        // Find the action keyword index
        let action_keywords = ["ALLOW", "DENY", "REJECT", "LIMIT"];
        let mut action_idx = None;
        for (i, part) in parts.iter().enumerate() {
            let upper = part.to_uppercase();
            if action_keywords.iter().any(|kw| upper == *kw) {
                action_idx = Some(i);
                break;
            }
        }

        let Some(ai) = action_idx else {
            return rule;
        };

        // Action
        rule.action = parts[ai].to_lowercase();

        // Direction: check token after action for IN/OUT/FWD
        let from_start;
        if ai + 1 < parts.len() {
            let next = parts[ai + 1].to_uppercase();
            if next == "IN" {
                rule.direction = "in".to_string();
                from_start = ai + 2;
            } else if next == "OUT" {
                rule.direction = "out".to_string();
                from_start = ai + 2;
            } else if next == "FWD" {
                rule.direction = "in".to_string();
                rule.is_route = true;
                from_start = ai + 2;
            } else {
                from_start = ai + 1;
            }
        } else {
            from_start = ai + 1;
        }

        // "To" side: everything before the action
        let to_parts = &parts[..ai];
        // "From" side: everything after action+direction
        let from_parts = &parts[from_start..];

        // Parse "to" side: could be "22/tcp", "22/tcp on eth0", "Anywhere on eth0", "Anywhere"
        self.parse_rule_endpoint(to_parts, &mut rule, true);
        // Parse "from" side: same format
        self.parse_rule_endpoint(from_parts, &mut rule, false);

        rule
    }

    /// Parse one side (to or from) of a UFW rule display line.
    /// Tokens like: ["22/tcp", "on", "eth0"] or ["Anywhere"] or ["192.168.1.0/24"]
    fn parse_rule_endpoint(&self, parts: &[&str], rule: &mut AdvancedRule, is_to_side: bool) {
        if parts.is_empty() {
            return;
        }

        let mut addr_or_port = parts[0];

        // Check for "on <interface>" in this side
        if let Some(on_idx) = parts.iter().position(|p| p.eq_ignore_ascii_case("on")) {
            if on_idx + 1 < parts.len() {
                let iface = parts[on_idx + 1];
                if is_to_side {
                    // "to" side interface = interface_in (for incoming rules)
                    // But in UFW display, "to" column with "on" means the listening interface
                    rule.interface_in = iface.to_string();
                } else {
                    rule.interface_out = iface.to_string();
                }
            }
            // The address/port is the part before "on"
            if on_idx > 0 {
                addr_or_port = parts[0];
            }
        }

        // Parse addr_or_port: could be "22/tcp", "Anywhere", "192.168.1.0/24", an app name, etc.
        if addr_or_port.eq_ignore_ascii_case("anywhere") {
            if is_to_side {
                rule.destination = "any".to_string();
            } else {
                rule.source = "any".to_string();
            }
        } else if addr_or_port.contains('/') {
            // Could be port/proto like "22/tcp" or CIDR like "192.168.1.0/24"
            let slash_parts: Vec<&str> = addr_or_port.splitn(2, '/').collect();
            if slash_parts.len() == 2 {
                // Check if second part is a protocol name
                let second = slash_parts[1].to_lowercase();
                if second == "tcp" || second == "udp" {
                    // It's port/proto
                    rule.port = slash_parts[0].to_string();
                    rule.protocol = second;
                    if is_to_side {
                        rule.destination = "any".to_string();
                    } else {
                        rule.source = "any".to_string();
                    }
                } else {
                    // Likely CIDR address
                    if is_to_side {
                        rule.destination = addr_or_port.to_string();
                    } else {
                        rule.source = addr_or_port.to_string();
                    }
                }
            }
        } else {
            // Plain address or port number or app name
            if is_to_side {
                // Could be a port number or an address
                if addr_or_port.chars().all(|c| c.is_ascii_digit() || c == ':') {
                    rule.port = addr_or_port.to_string();
                    rule.destination = "any".to_string();
                } else {
                    rule.destination = addr_or_port.to_string();
                }
            } else {
                rule.source = addr_or_port.to_string();
            }
        }
    }

    fn edit_rule(
        &mut self,
        rule_index: usize,
        new_action: &str,
        new_port: &str,
        new_protocol: &str,
    ) {
        if !self.authenticated {
            return;
        }
        if let Err(e) = validate_port(new_port) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }

        let rules = {
            if let Ok(status) = self.ufw_status.lock() {
                status.rules.clone()
            } else {
                return;
            }
        };

        if rule_index >= rules.len() {
            return;
        }

        let old_rule = &rules[rule_index];

        if let Some((old_action, old_port, old_protocol)) = self.parse_rule(old_rule.raw.as_str())
        {
            let ufw_status = self.ufw_status.clone();
            let op_flag = self.operation_in_progress.clone();
            let new_cmd = match new_action.to_lowercase().as_str() {
                "allow" => "allow",
                "deny" => "deny",
                "reject" => "reject",
                "limit" => "limit",
                _ => "deny",
            };
            let new_rule = format!("{}/{}", new_port, new_protocol);
            // Build delete args properly as a Vec (no split_whitespace injection)
            let delete_args = ["delete".to_string(),
                old_action,
                format!("{}/{}", old_port, old_protocol)];
            let add_args = [new_cmd.to_string(), new_rule];

            if op_flag
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                self.current_error = "Another operation is in progress, please wait.".to_string();
                self.show_error_dialog = true;
                return;
            }

            thread::spawn(move || {
                // Delete old rule
                let delete_refs: Vec<&str> = delete_args.iter().map(|s| s.as_str()).collect();
                let delete_result = run_privileged_ufw_command(&delete_refs);
                if let Err(e) = delete_result {
                    if let Ok(mut status) = ufw_status.lock() {
                        status.error = Some(format!("Failed to delete old rule: {}", e));
                    }
                    op_flag.store(false, Ordering::SeqCst);
                    return;
                }

                // Add new rule
                let add_refs: Vec<&str> = add_args.iter().map(|s| s.as_str()).collect();
                let add_result = run_privileged_ufw_command(&add_refs);
                if let Err(e) = add_result {
                    if let Ok(mut status) = ufw_status.lock() {
                        status.error = Some(format!(
                            "Old rule deleted but failed to add new rule: {}",
                            e
                        ));
                    }
                    op_flag.store(false, Ordering::SeqCst);
                    return;
                }

                // Refresh
                thread::sleep(Duration::from_millis(500));
                let refresh_result = get_ufw_status_and_rules();
                if let Ok(mut status) = ufw_status.lock() {
                    match refresh_result {
                        Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                            status.enabled = enabled;
                            status.rules = rules;
                            status.default_incoming = default_incoming;
                            status.default_outgoing = default_outgoing;
                            status.app_profiles = app_profiles;
                            status.error = None;
                        }
                        Err(e) => {
                            status.error = Some(e);
                        }
                    }
                }
                op_flag.store(false, Ordering::SeqCst);
            });
        }
    }

    fn add_advanced_rule(&mut self, rule: &AdvancedRule) {
        if !self.authenticated {
            return;
        }
        // Skip port validation when using an app profile
        if rule.app_profile.is_empty() && !rule.port.is_empty()
            && let Err(e) = validate_port(&rule.port) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if rule.source != "any"
            && let Err(e) = validate_address(&rule.source) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if rule.destination != "any"
            && let Err(e) = validate_address(&rule.destination) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if let Err(e) = validate_interface(&rule.interface_in) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }
        if let Err(e) = validate_interface(&rule.interface_out) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }
        let cmd_parts = self.build_ufw_command(rule, false);
        spawn_ufw_command_and_refresh(
            self.ufw_status.clone(),
            self.operation_in_progress.clone(),
            cmd_parts,
        );
    }

    /// Edit an advanced rule: delete old rule by number, then add the new one.
    fn edit_advanced_rule(&mut self, rule_number: usize, rule: &AdvancedRule) {
        if !self.authenticated {
            return;
        }
        // Same validation as add_advanced_rule
        if rule.app_profile.is_empty() && !rule.port.is_empty()
            && let Err(e) = validate_port(&rule.port) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if rule.source != "any"
            && let Err(e) = validate_address(&rule.source) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if rule.destination != "any"
            && let Err(e) = validate_address(&rule.destination) {
                self.current_error = e;
                self.show_error_dialog = true;
                return;
            }
        if let Err(e) = validate_interface(&rule.interface_in) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }
        if let Err(e) = validate_interface(&rule.interface_out) {
            self.current_error = e;
            self.show_error_dialog = true;
            return;
        }

        let ufw_status = self.ufw_status.clone();
        let op_flag = self.operation_in_progress.clone();
        let add_cmd = self.build_ufw_command(rule, false);
        let delete_args = [
            "--force".to_string(),
            "delete".to_string(),
            rule_number.to_string(),
        ];

        if op_flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            self.current_error = "Another operation is in progress, please wait.".to_string();
            self.show_error_dialog = true;
            return;
        }

        thread::spawn(move || {
            // Delete old rule by number
            let delete_refs: Vec<&str> = delete_args.iter().map(|s| s.as_str()).collect();
            let delete_result = run_privileged_ufw_command(&delete_refs);
            if let Err(e) = delete_result {
                if let Ok(mut status) = ufw_status.lock() {
                    status.error = Some(format!("Failed to delete old rule: {}", e));
                }
                op_flag.store(false, Ordering::SeqCst);
                return;
            }

            // Add new rule
            let add_refs: Vec<&str> = add_cmd.iter().map(|s| s.as_str()).collect();
            let add_result = run_privileged_ufw_command(&add_refs);
            if let Err(e) = add_result {
                if let Ok(mut status) = ufw_status.lock() {
                    status.error = Some(format!(
                        "Old rule deleted but failed to add new rule: {}",
                        e
                    ));
                }
                op_flag.store(false, Ordering::SeqCst);
                return;
            }

            // Refresh
            thread::sleep(Duration::from_millis(500));
            let refresh_result = get_ufw_status_and_rules();
            if let Ok(mut status) = ufw_status.lock() {
                match refresh_result {
                    Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                        status.enabled = enabled;
                        status.rules = rules;
                        status.default_incoming = default_incoming;
                        status.default_outgoing = default_outgoing;
                        status.app_profiles = app_profiles;
                        status.error = None;
                    }
                    Err(e) => {
                        status.error = Some(e);
                    }
                }
            }
            op_flag.store(false, Ordering::SeqCst);
        });
    }

    fn set_default_policies(&mut self, incoming: &str, outgoing: &str) {
        if !self.authenticated {
            return;
        }

        let ufw_status = self.ufw_status.clone();
        let op_flag = self.operation_in_progress.clone();
        let incoming = incoming.to_string();
        let outgoing = outgoing.to_string();

        if op_flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        thread::spawn(move || {
            // Fixed argument order: ufw default <policy> <direction>
            let _ = run_privileged_ufw_command(&["default", &incoming, "incoming"]);
            let _ = run_privileged_ufw_command(&["default", &outgoing, "outgoing"]);

            // Refresh to get actual state
            thread::sleep(Duration::from_millis(500));
            let refresh_result = get_ufw_status_and_rules();
            if let Ok(mut status) = ufw_status.lock() {
                match refresh_result {
                    Ok((enabled, rules, default_incoming, default_outgoing, app_profiles)) => {
                        status.enabled = enabled;
                        status.rules = rules;
                        status.default_incoming = default_incoming;
                        status.default_outgoing = default_outgoing;
                        status.app_profiles = app_profiles;
                        status.error = None;
                    }
                    Err(e) => {
                        status.error = Some(e);
                    }
                }
            }
            op_flag.store(false, Ordering::SeqCst);
        });
    }
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn run_privileged_ufw_command(args: &[&str]) -> Result<String, String> {
    let sudo_result = Command::new("sudo")
        .arg("-n")
        .arg("ufw")
        .args(args)
        .output();

    match sudo_result {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
        Ok(output) => Err(format!(
            "Command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )),
        _ => {
            let pkexec_result = Command::new("pkexec").arg("ufw").args(args).output();

            match pkexec_result {
                Ok(output) if output.status.success() => {
                    Ok(String::from_utf8_lossy(&output.stdout).to_string())
                }
                Ok(output) => Err(format!(
                    "Command failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )),
                Err(e) => Err(format!("Failed to run command: {}", e)),
            }
        }
    }
}

type UfwStatusResult = Result<(bool, Vec<UfwRule>, String, String, Vec<String>), String>;

fn get_ufw_status_and_rules() -> UfwStatusResult {
    // Use numbered status for line numbers
    let output = run_privileged_ufw_command(&["status", "numbered"])?;
    let mut enabled = false;
    let mut rules = Vec::new();
    // Default values (overridden by verbose output below)
    let mut default_incoming = "deny".to_string();
    let mut default_outgoing = "allow".to_string();

    for line in output.lines() {
        if line.contains("Status: active") {
            enabled = true;
        }
        if line.contains("Status: inactive") {
            enabled = false;
        }
        // Skip header/separator lines
        if line.starts_with("To")
            || line.starts_with("--")
            || line.trim().is_empty()
            || line
                .chars()
                .all(|c| c == '-' || c.is_whitespace())
        {
            continue;
        }
        // Parse rules with line numbers
        if line.starts_with('[')
            && let Some(idx) = line.find(']') {
                let num_str = line[1..idx].trim();
                if let Ok(num) = num_str.parse::<usize>() {
                    let rule_str = line[idx + 1..].trim().to_string();
                    rules.push(UfwRule {
                        line_number: Some(num),
                        raw: rule_str,
                    });
                }
            }
    }

    // Parse default policies from `ufw status verbose`
    if let Ok(verbose_output) = run_privileged_ufw_command(&["status", "verbose"]) {
        for line in verbose_output.lines() {
            // Line format: "Default: deny (incoming), allow (outgoing), disabled (routed)"
            if let Some(rest) = line.strip_prefix("Default:") {
                for part in rest.split(',') {
                    let part = part.trim();
                    if part.contains("(incoming)") {
                        let policy = part.split_whitespace().next().unwrap_or("deny");
                        default_incoming = policy.to_lowercase();
                    } else if part.contains("(outgoing)") {
                        let policy = part.split_whitespace().next().unwrap_or("allow");
                        default_outgoing = policy.to_lowercase();
                    }
                }
            }
        }
    }

    // Parse application profiles from `ufw app list`
    let mut app_profiles = Vec::new();
    if let Ok(app_output) = run_privileged_ufw_command(&["app", "list"]) {
        for line in app_output.lines() {
            let trimmed = line.trim();
            // Skip the header "Available applications:" and empty lines
            if trimmed.is_empty() || trimmed.starts_with("Available") {
                continue;
            }
            app_profiles.push(trimmed.to_string());
        }
    }

    Ok((enabled, rules, default_incoming, default_outgoing, app_profiles))
}

impl App for GufwApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Check if background auth has completed
        self.check_auth_status();

        // F5 to refresh
        if ctx.input(|i| i.key_pressed(egui::Key::F5)) {
            self.refresh_status();
        }

        let op_busy = self.operation_in_progress.load(Ordering::SeqCst);

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("gufw-rs - Firewall Configuration");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button("About")
                        .on_hover_text("Show help information")
                        .clicked()
                    {
                        self.show_about_dialog = true;
                    }
                    if ui
                        .button("Quit")
                        .on_hover_text("Exit application")
                        .clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        egui::SidePanel::left("sidebar").min_width(200.0).show(ctx, |ui| {
            let (enabled, error) = {
                if let Ok(status) = self.ufw_status.lock() {
                    (status.enabled, status.error.clone())
                } else {
                    (false, Some("Failed to read status".to_string()))
                }
            };
            ui.heading("Status");
            ui.add_space(8.0);

            if !self.authenticated {
                ui.colored_label(egui::Color32::YELLOW, "Authentication required");
                if ui.button("Authenticate").clicked() {
                    // Spawn auth in background
                    let ufw_status = self.ufw_status.clone();
                    let op_flag = self.operation_in_progress.clone();
                    thread::spawn(move || {
                        let ok = authenticate();
                        if ok {
                            op_flag.store(true, Ordering::SeqCst);
                            let result = get_ufw_status_and_rules();
                            if let Ok(mut status) = ufw_status.lock() {
                                match result {
                                    Ok((enabled, rules, di, do_, app_profiles)) => {
                                        status.enabled = enabled;
                                        status.rules = rules;
                                        status.default_incoming = di;
                                        status.default_outgoing = do_;
                                        status.app_profiles = app_profiles;
                                        status.error = None;
                                    }
                                    Err(e) => {
                                        status.error = Some(e);
                                    }
                                }
                            }
                            op_flag.store(false, Ordering::SeqCst);
                        } else if let Ok(mut status) = ufw_status.lock() {
                            status.error = Some("Authentication failed. Please try again.".to_string());
                        }
                    });
                }
            } else {
                ui.horizontal(|ui| {
                    let icon = if enabled { "🔒" } else { "🔓" };
                    ui.label(icon);
                    let mut toggle = enabled;
                    let checkbox = ui
                        .add_enabled(!op_busy, egui::Checkbox::new(&mut toggle, "Firewall enabled"))
                        .on_hover_text("Toggle firewall");
                    if checkbox.changed() && toggle != enabled {
                        self.set_ufw_enabled(toggle);
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
                if let Ok(status) = self.ufw_status.lock() {
                    (
                        status.default_incoming.clone(),
                        status.default_outgoing.clone(),
                    )
                } else {
                    ("deny".to_string(), "allow".to_string())
                }
            };
            ui.horizontal(|ui| {
                ui.label("Incoming:");
                ui.strong(capitalize_first(&default_incoming));
            });
            ui.horizontal(|ui| {
                ui.label("Outgoing:");
                ui.strong(capitalize_first(&default_outgoing));
            });
            if ui
                .add_enabled(!op_busy, egui::Button::new("Edit Policies"))
                .clicked()
            {
                self.policy_incoming = default_incoming.clone();
                self.policy_outgoing = default_outgoing.clone();
                self.show_policy_dialog = true;
            }
            ui.add_space(16.0);
            ui.label(format!("Version: {}", env!("CARGO_PKG_VERSION")));
            ui.label("by 7ANG0N1N3");
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Check for errors and show dialog if needed
            {
                if let Ok(status) = self.ufw_status.lock()
                    && let Some(error) = &status.error
                        && !self.show_error_dialog {
                            self.current_error = error.clone();
                            self.show_error_dialog = true;
                        }
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let mut tab_button =
                    |ui: &mut egui::Ui, tab: Tab, label: &str, icon: &str, tooltip: &str| {
                        let selected = self.selected_tab == tab;
                        let resp = ui
                            .add_sized(
                                [120.0, 28.0],
                                egui::SelectableLabel::new(
                                    selected,
                                    format!("{} {}", icon, label),
                                ),
                            )
                            .on_hover_text(tooltip);
                        if resp.clicked() {
                            self.selected_tab = tab;
                        }
                    };
                tab_button(ui, Tab::Simple, "Simple", "⚡", "Add simple rules");
                tab_button(
                    ui,
                    Tab::Preconfigured,
                    "Preconfigured",
                    "🛠",
                    "Add rules for common services",
                );
                tab_button(
                    ui,
                    Tab::Advanced,
                    "Advanced",
                    "⚙",
                    "Add advanced rules",
                );
            });
            ui.separator();
            ui.add_space(8.0);

            match self.selected_tab {
                Tab::Simple => {
                    let rules = {
                        if let Ok(status) = self.ufw_status.lock() {
                            status.rules.clone()
                        } else {
                            vec![]
                        }
                    };

                    if !self.authenticated {
                        ui.vertical_centered(|ui| {
                            ui.label("Please authenticate to view rules");
                        });
                        return;
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Simple Rules");
                        ui.add_space(4.0);

                        if rules.is_empty() {
                            ui.colored_label(
                                egui::Color32::GRAY,
                                "No rules configured. Add your first rule below.",
                            );
                            ui.add_space(8.0);
                        } else {
                            egui::Grid::new("rules_grid").striped(true).show(ui, |ui| {
                                ui.label(egui::RichText::new("Rule #").strong());
                                ui.label(egui::RichText::new("Port/Protocol").strong());
                                ui.label(egui::RichText::new("Action").strong());
                                ui.label(egui::RichText::new("Direction").strong());
                                ui.label(egui::RichText::new("Source").strong());
                                ui.label(egui::RichText::new("Actions").strong());
                                ui.end_row();
                                for (i, rule) in rules.iter().enumerate() {
                                    let (port_proto, action, direction, source) =
                                        self.parse_rule_for_display(rule.raw.as_str());
                                    let rule_num = rule
                                        .line_number
                                        .map(|n| n.to_string())
                                        .unwrap_or("-".to_string());
                                    ui.label(rule_num);
                                    ui.label(port_proto);
                                    ui.label(action);
                                    ui.label(direction);
                                    ui.label(source);
                                    ui.horizontal(|ui| {
                                        if let Some(num) = rule.line_number
                                            && ui
                                                .add_enabled(
                                                    !op_busy,
                                                    egui::Button::new("Remove")
                                                        .fill(egui::Color32::from_rgb(220, 60, 60)),
                                                )
                                                .on_hover_text("Remove this rule")
                                                .clicked()
                                            {
                                                self.remove_rule_by_number(num);
                                            }
                                        if ui
                                            .add_enabled(
                                                !op_busy,
                                                egui::Button::new("Edit")
                                                    .fill(egui::Color32::from_rgb(60, 120, 180)),
                                            )
                                            .on_hover_text("Edit this rule")
                                            .clicked()
                                            && let Some((action, port, protocol)) =
                                                self.parse_rule(rule.raw.as_str())
                                            {
                                                self.edit_action = action;
                                                self.edit_port = port;
                                                self.edit_protocol = protocol;
                                                self.edit_rule_index = Some(i);
                                                self.show_edit_dialog = true;
                                            }
                                    });
                                    ui.end_row();
                                }
                            });
                        }
                        ui.add_space(8.0);
                        if ui
                            .add_enabled(
                                !op_busy,
                                egui::Button::new("Add Rule")
                                    .fill(egui::Color32::from_rgb(60, 180, 60)),
                            )
                            .on_hover_text("Add a new rule")
                            .clicked()
                        {
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
                            if ui.add_enabled(!op_busy, egui::Button::new("SSH (22)")).clicked() {
                                self.add_rule("allow", "22", "tcp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("HTTP (80)")).clicked() {
                                self.add_rule("allow", "80", "tcp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("HTTPS (443)")).clicked()
                            {
                                self.add_rule("allow", "443", "tcp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("FTP (21)")).clicked() {
                                self.add_rule("allow", "21", "tcp");
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.add_enabled(!op_busy, egui::Button::new("DNS (53)")).clicked() {
                                self.add_rule("allow", "53", "udp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("SMTP (25)")).clicked() {
                                self.add_rule("allow", "25", "tcp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("POP3 (110)")).clicked()
                            {
                                self.add_rule("allow", "110", "tcp");
                            }
                            if ui.add_enabled(!op_busy, egui::Button::new("IMAP (143)")).clicked()
                            {
                                self.add_rule("allow", "143", "tcp");
                            }
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(!op_busy, egui::Button::new("MySQL (3306)"))
                                .clicked()
                            {
                                self.add_rule("allow", "3306", "tcp");
                            }
                            if ui
                                .add_enabled(!op_busy, egui::Button::new("PostgreSQL (5432)"))
                                .clicked()
                            {
                                self.add_rule("allow", "5432", "tcp");
                            }
                            if ui
                                .add_enabled(!op_busy, egui::Button::new("Redis (6379)"))
                                .clicked()
                            {
                                self.add_rule("allow", "6379", "tcp");
                            }
                            if ui
                                .add_enabled(!op_busy, egui::Button::new("MongoDB (27017)"))
                                .clicked()
                            {
                                self.add_rule("allow", "27017", "tcp");
                            }
                        });
                    });
                    // Application Profiles section
                    ui.add_space(16.0);
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Application Profiles");
                        let app_profiles = {
                            if let Ok(status) = self.ufw_status.lock() {
                                status.app_profiles.clone()
                            } else {
                                vec![]
                            }
                        };
                        if app_profiles.is_empty() {
                            ui.colored_label(
                                egui::Color32::GRAY,
                                "No application profiles found.",
                            );
                        } else {
                            ui.label("Click on an application profile to allow it:");
                            ui.add_space(4.0);
                            let mut profile_to_add: Option<String> = None;
                            egui::Grid::new("app_profiles_grid")
                                .min_col_width(150.0)
                                .show(ui, |ui| {
                                    for (i, profile) in app_profiles.iter().enumerate() {
                                        if ui
                                            .add_enabled(
                                                !op_busy,
                                                egui::Button::new(profile.as_str()),
                                            )
                                            .clicked()
                                        {
                                            profile_to_add = Some(profile.clone());
                                        }
                                        // 3 per row
                                        if (i + 1) % 3 == 0 {
                                            ui.end_row();
                                        }
                                    }
                                });
                            if let Some(profile) = profile_to_add {
                                spawn_ufw_command_and_refresh(
                                    self.ufw_status.clone(),
                                    self.operation_in_progress.clone(),
                                    vec!["allow".to_string(), profile],
                                );
                            }
                        }
                    });
                }
                Tab::Advanced => {
                    let rules = {
                        if let Ok(status) = self.ufw_status.lock() {
                            status.rules.clone()
                        } else {
                            vec![]
                        }
                    };

                    if !self.authenticated {
                        ui.vertical_centered(|ui| {
                            ui.label("Please authenticate to view rules");
                        });
                        return;
                    }
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.heading("Advanced Rules");
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    !op_busy,
                                    egui::Button::new("Add Advanced Rule")
                                        .fill(egui::Color32::from_rgb(60, 180, 60)),
                                )
                                .clicked()
                            {
                                self.show_advanced_dialog = true;
                            }
                        });
                        ui.add_space(8.0);

                        if rules.is_empty() {
                            ui.colored_label(
                                egui::Color32::GRAY,
                                "No rules configured. Add your first rule above.",
                            );
                        } else {
                            egui::Grid::new("advanced_rules_grid")
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Rule #").strong());
                                    ui.label(egui::RichText::new("Port/Protocol").strong());
                                    ui.label(egui::RichText::new("Action").strong());
                                    ui.label(egui::RichText::new("Direction").strong());
                                    ui.label(egui::RichText::new("Source").strong());
                                    ui.label(egui::RichText::new("Actions").strong());
                                    ui.end_row();
                                    for rule in rules.iter() {
                                        let (port_proto, action, direction, source) =
                                            self.parse_rule_for_display(rule.raw.as_str());
                                        let rule_num = rule
                                            .line_number
                                            .map(|n| n.to_string())
                                            .unwrap_or("-".to_string());
                                        ui.label(rule_num);
                                        ui.label(&port_proto);
                                        ui.label(&action);
                                        ui.label(&direction);
                                        ui.label(&source);
                                        ui.horizontal(|ui| {
                                            if let Some(num) = rule.line_number {
                                                if ui
                                                    .add_enabled(
                                                        !op_busy,
                                                        egui::Button::new("Remove").fill(
                                                            egui::Color32::from_rgb(220, 60, 60),
                                                        ),
                                                    )
                                                    .clicked()
                                                {
                                                    self.remove_rule_by_number(num);
                                                }
                                                if ui
                                                    .add_enabled(
                                                        !op_busy,
                                                        egui::Button::new("Edit").fill(
                                                            egui::Color32::from_rgb(60, 120, 180),
                                                        ),
                                                    )
                                                    .on_hover_text("Edit this rule")
                                                    .clicked()
                                                {
                                                    // Parse the raw rule line into an AdvancedRule
                                                    self.advanced_edit_rule = self.parse_rule_to_advanced(&rule.raw);
                                                    self.advanced_edit_rule_number = Some(num);
                                                    self.show_advanced_edit_dialog = true;
                                                }
                                            }
                                        });
                                        ui.end_row();
                                    }
                                });
                        }
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

        // Error Dialog
        if self.show_error_dialog {
            let is_initializing = self.current_error == "Initializing...";
            let window_title = if is_initializing { "Status" } else { "Error" };
            let message_color = if is_initializing {
                egui::Color32::BLUE
            } else {
                egui::Color32::RED
            };
            let message_label = if is_initializing {
                "Status:"
            } else {
                "An error occurred:"
            };

            egui::Window::new(window_title)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.colored_label(message_color, message_label);
                    ui.label(&self.current_error);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            self.show_error_dialog = false;
                            self.current_error.clear();
                            {
                                if let Ok(mut status) = self.ufw_status.lock() {
                                    status.error = None;
                                }
                            }
                            self.refresh_status();
                        }
                    });
                });
        }

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
                            .selected_text(capitalize_first(&add_action))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut add_action,
                                    "allow".to_string(),
                                    "Allow",
                                );
                                ui.selectable_value(&mut add_action, "deny".to_string(), "Deny");
                                ui.selectable_value(&mut add_action, "reject".to_string(), "Reject");
                                ui.selectable_value(&mut add_action, "limit".to_string(), "Limit");
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
                                ui.selectable_value(
                                    &mut add_protocol,
                                    "tcp".to_string(),
                                    "tcp",
                                );
                                ui.selectable_value(
                                    &mut add_protocol,
                                    "udp".to_string(),
                                    "udp",
                                );
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked()
                            && !add_port.trim().is_empty() {
                                add_clicked = true;
                                self.show_add_dialog = false;
                                rule_to_add = Some((
                                    add_action.clone(),
                                    add_port.clone(),
                                    add_protocol.clone(),
                                ));
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

        // Advanced Rule Dialog
        if self.show_advanced_dialog {
            let mut add_clicked = false;
            let mut advanced_rule = self.advanced_rule.clone();
            egui::Window::new("Add Advanced Rule")
                .collapsible(false)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().max_height(600.0).show(ui, |ui| {
                    // Route checkbox
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut advanced_rule.is_route, "Route/Forward rule");
                    });
                    // Action
                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        egui::ComboBox::new("advanced_action_combo", "")
                            .selected_text(capitalize_first(&advanced_rule.action))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut advanced_rule.action,
                                    "allow".to_string(),
                                    "Allow",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.action,
                                    "deny".to_string(),
                                    "Deny",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.action,
                                    "reject".to_string(),
                                    "Reject",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.action,
                                    "limit".to_string(),
                                    "Limit",
                                );
                            });
                    });
                    // Log option
                    ui.horizontal(|ui| {
                        ui.label("Log:");
                        let log_display = match advanced_rule.log_option.as_str() {
                            "log" => "Log",
                            "log-all" => "Log All",
                            _ => "None",
                        };
                        egui::ComboBox::new("advanced_log_combo", "")
                            .selected_text(log_display)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut advanced_rule.log_option,
                                    "none".to_string(),
                                    "None",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.log_option,
                                    "log".to_string(),
                                    "Log",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.log_option,
                                    "log-all".to_string(),
                                    "Log All",
                                );
                            });
                    });
                    // Direction
                    ui.horizontal(|ui| {
                        ui.label("Direction:");
                        egui::ComboBox::new("direction_combo", "")
                            .selected_text(capitalize_first(&advanced_rule.direction))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut advanced_rule.direction,
                                    "in".to_string(),
                                    "Incoming",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.direction,
                                    "out".to_string(),
                                    "Outgoing",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.direction,
                                    "any".to_string(),
                                    "Any",
                                );
                            });
                    });
                    // Interface In
                    ui.horizontal(|ui| {
                        ui.label("Interface In:");
                        ui.text_edit_singleline(&mut advanced_rule.interface_in);
                        ui.label("(e.g. eth0)");
                    });
                    // Interface Out
                    ui.horizontal(|ui| {
                        ui.label("Interface Out:");
                        ui.text_edit_singleline(&mut advanced_rule.interface_out);
                        ui.label("(e.g. eth1)");
                    });
                    ui.separator();
                    // App Profile
                    ui.horizontal(|ui| {
                        ui.label("App Profile:");
                        ui.text_edit_singleline(&mut advanced_rule.app_profile);
                        ui.label("(e.g. OpenSSH, leave empty for manual)");
                    });
                    if !advanced_rule.app_profile.is_empty() {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            "Port, protocol, source, and destination are ignored when an app profile is set.",
                        );
                    }
                    ui.separator();
                    // Protocol
                    ui.horizontal(|ui| {
                        ui.label("Protocol:");
                        egui::ComboBox::new("advanced_proto_combo", "")
                            .selected_text(advanced_rule.protocol.to_uppercase())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut advanced_rule.protocol,
                                    "tcp".to_string(),
                                    "TCP",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.protocol,
                                    "udp".to_string(),
                                    "UDP",
                                );
                                ui.selectable_value(
                                    &mut advanced_rule.protocol,
                                    "any".to_string(),
                                    "Any",
                                );
                            });
                    });
                    // Port
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut advanced_rule.port);
                    });
                    // Source
                    ui.horizontal(|ui| {
                        ui.label("Source:");
                        ui.text_edit_singleline(&mut advanced_rule.source);
                        ui.label("(e.g., 192.168.1.0/24, any)");
                    });
                    // Destination
                    ui.horizontal(|ui| {
                        ui.label("Destination:");
                        ui.text_edit_singleline(&mut advanced_rule.destination);
                        ui.label("(e.g., 192.168.1.100, any)");
                    });
                    // Comment
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
                    }); // end ScrollArea
                });
            if add_clicked {
                self.add_advanced_rule(&advanced_rule);
            } else {
                self.advanced_rule = advanced_rule;
            }
        }

        // Advanced Edit Rule Dialog
        if self.show_advanced_edit_dialog {
            let mut save_clicked = false;
            let mut edit_rule = self.advanced_edit_rule.clone();
            let edit_rule_number = self.advanced_edit_rule_number;
            egui::Window::new("Edit Advanced Rule")
                .collapsible(false)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical().max_height(600.0).show(ui, |ui| {
                    // Route checkbox
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut edit_rule.is_route, "Route/Forward rule");
                    });
                    // Action
                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        egui::ComboBox::new("adv_edit_action_combo", "")
                            .selected_text(capitalize_first(&edit_rule.action))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_rule.action, "allow".to_string(), "Allow");
                                ui.selectable_value(&mut edit_rule.action, "deny".to_string(), "Deny");
                                ui.selectable_value(&mut edit_rule.action, "reject".to_string(), "Reject");
                                ui.selectable_value(&mut edit_rule.action, "limit".to_string(), "Limit");
                            });
                    });
                    // Log option
                    ui.horizontal(|ui| {
                        ui.label("Log:");
                        let log_display = match edit_rule.log_option.as_str() {
                            "log" => "Log",
                            "log-all" => "Log All",
                            _ => "None",
                        };
                        egui::ComboBox::new("adv_edit_log_combo", "")
                            .selected_text(log_display)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_rule.log_option, "none".to_string(), "None");
                                ui.selectable_value(&mut edit_rule.log_option, "log".to_string(), "Log");
                                ui.selectable_value(&mut edit_rule.log_option, "log-all".to_string(), "Log All");
                            });
                    });
                    // Direction
                    ui.horizontal(|ui| {
                        ui.label("Direction:");
                        egui::ComboBox::new("adv_edit_direction_combo", "")
                            .selected_text(capitalize_first(&edit_rule.direction))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_rule.direction, "in".to_string(), "Incoming");
                                ui.selectable_value(&mut edit_rule.direction, "out".to_string(), "Outgoing");
                                ui.selectable_value(&mut edit_rule.direction, "any".to_string(), "Any");
                            });
                    });
                    // Interface In
                    ui.horizontal(|ui| {
                        ui.label("Interface In:");
                        ui.text_edit_singleline(&mut edit_rule.interface_in);
                        ui.label("(e.g. eth0)");
                    });
                    // Interface Out
                    ui.horizontal(|ui| {
                        ui.label("Interface Out:");
                        ui.text_edit_singleline(&mut edit_rule.interface_out);
                        ui.label("(e.g. eth1)");
                    });
                    ui.separator();
                    // App Profile
                    ui.horizontal(|ui| {
                        ui.label("App Profile:");
                        ui.text_edit_singleline(&mut edit_rule.app_profile);
                        ui.label("(e.g. OpenSSH, leave empty for manual)");
                    });
                    if !edit_rule.app_profile.is_empty() {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            "Port, protocol, source, and destination are ignored when an app profile is set.",
                        );
                    }
                    ui.separator();
                    // Protocol
                    ui.horizontal(|ui| {
                        ui.label("Protocol:");
                        egui::ComboBox::new("adv_edit_proto_combo", "")
                            .selected_text(edit_rule.protocol.to_uppercase())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut edit_rule.protocol, "tcp".to_string(), "TCP");
                                ui.selectable_value(&mut edit_rule.protocol, "udp".to_string(), "UDP");
                                ui.selectable_value(&mut edit_rule.protocol, "any".to_string(), "Any");
                            });
                    });
                    // Port
                    ui.horizontal(|ui| {
                        ui.label("Port:");
                        ui.text_edit_singleline(&mut edit_rule.port);
                    });
                    // Source
                    ui.horizontal(|ui| {
                        ui.label("Source:");
                        ui.text_edit_singleline(&mut edit_rule.source);
                        ui.label("(e.g., 192.168.1.0/24, any)");
                    });
                    // Destination
                    ui.horizontal(|ui| {
                        ui.label("Destination:");
                        ui.text_edit_singleline(&mut edit_rule.destination);
                        ui.label("(e.g., 192.168.1.100, any)");
                    });
                    // Comment
                    ui.horizontal(|ui| {
                        ui.label("Comment:");
                        ui.text_edit_singleline(&mut edit_rule.comment);
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            save_clicked = true;
                            self.show_advanced_edit_dialog = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_advanced_edit_dialog = false;
                        }
                    });
                    }); // end ScrollArea
                });
            if save_clicked {
                if let Some(rule_num) = edit_rule_number {
                    self.edit_advanced_rule(rule_num, &edit_rule);
                }
            } else {
                self.advanced_edit_rule = edit_rule;
            }
        }

        // Edit Rule Dialog (Simple)
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
                            .selected_text(capitalize_first(&edit_action))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut edit_action,
                                    "allow".to_string(),
                                    "Allow",
                                );
                                ui.selectable_value(&mut edit_action, "deny".to_string(), "Deny");
                                ui.selectable_value(&mut edit_action, "reject".to_string(), "Reject");
                                ui.selectable_value(&mut edit_action, "limit".to_string(), "Limit");
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
                                ui.selectable_value(
                                    &mut edit_protocol,
                                    "tcp".to_string(),
                                    "tcp",
                                );
                                ui.selectable_value(
                                    &mut edit_protocol,
                                    "udp".to_string(),
                                    "udp",
                                );
                            });
                    });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked()
                            && !edit_port.trim().is_empty() {
                                edit_clicked = true;
                                self.show_edit_dialog = false;
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
                    ui.label(
                        "Set the default policies for incoming and outgoing traffic:",
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label("Incoming Policy:");
                        egui::ComboBox::new("incoming_policy_combo", "")
                            .selected_text(capitalize_first(&policy_incoming))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut policy_incoming,
                                    "deny".to_string(),
                                    "Deny",
                                );
                                ui.selectable_value(
                                    &mut policy_incoming,
                                    "allow".to_string(),
                                    "Allow",
                                );
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Outgoing Policy:");
                        egui::ComboBox::new("outgoing_policy_combo", "")
                            .selected_text(capitalize_first(&policy_outgoing))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut policy_outgoing,
                                    "allow".to_string(),
                                    "Allow",
                                );
                                ui.selectable_value(
                                    &mut policy_outgoing,
                                    "deny".to_string(),
                                    "Deny",
                                );
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

        // About Dialog
        if self.show_about_dialog {
            egui::Window::new("About")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("gufw-rs : GUI UFW interface in Rust");
                        ui.add_space(8.0);
                        ui.label(format!("version : {}", env!("CARGO_PKG_VERSION")));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("GITHUB  : ");
                            if ui
                                .link("https://github.com/7ang0n1n3/gufw-rs")
                                .clicked()
                            {
                                let _ =
                                    webbrowser::open("https://github.com/7ang0n1n3/gufw-rs");
                            }
                        });
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            ui.label("This is a take on gufw by costales ");
                            if ui
                                .link("<https://github.com/costales/gufw>")
                                .clicked()
                            {
                                let _ = webbrowser::open("https://github.com/costales/gufw");
                            }
                        });
                    });
                    ui.add_space(16.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.button("OK").clicked() {
                                    self.show_about_dialog = false;
                                }
                            },
                        );
                    });
                });
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "gufw-rs",
        options,
        Box::new(|cc| {
            use egui::{FontFamily, FontId, TextStyle};
            let mut style = (*cc.egui_ctx.style()).clone();
            style.text_styles = [
                (
                    TextStyle::Heading,
                    FontId::new(28.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Body,
                    FontId::new(18.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Monospace,
                    FontId::new(16.0, FontFamily::Monospace),
                ),
                (
                    TextStyle::Button,
                    FontId::new(18.0, FontFamily::Proportional),
                ),
                (
                    TextStyle::Small,
                    FontId::new(14.0, FontFamily::Proportional),
                ),
            ]
            .into();
            cc.egui_ctx.set_style(style);
            Ok(Box::new(GufwApp::default()))
        }),
    )
}
