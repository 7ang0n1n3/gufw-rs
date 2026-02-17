# gufw-rs

A modern GUI firewall configuration tool written in Rust for Linux systems, inspired by the original GUFW (Graphical Uncomplicated Firewall).

[![Rust](https://img.shields.io/badge/Rust-1.70+-blue.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.6.0-orange.svg)](Cargo.toml)

## Overview

gufw-rs is a graphical user interface for managing UFW (Uncomplicated Firewall) rules on Linux systems. Built with Rust and egui, it provides an intuitive way to configure firewall rules without using the command line.

**Demo Video**: https://www.youtube.com/watch?v=3fmM8_NRs_c

## Features

### Authentication & Security
- **Dual Authentication Support**: Uses both `sudo` and `pkexec` for privilege escalation
- **Timestamp-based Authentication**: Leverages sudo timestamp to avoid repeated password prompts
- **Secure Command Execution**: All UFW commands are executed with proper privilege escalation
- **Error Handling**: Comprehensive error handling with user-friendly error messages

### Firewall Management
- **Enable/Disable Firewall**: Toggle UFW firewall on/off with a single click
- **Real-time Status**: Live monitoring of firewall status and rules
- **Default Policies**: Configure default incoming and outgoing traffic policies
- **Rule Management**: Add, edit, and remove firewall rules through an intuitive interface

### Rule Management Features

#### Simple Rules
- **Port-based Rules**: Add rules for specific ports and protocols
- **Action Selection**: Allow, Deny, Reject, or Limit traffic for specified ports
- **Protocol Support**: TCP and UDP protocol support
- **Quick Add**: One-click rule addition for common scenarios

#### Preconfigured Rules
- **Common Services**: Pre-configured rules for popular services:
  - SSH (22/tcp), HTTP (80/tcp), HTTPS (443/tcp), FTP (21/tcp)
  - DNS (53/udp), SMTP (25/tcp), POP3 (110/tcp), IMAP (143/tcp)
  - MySQL (3306/tcp), PostgreSQL (5432/tcp), Redis (6379/tcp), MongoDB (27017/tcp)
- **Application Profiles**: Automatically detects and lists UFW application profiles installed on the system (e.g. OpenSSH, Apache, Nginx). Click any profile to allow it with one click.

#### Advanced Rules
- **Granular Control**: Full control over rule parameters
- **Action Types**: Allow, Deny, Reject, and Limit (rate-limiting for brute-force protection)
- **Direction Support**: Incoming, outgoing, or bidirectional rules
- **Route/Forward Rules**: Create forwarding rules for routing traffic between interfaces
- **Per-Rule Logging**: Set logging level per rule (None, Log, Log All)
- **Interface Binding**: Bind rules to specific network interfaces (in and/or out)
- **Application Profiles**: Specify a UFW app profile instead of manual port/protocol
- **Source/Destination**: Specify source and destination addresses with CIDR support
- **Comments**: Add descriptive comments to rules
- **Full Edit Support**: Edit existing rules with all advanced fields pre-populated from the current rule

### User Interface
- **Modern GUI**: Built with egui for a native, responsive interface
- **Tabbed Interface**: Organized into Simple, Preconfigured, and Advanced tabs
- **Scrollable Dialogs**: Advanced rule dialogs are scrollable and resizable for all fields
- **Real-time Updates**: Live status updates and rule refresh
- **Error Dialogs**: User-friendly error messages and status notifications
- **Keyboard Shortcuts**: F5 to refresh status

### Technical Features
- **Thread Safety**: Multi-threaded architecture with proper mutex handling
- **Error Recovery**: Graceful handling of authentication and command failures
- **Input Validation**: Port, address, and interface name validation
- **Intelligent Rule Parsing**: Parses UFW rule output back into editable components
- **Full UFW Syntax**: Generates correct UFW commands including route, log, interface, and app profile options

## Installation

### Prerequisites
- Rust 1.70 or higher
- UFW (Uncomplicated Firewall) installed
- sudo or pkexec access

### Building from Source
```bash
# Clone the repository
git clone https://github.com/7ang0n1n3/gufw-rs.git
cd gufw-rs

# Build the application
cargo build --release

# Run the application
cargo run --release
```

### Dependencies
The application requires the following system dependencies:
- `ufw` - Uncomplicated Firewall
- `sudo` or `pkexec` - For privilege escalation

## Usage

### Starting the Application
```bash
# Run from source
cargo run --release

# Or run the compiled binary
./target/release/gufw-rs
```

### Authentication
1. **First Launch**: The application will prompt for authentication using pkexec
2. **Subsequent Launches**: Uses sudo timestamp for seamless operation
3. **Re-authentication**: Automatically prompts when sudo timestamp expires

### Basic Operations

#### Enabling/Disabling Firewall
- Use the checkbox in the sidebar to toggle firewall status
- Status is displayed with color-coded indicators (Green = Enabled, Red = Disabled)

#### Adding Simple Rules
1. Navigate to the **Simple** tab
2. Click **Add Rule**
3. Select action (Allow/Deny/Reject/Limit)
4. Enter port number
5. Select protocol (TCP/UDP)
6. Click **Add**

#### Adding Preconfigured Rules
1. Navigate to the **Preconfigured** tab
2. Click on any service button (SSH, HTTP, HTTPS, etc.)
3. Or click an **Application Profile** button to allow a detected app profile
4. Rules are automatically added with appropriate settings

#### Adding Advanced Rules
1. Navigate to the **Advanced** tab
2. Click **Add Advanced Rule**
3. Configure parameters:
   - **Route** checkbox - enable for forwarding/route rules
   - **Action** (Allow/Deny/Reject/Limit)
   - **Log** (None/Log/Log All) - per-rule logging
   - **Direction** (Incoming/Outgoing/Any)
   - **Interface In** - bind to an incoming interface (e.g. eth0)
   - **Interface Out** - bind to an outgoing interface (e.g. eth1)
   - **App Profile** - use a UFW application profile instead of manual port/proto
   - **Protocol** (TCP/UDP/Any)
   - **Port** (optional)
   - **Source address** (e.g. 192.168.1.0/24, or "any")
   - **Destination address**
   - **Comment** (optional)
4. Click **Add**

#### Editing Advanced Rules
1. In the **Advanced** tab, click **Edit** next to any rule
2. The edit dialog opens pre-populated with the rule's current settings
3. Modify any fields and click **Save**
4. The old rule is deleted and the new rule is added

#### Managing Rules
- **View Rules**: All rules are displayed in a table format with rule number, port/protocol, action, direction, and source
- **Remove Rules**: Click the **Remove** button next to any rule
- **Edit Rules**: Click the **Edit** button to modify existing rules
- **Rule Numbers**: Rules are numbered for easy identification

#### Default Policies
1. Click **Edit Policies** in the sidebar
2. Configure default incoming and outgoing policies
3. Click **Save** to apply changes

## API Reference

### Data Structures

#### UfwStatus
```rust
struct UfwStatus {
    enabled: bool,                    // Firewall enabled state
    rules: Vec<UfwRule>,             // List of firewall rules
    error: Option<String>,           // Error message if any
    default_incoming: String,        // Default incoming policy
    default_outgoing: String,        // Default outgoing policy
    app_profiles: Vec<String>,       // Available UFW application profiles
}
```

#### UfwRule
```rust
struct UfwRule {
    line_number: Option<usize>,      // Rule line number
    raw: String,                     // Raw rule string
}
```

#### AdvancedRule
```rust
struct AdvancedRule {
    action: String,                  // Allow/Deny/Reject/Limit
    direction: String,               // In/Out/Any
    protocol: String,                // TCP/UDP/Any
    port: String,                    // Port number or range
    source: String,                  // Source address
    destination: String,             // Destination address
    comment: String,                 // Rule comment
    log_option: String,              // "none", "log", or "log-all"
    interface_in: String,            // Incoming interface (e.g. eth0)
    interface_out: String,           // Outgoing interface (e.g. eth1)
    is_route: bool,                  // Route/forward rule
    app_profile: String,             // UFW app profile name
}
```

## Development

### Project Structure
```
gufw-rs/
├── src/
│   └── main.rs          # Main application code
├── Cargo.toml           # Rust dependencies and metadata
├── README.md           # This file
└── LICENSE             # MIT License
```

### Dependencies
- `eframe` - egui application framework
- `egui` - Immediate mode GUI library
- `webbrowser` - Web browser integration

### Building for Development
```bash
# Development build
cargo build

# Run with debug information
cargo run

# Check for warnings and errors
cargo clippy

# Run tests (when implemented)
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines
1. Follow Rust coding conventions
2. Add proper error handling
3. Include documentation for new functions
4. Test thoroughly before submitting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Original GUFW**: Inspired by [costales/gufw](https://github.com/costales/gufw)
- **egui**: For the excellent GUI framework
- **Rust Community**: For the amazing ecosystem and tools

---

**Created by 7ANG0N1N3**

*Built for Arch Linux and Hyprland, but works on any Linux distribution with UFW support.*
