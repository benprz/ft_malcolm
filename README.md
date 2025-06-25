# ft_malcolm - ARP Spoofing Tool

A network security tool that implements ARP (Address Resolution Protocol) spoofing functionality. This project demonstrates how ARP attacks work and can be used for educational purposes in network security.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Security Notice](#security-notice)
- [License](#license)

## Overview

ft_malcolm is an ARP spoofing tool that can:
- Intercept ARP requests from a target host
- Send spoofed ARP replies to redirect network traffic
- Monitor network activity with verbose output
- Support different target identification methods (IP, MAC, hostname)

This tool is designed for educational purposes to understand how ARP attacks work and to demonstrate network security concepts.

## Features

- **ARP Request Interception**: Listens for ARP requests from specified targets
- **Spoofed ARP Replies**: Sends fake ARP responses to redirect traffic
- **Multiple Target Types**: Support for IP addresses, MAC addresses, and hostnames
- **Verbose Mode**: Detailed packet information output
- **Signal Handling**: Graceful shutdown with Ctrl+C
- **Network Interface Detection**: Automatic interface and MAC address detection

## Prerequisites

- Linux operating system (uses Linux-specific networking headers)
- GCC compiler
- Root privileges (required for raw socket operations)
- Network interface with proper permissions

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ft_malcolm
```

2. Compile the project:
```bash
make
```

This will create the `ft_malcolm` executable.

## Usage

**⚠️ WARNING: This tool requires root privileges and should only be used on networks you own or have explicit permission to test.**

### Basic Usage

```bash
sudo ./ft_malcolm [options] <target>
```

### Options

- `-v, --verbose`: Enable verbose output showing packet details
- `-h, --help`: Display help information

### Target Specification

The target can be specified in three formats:

1. **IP Address**: `192.168.1.100`
2. **MAC Address**: `00:11:22:33:44:55`
3. **Hostname**: `target.local`

### Examples

```bash
# Basic usage with IP address
sudo ./ft_malcolm 192.168.1.100

# With verbose output
sudo ./ft_malcolm -v 192.168.1.100

# Using MAC address
sudo ./ft_malcolm 00:11:22:33:44:55

# Using hostname
sudo ./ft_malcolm target.local
```

## How It Works

### ARP Spoofing Process

1. **Socket Creation**: Creates a raw socket to capture and send packets
2. **Interface Detection**: Automatically detects the network interface and its MAC address
3. **ARP Request Monitoring**: Listens for ARP requests from the target host
4. **Spoofed Reply Generation**: When an ARP request is detected, sends a fake ARP reply
5. **Traffic Redirection**: The target host updates its ARP cache with the spoofed information

### Packet Structure

The tool constructs ARP packets with:
- **Ethernet Header**: Source and destination MAC addresses
- **ARP Header**: Hardware type, protocol type, operation code, and address mappings

### Signal Handling

The program handles SIGINT (Ctrl+C) gracefully:
- Sets a flag to stop the main loop
- Closes the socket
- Exits cleanly

## Project Structure

```
ft_malcolm/
├── main.c              # Main program logic
├── Makefile            # Build configuration
├── libft/              # Custom C library
│   ├── includes/       # Header files
│   ├── src/           # Source files
│   └── Makefile       # Library build configuration
├── en.subject.pdf     # Project requirements
└── README.md          # This file
```

## Dependencies

### External Libraries
- Standard C libraries (libc)
- Linux networking headers
- Socket programming libraries

### Internal Library
- **libft**: Custom C library providing utility functions
  - String manipulation functions
  - Memory management functions
  - Network utility functions (MAC address conversion)
  - I/O functions

## Security Notice

**⚠️ IMPORTANT SECURITY WARNINGS:**

1. **Legal Use Only**: This tool should only be used on networks you own or have explicit permission to test
2. **Educational Purpose**: This is designed for learning about network security, not for malicious use
3. **Root Privileges**: The tool requires root access for raw socket operations
4. **Network Impact**: ARP spoofing can disrupt network connectivity for affected hosts
5. **Responsible Disclosure**: If you find security vulnerabilities, report them responsibly

### Ethical Guidelines

- Only test on your own networks or with explicit permission
- Inform network administrators before testing
- Do not use for unauthorized network access
- Respect privacy and data protection laws

## Technical Details

### Network Protocol Support
- **Ethernet**: Raw ethernet frame handling
- **ARP**: Address Resolution Protocol implementation
- **IPv4**: Internet Protocol version 4 support

### Error Handling
- Comprehensive error checking for socket operations
- Graceful handling of network errors
- Signal-safe operations

## License

This project is part of the 42 school curriculum and is intended for educational purposes. Please use responsibly and in accordance with applicable laws and regulations.