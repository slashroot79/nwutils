#!/bin/bash

# ==============================================================================
# Basic Network Diagnostics Script for Azure Linux Envionments
# Author: Ragu Karuturi
# This script provides multiple functions for network troubleshooting:
# 1. install: Installs a suite of networking tools based on the detected OS.
# 2. <target> [port]: Tests connectivity to a target FQDN or IP. Default ports 80 and 443.
# 3. run: Interactive mode to detect outbound connections and run diagnostics.
# ==============================================================================

# Default log file. This can be overridden by user prompts. Override for non App Service Environments (VMs, ACAs etc).
LOG_FILE="/home/Logfiles/nwutils.log"
PACKET_CAPTURE_FILE="/home/Logfiles/nwutils_$(date +%s).pcap"
if ! touch "$LOG_FILE" 2>/dev/null; then
    LOG_FILE="/home/Logfiles/nwutils.log"
    touch "$LOG_FILE"
fi

# Log messages to both stdout and log file
log_message() {
    message="$1"
    timestamped_message="[$(date +'%Y-%m-%d %H:%M:%S')] $message"
    echo -e "$timestamped_message" | tee -a "$LOG_FILE"
}

log_message "Log file initialized at $LOG_FILE"

# Check if the script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        return 1 # Not root
    else
        return 0 # Is root
    fi
}

# INSTALLATION
# Detects OS and installs networking tools
install_tools() {
    if ! check_root; then
        log_message "Tool installation requires root privileges. Please run with sudo."
        # Attempt to re-run with sudo
        if command -v sudo &> /dev/null; then
            log_message "Attempting to re-run with sudo..."
            sudo "$0" "install"
            exit $?
        else
            log_message "sudo command not found. Please run this script as root."
            exit 1
        fi
    fi

    log_message "*** Starting Tool Installation ***"

    # Detect OS
    local OS_ID=""
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
    else
        log_message "Error: Cannot detect operating system. /etc/os-release not found."
        exit 1
    fi

    log_message "Operating System Detected: -- $OS_ID"

    local PKG_MANAGER=""
    local INSTALL_CMD=""
    local UPDATE_CMD=""
    local packages_to_install=""

    case "$OS_ID" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            UPDATE_CMD="apt-get update"
            INSTALL_CMD="apt-get install -y"
            packages_to_install="nmap netcat-openbsd tcpdump dnsutils iftop net-tools netsniff-ng iptraf-ng curl wget lsof"
            ;;
        rhel|mariner|azurelinux) # Red Hat, CBL-Mariner, Azure Linux
            PKG_MANAGER="dnf"
            if ! command -v dnf &> /dev/null; then
                PKG_MANAGER="yum"
            fi
            UPDATE_CMD="$PKG_MANAGER makecache"
            INSTALL_CMD="$PKG_MANAGER install -y"
            # nmap-ncat provides 'nc', bind-utils provides 'nslookup'
            packages_to_install="nmap nmap-ncat tcpdump iproute bind-utils iftop net-tools netsniff-ng iptraf-ng curl wget lsof"
            ;;
        alpine)
            PKG_MANAGER="apk"
            UPDATE_CMD="apk update"
            INSTALL_CMD="apk add"
            packages_to_install="nmap nmap-ncat tcpdump iproute2 bind-tools iftop net-tools netsniff-ng iptraf-ng curl wget lsof"
            ;;
        *)
            log_message "Unsupported Operating System: $OS_ID. Cannot install tools."
            exit 1
            ;;
    esac

    log_message "Updating package lists using $PKG_MANAGER..."
    $UPDATE_CMD >/dev/null 2>&1

    log_message "Starting installation of tools..."
    for pkg in $packages_to_install; do
        if $INSTALL_CMD $pkg >/dev/null 2>&1; then
            log_message "Successfully installed $pkg."
        else
            log_message "Skip install for $pkg: Package not found or failed to install."
        fi
    done
    log_message "--- Tool Installation Complete ---"
}

# Checks if required tools are present and prompts for install if not.
# Usage: check_tools "tool1" "tool2" ...
check_tools() {
    local missing_tools=()
    for tool in "$@"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_message "The following required tools are missing: ${missing_tools[*]}"
        echo "The following required tools are missing: ${missing_tools[*]}" >&2 # Also to stderr
        
        read -p "Would you like to run the tool installation now? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            install_tools
            # Re-check after install
            for tool in "$@"; do
                if ! command -v "$tool" &> /dev/null; then
                    log_message "Error: $tool is still not installed. Exiting."
                    exit 1
                fi
            done
        else
            log_message "Installation skipped. Cannot proceed without required tools."
            exit 1
        fi
    fi
}

# Tests connectivity to a target on specified ports.
# Usage: test_connectivity "target.com" "80" "443"
test_connectivity() {
    local target="$1"
    # Create an array of ports from the rest of the arguments
    local ports=("${@:2}")

    log_message "--- Starting Connectivity Test for $target on port(s): ${ports[*]} ---"
    
    # Check for required tools
    check_tools "nmap" "nping" "nc"

    for port in "${ports[@]}"; do
        log_message " "
        log_message "Testing $target on port $port"
        log_message "================================================="

        # Test 1: nmap - TCP SYN scan
        log_message "Running: nmap -p $port $target"
        nmap -p "$port" "$target" | sed 's/^/  [nmap] /' | tee -a "$LOG_FILE"
        log_message "nmap test complete."
        log_message " - - - - - - "
        # Test 2: nping - TCP connect
        log_message "Running: nping --tcp-connect -p $port -c 3 $target"
        nping --tcp-connect -p "$port" -c 3 "$target" | sed 's/^/  [nping] /' | tee -a "$LOG_FILE"
        log_message "nping test complete."
        log_message " - - - - - - "
        # Test 3: nc (netcat) - z (zero-I/O) v (verbose)
        log_message "Running: nc -zv $target $port"
        # nc output is often to stderr
        (nc -zv "$target" "$port" 2>&1) | sed 's/^/  [nc] /' | tee -a "$LOG_FILE"
        log_message "netcat test complete."
        log_message " - - - - - - "
    done

    log_message "--- Connectivity Test for $target Complete ---"
}

# RUN 
run_interactive() {
    log_message "--- Starting Interactive Diagnostics Mode ---"
    check_tools "netstat" "nslookup" "nc" "tcpdump" "nping"

    local target_ip=""
    local target_port=""

    # Detect outbound IP and port. 
    # Prompt only for port number
    read -p "Please enter the destination Port to test: " target_port

    # Validate port
    if ! [[ "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        log_message "Error: Invalid port specified: '$target_port'. Must be 1-65535."
        exit 1
    fi

    local connection
    log_message "Detecting active outbound connection for port $target_port..."
    connection=$(netstat -tunp 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | grep -v ':22 ' | grep ":$target_port ")

    if [ -z "$connection" ]; then
        log_message "No active outbound connection found for port $target_port."
        exit 0
    fi

    target_ip=$(echo "$connection" | awk '{print $5}' | cut -d':' -f1 | head -n1)
    # Extract Process name
    process_info=$(echo "$connection" | awk '{print $7}' | head -n1)  
    process_name=$(echo "$process_info" | cut -d'/' -f2)

    read -p "Detected application process: $process_name, destination: $dest_ip:$dest_port. Proceed with diagnostics? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_message "Diagnostics canceled by user."
        echo "Please run diagnostics manually if needed."
        exit 0
    fi

    log_message "Proceeding with diagnostics..."
    # 1. nslookup
    log_message "Running nslookup $target_ip..."
    nslookup "$target_ip" | sed 's/^/  [nslookup] /' | tee -a "$LOG_FILE"
    log_message "nslookup complete."

    # 2. TCP Connectivity
    log_message "Running TCP connectivity test (nc -zv $target_ip $target_port)..."
    (nc -zv "$target_ip" "$target_port" 2>&1) | sed 's/^/  [nc] /' | tee -a "$LOG_FILE"
    log_message "TCP connectivity test complete."

    # 3. Latency Test
    log_message "Running latency test (nping --tcp -p $target_port -c 5 $target_ip)..."
    nping --tcp -p "$target_port" -c 5 "$target_ip" | sed 's/^/  [nping] /' | tee -a "$LOG_FILE"
    log_message "Latency test complete."

    # 4. Packet Capture
    log_message "---"
    log_message "Starting packet capture for 1 minute."
    log_message "This requires root privileges."
    log_message "Packets will be saved to: $PACKET_CAPTURE_FILE"
    log_message "Filter: host $target_ip and port $target_port"
    
    local capture_cmd="tcpdump -i any -w $PACKET_CAPTURE_FILE host $target_ip and port $target_port -G 60 -W 1"
    
    if ! check_root; then
        if command -v sudo &> /dev/null; then
            log_message "Requesting sudo for tcpdump..."
            sudo $capture_cmd
        else
            log_message "Error: sudo not found. Cannot run tcpdump as non-root."
            return 1
        fi
    else
        log_message "Running tcpdump as root..."
        $capture_cmd
    fi
    
    log_message "Packet capture complete. File: $PACKET_CAPTURE_FILE"
    log_message "--- Interactive Diagnostics Complete ---"
}

# Show help
show_help() {
    echo "Network Diagnostics Script"
    echo "--------------------------"
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install                 Detect OS and install required networking tools."
    echo "                          (Requires root/sudo privileges)"
    echo ""
    echo "  <fqdn_or_ip>            Test connectivity to <fqdn_or_ip> on ports 80 and 443."
    echo "                          Prompts for a log file location."
    echo ""
    echo "  <fqdn_or_ip> <port>     Test connectivity to <fqdn_or_ip> on the specified <port>."
    echo "                          Prompts for a log file location."
    echo ""
    echo "  run                     Run interactive diagnostics."
    echo "                          - Detects outbound connections (via netstat)"
    echo "                          - Prompts for target"
    echo "                          - Runs nslookup, connectivity, and latency tests"
    echo "                          - Captures 1 minute of packets (requires root/sudo)"
    echo ""
    echo "  help (or no args)       Show this help message."
    echo ""
    echo "Global Log File: $LOG_FILE"
    echo "Packet Captures: $PACKET_CAPTURE_FILE (for 'run' mode)"
}


# ==============================================================================
# MAIN SCRIPT
# Parse command-line arguments
# ==============================================================================

# No arguments: Show help
if [ "$#" -eq 0 ]; then
    show_help
    exit 0
fi

# Handle specific commands first
case "$1" in
    install)
        install_tools
        exit $?
        ;;
    run)
        run_interactive
        exit $?
        ;;
    help)
        show_help
        exit 0
        ;;
    -h|--help)
        show_help
        exit 0
        ;;
esac

# --- Handle FQDN/IP commands ---
# If not above (isntall, run, help), the cmdline arguments must be fqdn/ip and/or port number

log_message() {
    local message="$1"
    local timestamped_message="[$(date +'%Y-%m-%d %H:%M:%S')] $message"
    echo -e "$timestamped_message" | tee -a "$LOG_FILE"
}

log_message "--- Logging all diagnostics to $LOG_FILE ---"

TARGET_FQDN="$1"

if [ "$#" -eq 1 ]; then
    test_connectivity "$TARGET_FQDN" "80" "443"
elif [ "$#" -eq 2 ]; then
    TARGET_PORT="$2"
    if ! [[ "$TARGET_PORT" =~ ^[0-9]+$ ]] || [ "$TARGET_PORT" -lt 1 ] || [ "$TARGET_PORT" -gt 65535 ]; then
        log_message "Error: Invalid port specified: '$TARGET_PORT'. Must be a number between 1 and 65535."
        exit 1
    fi
    test_connectivity "$TARGET_FQDN" "$TARGET_PORT"
else
    log_message "Error: Incorrect or too many arguments provided"
    show_help
    exit 1
fi

exit 0
