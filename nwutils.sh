#!/bin/bash

# ==============================================================================
# Basic Network Diagnostics Script for Azure Linux Envionments
# Author: Ragu Karuturi
# This script provides multiple functions for network troubleshooting:
# 1. install: Installs a suite of networking tools based on the detected OS.
# 2. <target> [port]: Tests connectivity to a target FQDN or IP. Default ports 80 and 443.
# 3. run: Interactive mode to detect outbound connections and run diagnostics.
# ==============================================================================

# Default log dir - applicable for Azure Linux App Services
LOG_DIR="/home/Logfiles"

# Create a custom log dir (/Appuserlogs) in IaaS or non App Service hosts. Imp: Enable storage in Custom Containers (App Service). 
if [ ! -d "$LOG_DIR" ] || [ ! -w "$LOG_DIR" ]; then
    LOG_DIR="/Appuserlogs"
    mkdir -p "$LOG_DIR" || { echo "Failed to create log directory $LOG_DIR"; exit 1; }
fi

# Create Log files
LOG_FILE="$LOG_DIR/nwutils.log"
PACKET_CAPTURE_FILE="$LOG_DIR/nwutils_$(date +%s).pcap"

# Test access
touch "$LOG_FILE" || {
    echo "Cannot write to log file"
    exit 1
}

# Log messages to both stdout and log file
log_message() {
    message="$1"
    timestamped_message="[$(date +'%Y-%m-%d %H:%M:%S')] $message"
    echo -e "$timestamped_message" | tee -a "$LOG_FILE"
}

log_message "**********************************************************"
log_message "Log file initialized at $LOG_FILE"
log_message "Logging all diagnostics to $LOG_FILE"
log_message "**********************************************************"

# Check if the script is run as root else attempt to run with sudo
root_or_try() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        log_message "Not running as root. Attempting to re-run with sudo..."
        sudo "$0" "$@" || {
            log_message "sudo attempt failed or was canceled by user."
            exit 1
        }
        exit 0
    else
        log_message "Error: sudo not available and script is not running as root."
        exit 1
    fi
}

# Port validation helper function
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# Host validation helper function
validate_host() {
    local host="$1"
    # IPv4
    if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    # FQDN 
    if [[ "$host" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# INSTALLATION
# Detects OS and installs networking tools
install_tools() {
    root_or_try install
    log_message "**********************************************************"
    log_message "*** Starting Tool Installation ***"
    log_message "**********************************************************"

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
            packages_to_install="nmap netcat-openbsd tcpdump dnsutils iproute2 iftop net-tools iptraf-ng nethogs nload curl wget lsof tshark"
            ;;
        rhel|mariner|azurelinux) # Red Hat, CBL-Mariner, Azure Linux
            PKG_MANAGER="dnf"
            if ! command -v dnf &> /dev/null; then
                PKG_MANAGER="yum"
            fi
            UPDATE_CMD="$PKG_MANAGER makecache"
            INSTALL_CMD="$PKG_MANAGER install -y"
            # nmap-ncat provides 'nc', bind-utils provides 'nslookup'
            packages_to_install="nmap nmap-ncat tcpdump iproute bind-utils iftop net-tools iptraf-ng nethogs curl wget lsof tshark"
            ;;
        alpine)
            PKG_MANAGER="apk"
            UPDATE_CMD="apk update"
            INSTALL_CMD="apk add"
            packages_to_install="nmap nmap-ncat tcpdump iproute2 bind-tools iftop net-tools iptraf-ng nethogs nload curl wget lsof tshark"
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
    log_message "*** Tool Installation Complete ***"
    log_message "**********************************************************"
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
        log_message "Required troubleshooting tools are missing..."
        read -p "Would you like to run the tool installation now? (y/n): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            install_tools
        else
            log_message "Installation skipped. Cannot proceed without required tools."
            exit 1
        fi
    else
        log_message "Found needed tools to proceed..."
    fi
}

# n/w diagnostics helper function
run_diagnostics() {
    local target_ip="$1"
    local target_port="$2"

    log_message "Proceeding with diagnostics for $target_ip:$target_port..."

    # --- 1. DNS resolution ---
    log_message "DNS lookup (nslookup)"
    if ! nslookup "$target_ip" 2>&1 | sed 's/^/  [dns] /' | tee -a "$LOG_FILE"; then
        log_message "  [dns] did not succeed or try manually if reverse lookup"
    fi
    wait
    log_message "---"

    # --- 2. Network Reachability: nc ---
    log_message "Reachability test (nc)"
    if nc -z -w 3 "$target_ip" "$target_port" >/dev/null 2>&1; then
        log_message "  [nc] Upstream dst reachable"
        nc_rc=0
    else
        log_message "  [nc] Upstream dst NOT reachable. Validate port and IP, try a different destination or a public endpoint and with a different (installed) tool (tcpping, nping)"
        nc_rc=1
    fi
    wait
    log_message "---"

    # --- 3. Network Connectivity + latency: nping ---
    log_message "Connectivity & latency test (nping --tcp-connect)"
    if ! command -v nping >/dev/null 2>&1; then
        log_message "  [nping] not available on this system"
    else
        output="$(nping --tcp-connect -p "$target_port" -c 5 "$target_ip" 2>&1)"

        if echo "$output" | grep -q "TCP connection succeeded"; then
            echo "$output" | awk '/RTT/ {print "  [nping]", $0}' | tee -a "$LOG_FILE"
        else
            log_message "  [nping] Connection attempt failed"
            echo "$output" | sed 's/^/  [nping] /' | tee -a "$LOG_FILE"
        fi
    fi
    wait
    log_message "---"

    # --- 4. Packet capture (120s) - pcap + live diagnostics ---
    log_message "Packet capture (120s)"
    log_message "Capturing TCP + DNS traffic"

    local pcap_file="$PACKET_CAPTURE_FILE"
    local filter="(host $target_ip and port $target_port) or port 53"

    local tcpdump_cmd_all="tcpdump -i any -tttt -nn -w \"$pcap_file\""
    local tcpdump_cmd="tcpdump -i any -tttt -nn -w \"$pcap_file\" \"$filter\""
    local tcpdump_live="tcpdump -i any -tttt -nn \"$filter\" | egrep 'Flags|retransmission|Retransmission|Dup ACK|RST|NXDOMAIN|ServFail|timeout'"

    if [ "$EUID" -ne 0 ]; then
        log_message "Using sudo for tcpdump"
        sudo timeout 120 tcpdump -i any -tttt -nn "$filter" | sed 's/^/  [tcpdump] /' | tee -a "$LOG_FILE" &
        sudo timeout 120 tcpdump -i any -tttt -nn -w "$pcap_file" "$filter" >/dev/null 2>&1
    else
        timeout 120 tcpdump -i any -tttt -nn "$filter" | sed 's/^/  [tcpdump] /' | tee -a "$LOG_FILE" &
        timeout 120 tcpdump -i any -tttt -nn -w "$pcap_file" "$filter" >/dev/null 2>&1
    fi

    wait
    log_message "Packet capture saved to $pcap_file"
    log_message "---"


 # --- 4. Packet capture for 120s ---
    log_message "Packet capture (120s) - TCP + DNS traffic"
    local pcap_file="$PACKET_CAPTURE_FILE"
    local filter="(host $target_ip and port $target_port) or port 53"

    if [ "$EUID" -ne 0 ]; then
        log_message "Using sudo for tcpdump"
        sudo timeout 120 tcpdump -i any -tttt -nn "$filter" | sed 's/^/  [tcpdump] /' | tee -a "$LOG_FILE" &
        sudo timeout 120 tcpdump -i any -tttt -nn -w "$pcap_file" "$filter" >/dev/null 2>&1
    else
        timeout 120 tcpdump -i any -tttt -nn "$filter" | sed 's/^/  [tcpdump] /' | tee -a "$LOG_FILE" &
        timeout 120 tcpdump -i any -tttt -nn -w "$pcap_file" "$filter" >/dev/null 2>&1
    fi
    wait
    log_message "Packet capture saved to $pcap_file"
    log_message "---"

    # --- 5. TCP Stream Summary using tshark ---
    if command -v tshark >/dev/null 2>&1; then
        log_message "Generating TCP stream summary (SYN, SYN-ACK, retransmissions, RTT, SYN_DROP)..."
        tshark -r "$pcap_file" -q -z conv,tcp >/dev/null 2>&1 # ensures tshark can parse TCP
        bash <<'EOF'
STREAMS=$(tshark -r "$pcap_file" -T fields -e tcp.stream | sort -n | uniq)
for stream in $STREAMS; do
    echo "stream $stream:"
    tshark -r "$pcap_file" -Y "tcp.stream==$stream" -T fields \
        -e frame.time_relative \
        -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
        -e tcp.flags -e tcp.seq -e tcp.ack -e tcp.analysis.retransmission \
        | while read -r time src sport dst dport flags seq ack retrans; do
            FLAG_STR=""
            [[ $flags =~ 0x02 ]] && FLAG_STR+="SYN "
            [[ $flags =~ 0x12 ]] && FLAG_STR+="SYN-ACK "
            [[ $flags =~ 0x10 ]] && FLAG_STR+="ACK "
            [[ $flags =~ 0x04 ]] && FLAG_STR+="RST "
            [[ -n $retrans ]] && FLAG_STR+="# retransmission"
            echo "  $src:$sport -> $dst:$dport $FLAG_STR seq=$seq ack=$ack time=${time}s"
        done
    SYN_TIME=$(tshark -r "$pcap_file" -Y "tcp.stream==$stream and tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e frame.time_relative | head -1)
    SYNACK_TIME=$(tshark -r "$pcap_file" -Y "tcp.stream==$stream and tcp.flags.syn==1 and tcp.flags.ack==1" -T fields -e frame.time_relative | head -1)
    if [[ -z $SYNACK_TIME && -n $SYN_TIME ]]; then
        echo "  # no reply → SYN_DROP"
    elif [[ -n $SYN_TIME && -n $SYNACK_TIME ]]; then
        RTT=$(echo "($SYNACK_TIME - $SYN_TIME)*1000" | bc -l)
        printf "  # SYN → SYN-ACK RTT: %.2f ms\n" "$RTT"
    fi
    echo ""
done
EOF
    else
        log_message "tshark not available. Skipping TCP stream summary. Review pcap with tcpdump or wireshark."
    fi
    log_message "---"
    log_message "Diagnostics finished for $target_ip:$target_port"
}


# Tests connectivity to a target on specified ports.
# Usage: test_connectivity "target.com" "80" "443"
test_connectivity() {
    local target="$1"
    # Create an array of ports from the rest of the arguments
    local ports=("${@:2}")

    log_message "**********************************************************"
    log_message "*** Starting Connectivity Test for $target on port(s): ${ports[*]} ***"
    log_message "**********************************************************"
    
    # Check for required tools
    check_tools "nmap" "iftop" "netstat"

    for port in "${ports[@]}"; do
        run_diagnostics "$target" "$port"
    done
    log_message "**********************************************************"
}

# RUN 
run_interactive() {
    log_message "**********************************************************"
    log_message "*** Starting Interactive Diagnostics Mode ***"
    log_message "**********************************************************"
    check_tools "nmap" "iftop" "netstat"

    local target_ip=""
    local target_port=""

    # Detect outbound IP and port. 
    # Prompt only for port number
    read -p "Enter the destination Port to test: " target_port

    # Validate port
    if ! validate_port "$target_port"; then
        log_message "Error: Invalid port specified: '$target_port'. Must be an integer between 1-65535."
        exit 1
    fi

    local connection
    log_message "Detecting active outbound connection for port $target_port..."
    connection=$(netstat -tunp 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | grep -v ':22 ' | grep ":$target_port ")

    if [ -z "$connection" ]; then
        log_message "No ACTIVE outbound connection found for port $target_port. If possible, trigger outbound n/w transactions and try again."
        exit 0
    fi

    target_ip=$(echo "$connection" | awk '{print $5}' | cut -d':' -f1 | head -n1)
    # Extract Process name
    process_info=$(echo "$connection" | awk '{print $7}' | head -n1)  
    process_name=$(echo "$process_info" | cut -d'/' -f2)

    read -p "Detected application process: $process_name , destination: $target_ip:$target_port. Proceed with diagnostics? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_message "Diagnostics canceled by user."
        echo "Run diagnostics manually as needed. Ex: nwutils <fqdn> <port>. See nwutils -h for more options."
        exit 0
    fi

    log_message "Proceeding with diagnostics..."
    run_diagnostics "$target_ip" "$target_port"
    log_message "**********************************************************"
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

TARGET_PORT=""
TARGET_FQDN="$1"
if ! validate_host "$TARGET_FQDN"; then
    log_message "Error: Invalid hostname or IP: '$TARGET_FQDN'"
    exit 1
fi
if [ "$#" -eq 1 ]; then
    test_connectivity "$TARGET_FQDN" "80" "443"
elif [ "$#" -eq 2 ]; then
    TARGET_PORT="$2"
    if ! validate_port "$TARGET_PORT"; then
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
