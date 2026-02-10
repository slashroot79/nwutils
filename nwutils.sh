#!/bin/bash

# ==============================================================================
# Basic Network Diagnostics Script for Azure Linux Envionments
# Author: Ragu Karuturi 
# This script provides multiple functions for network troubleshooting:
# 1. install: Installs a suite of networking tools based on the detected OS.
# 2. <target> [port]: Tests connectivity to a target FQDN or IP. Default ports 80 and 443.
# 3. run: Interactive mode to detect outbound connections and run diagnostics.
# ==============================================================================

SCRIPT_VERSION="1.2.7"

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
log_message "Network Diagnostics Script Version: $SCRIPT_VERSION"
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
            packages_to_install="nmap bc netcat-openbsd tcpdump dnsutils iproute2 iftop net-tools iptraf-ng nethogs nload curl wget lsof tshark"
            ;;
        rhel|mariner|azurelinux) # Red Hat, CBL-Mariner, Azure Linux
            PKG_MANAGER="dnf"
            if ! command -v dnf &> /dev/null; then
                PKG_MANAGER="yum"
            fi
            UPDATE_CMD="$PKG_MANAGER makecache"
            INSTALL_CMD="$PKG_MANAGER install -y"
            # nmap-ncat provides 'nc', bind-utils provides 'nslookup'
            packages_to_install="nmap bc nmap-ncat tcpdump iproute bind-utils iftop net-tools iptraf-ng nethogs curl wget lsof tshark"
            ;;
        alpine)
            PKG_MANAGER="apk"
            UPDATE_CMD="apk update"
            INSTALL_CMD="apk add"
            packages_to_install="nmap bc nmap-ncat tcpdump iproute2 bind-tools iftop net-tools iptraf-ng nethogs nload curl wget lsof tshark"
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
        log_message "Troubleshooting tools found...skipping installation..."
    fi
}

dns_lookup() {
    local target_ip="$1"
    if [[ "$target_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_message "  [dns] Reverse lookup (IP → name)"

        if out=$(dig +short -x "$target_ip" 2>/dev/null); then
            if [ -n "$out" ]; then
                echo "$out" | sed 's/^/  [dns] /' | tee -a "$LOG_FILE"
                return
            fi
        fi

        if out=$(nslookup "$target_ip" 2>/dev/null); then
            echo "$out" | sed 's/^/  [dns] /' | tee -a "$LOG_FILE"
        else
            log_message "  [dns] No PTR record found (normal for many IPs)"
        fi

    else
        log_message "  [dns] Forward lookup (name → IP)"

        if out=$(dig +short "$target_ip" 2>/dev/null); then
            if [ -n "$out" ]; then
                echo "$out" | sed 's/^/  [dns] /' | tee -a "$LOG_FILE"
                return
            fi
        fi

        if out=$(nslookup "$target_ip" 2>/dev/null); then
            echo "$out" | sed 's/^/  [dns] /' | tee -a "$LOG_FILE"
        else
            log_message "  [dns] Forward lookup failed"
        fi
    fi
}

run_nping() {
    local target_ip="$1"
    local target_port="$2"

    if ! command -v nping >/dev/null 2>&1; then
        log_message "  [nping] not installed on this system"
        return
    fi

    local output
    output=$(nping --tcp-connect -p "$target_port" -c 5 "$target_ip" 2>&1)
    
    echo "$output" | awk -v log_file="$LOG_FILE" '
    /Max rtt:/ { 
        print "  [nping]", $0 > log_file
        max_rtt=$3; min_rtt=$6; avg_rtt=$9
    }
    /TCP connection attempts:/ {
        print "  [nping]", $0 > log_file
        success=$7+0
        fail=$10+0
        if (success>0) {
            print "  [nping] Connectivity SUCCESS: " success " of " ($7+$10) " connections worked" > log_file
        } else {
            print "  [nping] Connectivity FAILED: All attempts failed" > log_file
        }
    }'
    echo "$output" | awk -v log_file="$LOG_FILE" '/SENT|RCVD/ {print "  [nping]", $0 > log_file}'
}


# n/w diagnostics helper function
run_diagnostics() {
    local target_ip="$1"
    local target_port="$2"

    log_message "Proceeding with diagnostics for $target_ip:$target_port..."

    # --- 1. DNS resolution ---
    log_message ""
    log_message "DNS lookup (nslookup)"
    dns_lookup "$target_ip"
    log_message "----------------------------------------------------------"

    # --- 2. Network Reachability: nc ---
    log_message ""
    log_message "Reachability test (nc)"
    if nc -z -w 3 "$target_ip" "$target_port" >/dev/null 2>&1; then
        log_message "  [nc] Success...destination is reachable"
        nc_rc=0
    else
        log_message "  [nc] Upstream dst NOT reachable. Validate port and IP, try a different destination or a public endpoint and with a different (installed) tool (tcpping, nping)"
        nc_rc=1
    fi
    log_message "----------------------------------------------------------"

    # --- 3. Network Connectivity + latency: nping ---
    log_message ""
    log_message " \\n Connectivity & latency test (nping --tcp-connect)"
    run_nping "$target_ip" "$target_port"
    log_message "----------------------------------------------------------"

    # --- 4. Packet capture (120s) - pcap + live diagnostics ---
    log_message ""
    log_message "Packet capture (120s)...capturing TCP + DNS traffic and generating pcap files..."

    local pcap_file="$PACKET_CAPTURE_FILE"
    local filter="(host $target_ip and port $target_port) or port 53"

    local tcpdump_cmd="tcpdump -i any -tttt -nn -U -w \"$pcap_file\""
    # local tcpdump_live="tcpdump -i any -tttt -U -nn \"$filter\" | egrep 'Flags|retransmission|Retransmission|Dup ACK|RST|NXDOMAIN|ServFail|timeout'"

    if [ "$EUID" -ne 0 ]; then
        log_message "Using sudo for tcpdump"
        sudo timeout 120 bash -c "$tcpdump_cmd" >/dev/null 2>&1
    else
        timeout 120 bash -c "$tcpdump_cmd" >/dev/null 2>&1
    fi
    log_message "Packet capture saved to $pcap_file"
    log_message "----------------------------------------------------------"

# --- 5. TCP Stream Summary using tshark ---
    exec > >(tee -a "$LOG_FILE") 2>&1
    log_message ""
    log_message "TCP Analysis summary for $target_ip:$target_port"
    log_message "
    LEGEND (TCP Flags String: [C E U A P R S F])
    --------------------------------------------
    C = CWR (Congestion Window Reduced)
    E = ECE (ECN-Echo)
    U = URG (Urgent)
    A = ACK (Acknowledgment)
    P = PSH (Push)
    R = RST (Reset)
    S = SYN (Synchronize)
    F = FIN (Finish)
    * = Flag not set
    --------------------------------------------"

# Apply display filter to analyze only target TCP + DNS packets
    tshark -r "$pcap_file" -Y "(tcp.port == $target_port && ip.addr == $target_ip) || (dns)" -T fields \
    -e tcp.stream \
    -e frame.time_relative \
    -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
    -e tcp.flags.str -e tcp.seq -e tcp.ack \
    -e tcp.len \
    -e tcp.analysis.ack_rtt \
    -e tcp.analysis.retransmission \
    -e tcp.analysis.lost_segment \
    -E header=y -E separator=/t | awk -F'\t' '
BEGIN {
    current_stream = -1;
}
{
    if ($1 == "tcp.stream") next;

    stream = $1; time = $2; src = $3 ":" $4; dst = $5 ":" $6;
    flags = $7; seq = $8; ack = $9; bytes = $10; rtt = $11; retrans = $12; lost = $13;

    # Initialize per-stream stats
    if (!(stream in stream_bytes_sent)) {
        stream_bytes_sent[stream] = 0;
        stream_bytes_recv[stream] = 0;
        stream_retrans[stream] = 0;
        stream_syn_sent[stream] = 0;
        stream_synack_received[stream] = 0;
        stream_start_time[stream] = time;
        stream_end_time[stream] = time;
        stream_push_detected[stream] = 0;
    }

    # Update direction-based bytes
    if (src ~ "'"$target_ip"'") {
        stream_bytes_sent[stream] += bytes;
    } else {
        stream_bytes_recv[stream] += bytes;
    }

    # Track retransmissions
    if (retrans != "") stream_retrans[stream]++;

    # Detect push
    if (flags ~ /P/) stream_push_detected[stream] = 1;

    # Track SYN/SYN-ACK
    if (flags ~ /S/ && flags !~ /A/) stream_syn_sent[stream]++;
    if (flags ~ /S/ && flags ~ /A/) stream_synack_received[stream]++;

    # Update connection end time
    stream_end_time[stream] = time;

    # Print per-packet details
    if (stream != current_stream) {
        if (current_stream != -1) print "\n----------------------------------------------------------";
        print "\n[ STREAM ID: " stream " ]";
        printf "%-10s | %-28s | %-10s | %-8s | %-8s | %-5s | %-8s | %-8s | %-8s\n", "Time", "Src -> Dst", "Flags", "Seq", "Ack", "Bytes", "RTT(ms)", "Push", "Retrans";
        print "----------------------------------------------------------------------------------------------------";
        current_stream = stream;
    }

    rtt_disp = (rtt != "" ? sprintf("%.2f", rtt * 1000) : "-");
    push_flag = (stream_push_detected[stream] ? "YES" : "NO");
    retrans_flag = (retrans != "" ? "YES" : "NO");

    printf "%-10.4f | %-28s | %-10s | %-8s | %-8s | %-5s | %-8s | %-8s | %-8s\n", time, src " -> " dst, flags, seq, ack, bytes, rtt_disp, push_flag, retrans_flag;
}
END {
    print "\n============================================================";
    print "FINAL STREAM SUMMARY";
    print "============================================================";

    for (s in stream_bytes_sent) {
        duration = stream_end_time[s] - stream_start_time[s];
        syn_drops = stream_syn_sent[s] - stream_synack_received[s];
        retrans_pct = (stream_retrans[s] > 0 ? sprintf("%.2f", (stream_retrans[s]/(stream_retrans[s]+1))*100) : "0.00");

        printf "[Stream %s] Duration: %.3fs | Bytes Sent: %d | Bytes Recv: %d | Retrans: %d (%s%%) | SYN drops: %d | Push detected: %s\n",
            s, duration, stream_bytes_sent[s], stream_bytes_recv[s], stream_retrans[s], retrans_pct, syn_drops, (stream_push_detected[s] ? "YES" : "NO");
    }
    print "============================================================";
}'
    log_message "----------------------------------------------------------"
    log_message "Diagnostics finished for $target_ip:$target_port"
}

# Tests connectivity to a target on specified ports.
# Usage: test_connectivity "target.com" "80" "443"
test_connectivity() {
    local target="$1"
    # Create an array of ports from the rest of the arguments
    local ports=("${@:2}")

    log_message "*** Starting tests for $target on port(s): ${ports[*]} ***"
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
    log_message "*** Starting tests in Interactive Mode ***"
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

# Show script version
show_version() {
    echo "Network Diagnostics Script - Version $SCRIPT_VERSION"
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
    -v|--version)
        show_version
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
