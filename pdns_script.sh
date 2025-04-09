#!/bin/bash
# PowerDNS Master (PDNS) / Slave (BIND) Setup Script v1.2.1
# ========================================================================
# https://github.com/ENGINYRING/pdns-bind-setup
# Author: ENGINYRING
#
# This script configures a PowerDNS master and associated BIND slaves
# with automatic zone synchronization, IPv6 support, secure API communication,
# enhanced monitoring & backup, and resource checks.
#
# Features:
#   - File-based locking using flock for atomic concurrency control.
#   - Robust input validation/sanitization (including IPv4/IPv6 and domain names).
#   - Secret management with file permission checking and masked logging.
#   - Optional structured (JSON) logging for SIEM integration.
#   - Comprehensive error handling, idempotency and cleanup.
#   - Automatic zone discovery via PowerDNS API (with timeout) and AXFR fallback.
#   - IPv6 support.
#   - Secure API communication (with automatic self-signed certificate generation if needed).
#   - Enhanced monitoring and backup capabilities.
#   - Resource checks for disk space and memory.
#
# WARNING: Review and test thoroughly before production use.

set -euo pipefail
umask 077

# --- Script Metadata ---
SCRIPT_NAME=$(basename "$0")
SCRIPT_VERSION="1.2.1"
LOCK_FILE="/var/lock/${SCRIPT_NAME}.lock"

# --- Global Variables and Defaults ---
# Operation Mode
ROLE_TYPE=""                # 'master' or 'slave'
ACTION="initial"            # For master: 'initial' or 'add-slave'
NONINTERACTIVE=0            # 0 = interactive, 1 = non-interactive

# External Configuration & Logging Options
CONFIG_FILE="/etc/pdns-setup.conf"
LOG_FILE=""                 # Optional log file; defaults to stderr if empty
LOG_LEVEL=2                 # 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG
LOG_FORMAT="${LOG_FORMAT:-plain}"  # "plain" or "json"

# Core paths & settings
PDNS_CONF_DIR="/etc/powerdns"
PDNS_USER="pdns"
PDNS_GROUP="pdns"

# BIND directories and settings (Debian and RHEL)
BIND_CONF_DIR_DEBIAN="/etc/bind"
BIND_CONF_DIR_RHEL="/etc/named"
BIND_SLAVE_ZONE_DIR_DEBIAN="/var/cache/bind/slaves"
BIND_SLAVE_ZONE_DIR_RHEL="/var/named/slaves"
BIND_USER_DEBIAN="bind";   BIND_GROUP_DEBIAN="bind"
BIND_USER_RHEL="named";    BIND_GROUP_RHEL="named"
BIND_CONF_FILE="named.conf"
BIND_CONF_OPTIONS_FILE="named.conf.options"
BIND_CONF_LOCAL_FILE="named.conf.local"
BIND_ZONES_DIR="zones"

# PDNS Backend (MySQL example)
PDNS_BACKEND_TYPE="gmysql"
PDNS_DB_NAME="pdns_prod"
PDNS_DB_USER="pdns_prod_user"
PDNS_DB_HOST="127.0.0.1"
PDNS_DB_PORT="3306"
PDNS_DB_PASSWORD=""
PDNS_DB_PASSWORD_FILE=""
MYSQL_ROOT_PASSWORD=""
MYSQL_ROOT_PASSWORD_FILE=""
PDNS_SCHEMA_URL="https://raw.githubusercontent.com/PowerDNS/pdns/rel/auth-4.8.x/modules/gmysqlbackend/schema.mysql.sql"

# PDNS API / TSIG Secrets and SSL settings
PDNS_API_KEY=""
PDNS_API_KEY_FILE=""
PDNS_API_PORT="8081"
PDNS_API_USE_SSL="yes"     # yes/no (for secure API communication)
# SSL cert settings; auto-generated if empty
PDNS_API_SSL_CERT_DIR=""   # Auto-set based on OS in detect_system()
PDNS_API_SSL_CERT=""
PDNS_API_SSL_KEY=""

# BIND & Slave-specific configuration
PDNS_CONF_D_DIR="${PDNS_CONF_DIR}/pdns.d"
PDNS_SLAVE_CONFIG_SNIPPET="${PDNS_CONF_D_DIR}/90-slaves-axfr.conf"
PDNS_MASTER_MARKER_FILE="/etc/powerdns/.pdns_master_script_configured_axfr"

# Zone synchronization settings
ZONE_SYNC_CRON_SCHEDULE="0 * * * *"  # hourly by default
ZONE_SYNC_SCRIPT="/usr/local/bin/sync_dns_zones.sh"
ZONE_SYNC_ENV_FILE="/etc/default/pdns-zone-sync"
ZONE_SYNC_LOG_DIR="/var/log/pdns-zone-sync"

# DNSSEC Settings
ENABLE_DNSSEC="yes"         # Enable DNSSEC automatically
DNSSEC_KEY_DIR="/etc/powerdns/keys"

# Resource thresholds (configurable)
MIN_DISK_SPACE_MB=500       # Minimum disk space in MB
MIN_MEMORY_MB=256           # Minimum memory in MB

# --- Run-time Variables to be Detected ---
PKG_MANAGER=""
UPDATE_CMD=""
INSTALL_CMD=""
PKG_PDNS=""
PKG_PDNS_MYSQL=""
PKG_MYSQL_SERVER=""
PKG_MYSQL_CLIENT=""
PKG_BIND=""
PKG_UTILS=""
FIREWALL_CMD=""
BIND_CONF_DIR=""            # Set in detect_system()
BIND_USER=""
BIND_GROUP=""
BIND_SLAVE_ZONE_DIR=""

# Central service names (set in detect_system())
PDNS_SERVICE=""
BIND_SERVICE=""

# Associate arrays for slave configuration (Bash 4+ required)
declare -A CURRENT_SLAVES       # Map: slave_ip -> tsig_key_name
declare -A CURRENT_TSIG_KEYS    # Map: tsig_key_name -> key_secret

# --- Helper Functions ---
# run_cmd: executes commands directly if root; otherwise uses sudo.
run_cmd() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# mask_secret: returns secret masked (first 4 and last 4 chars remain).
mask_secret() {
    local secret="$1"
    local len=${#secret}
    if (( len > 8 )); then
        echo "${secret:0:4}...${secret: -4}"
    else
        echo "$secret"
    fi
}

# set_secret: sets variable via indirect parameter expansion.
set_secret() {
    local var_name="$1"
    shift
    printf -v "$var_name" "%s" "$*"
}

# is_valid_domain: basic check for a domain name format.
is_valid_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# check_disk_space: checks if a path has at least a required MB of free disk space.
check_disk_space() {
    local path="${1:-/}"
    local required_mb=${2:-$MIN_DISK_SPACE_MB}
    local available_kb available_mb
    available_kb=$(df -k "$path" | awk 'NR==2 {print $4}')
    available_mb=$(( available_kb / 1024 ))
    if [[ $available_mb -lt $required_mb ]]; then
        log_error "Not enough disk space on $path. Available: ${available_mb}MB, Required: ${required_mb}MB"
    fi
    log_info "Disk space check passed for $path: ${available_mb}MB available"
}

# check_memory: checks for minimum available memory.
check_memory() {
    local required_mb=${1:-$MIN_MEMORY_MB}
    local available_kb available_mb
    available_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    available_mb=$(( available_kb / 1024 ))
    if [[ $available_mb -lt $required_mb ]]; then
        log_error "Not enough memory. Available: ${available_mb}MB, Required: ${required_mb}MB"
    fi
    log_info "Memory check passed: ${available_mb}MB available"
}

# validate_ipv4: validates an IPv4 address.
validate_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a octets=($ip)
    if [ "${#octets[@]}" -ne 4 ]; then
        return 1
    fi
    for oct in "${octets[@]}"; do
        if ! [[ "$oct" =~ ^[0-9]+$ ]] || [ "$oct" -gt 255 ] || [ "$oct" -lt 0 ]; then
            return 1
        fi
    done
    return 0
}

# validate_ipv6: validates an IPv6 address (basic check).
validate_ipv6() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    else
        return 1
    fi
}

# validate_ip: validates an IP address as either IPv4 or IPv6.
validate_ip() {
    local ip="$1"
    if validate_ipv4 "$ip" || validate_ipv6 "$ip"; then
        return 0
    else
        return 1
    fi
}

# backup_file: creates a backup copy of a file.
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_path="${file}.bak.$(date +%Y%m%d%H%M%S)"
        if cp -p "$file" "$backup_path"; then
            log_info "Backup of '$file' saved as '$backup_path'."
        else
            log_warn "Failed to create backup for '$file'."
        fi
    fi
}

# read_secret_file: reads a secret from a file; verifies that file permissions are secure.
read_secret_file() {
    local file_path="$1"
    local secret_var_name="$2"
    if [[ -n "$file_path" && -f "$file_path" ]]; then
        local perms owner_uid
        perms=$(stat -c "%a" "$file_path")
        owner_uid=$(stat -c "%u" "$file_path")
        if [[ "$perms" =~ ^[46]00$ && "$owner_uid" == "0" ]]; then
            local secret; secret=$(<"$file_path")
            if [[ -n "$secret" ]]; then
                log_info "Read secret for $secret_var_name from $file_path."
                set_secret "$secret_var_name" "$secret"
                return 0
            else
                log_warn "Secret file $file_path is empty."
            fi
        else
            log_warn "Secret file $file_path has insecure permissions ($perms) or is not owned by root (UID $owner_uid)."
        fi
    fi
    return 1
}

# get_or_generate_secret: obtains a secret from a file or generates/prompts one.
get_or_generate_secret() {
    local secret_var_name="$1"
    local secret_file_var_name="$2"
    local prompt_text="$3"
    local generation_func="$4"
    local generated_secret_file="${5:-}"
    local current_secret; current_secret=$(eval echo "\$$secret_var_name")
    local secret_file_path; secret_file_path=$(eval echo "\$$secret_file_var_name")

    if [[ -n "$current_secret" ]]; then
        log_debug "Secret '$secret_var_name' already set."
        return 0
    fi

    if read_secret_file "$secret_file_path" "$secret_var_name"; then
        return 0
    fi

    if [[ $NONINTERACTIVE -eq 1 ]]; then
        log_info "Generating secret for $secret_var_name in non-interactive mode..."
        local secret_value; secret_value=$($generation_func)
        set_secret "$secret_var_name" "$secret_value"
        log_warn "Generated secret for $secret_var_name; please store it securely. (Value masked: $(mask_secret "$secret_value"))"
        if [[ -n "$generated_secret_file" ]]; then
            log_info "Writing generated secret to $generated_secret_file."
            echo "$secret_value" | run_cmd tee "$generated_secret_file" > /dev/null || log_warn "Failed to write generated secret to file."
            run_cmd chmod 600 "$generated_secret_file" || log_warn "Failed to set permissions on secret file."
            run_cmd chown root:root "$generated_secret_file" || log_warn "Failed to set ownership on secret file."
        fi
    else
        log_info "Secret for $secret_var_name not found; prompting interactively."
        prompt_password_confirm "$prompt_text" "$secret_var_name"
    fi
}

# prompt_password_confirm: prompts user for a password and confirmation.
prompt_password_confirm() {
    local prompt_text="$1"
    local var_name="$2"
    local password=""
    local password_confirm=""
    while true; do
        read -sp "$prompt_text: " password; echo
        read -sp "Confirm password: " password_confirm; echo
        if [[ "$password" == "$password_confirm" ]]; then
            if [[ -z "$password" ]]; then
                echo "Password cannot be empty."
            else
                set_secret "$var_name" "$password"
                break
            fi
        else
            echo "Passwords do not match. Try again."
        fi
    done
}

# --- SSL Certificate Generation ---
generate_ssl_cert() {
    local cert_dir="$1"
    local cert_file="$2"
    local key_file="$3"
    local cn="${4:-pdns-api}"
    
    log_info "Generating self-signed SSL certificate for PowerDNS API..."
    run_cmd mkdir -p "$cert_dir" || log_error "Failed to create certificate directory"
    
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        log_info "SSL certificate already exists, skipping generation."
        return 0
    fi
    
    local ssl_cnf="/tmp/pdns_ssl.cnf"
    cat > "$ssl_cnf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $cn

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $cn
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    run_cmd openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$key_file" -out "$cert_file" \
        -config "$ssl_cnf" --max-time 10 || log_error "Failed to generate SSL certificate"
    
    run_cmd chmod 600 "$key_file"
    run_cmd chmod 644 "$cert_file"
    run_cmd chown "$PDNS_USER:$PDNS_GROUP" "$key_file" "$cert_file"
    rm -f "$ssl_cnf"
    log_info "SSL certificate generated successfully."
}

# --- OS Detection, Package Manager and Service Names ---
detect_system() {
    log_info "Detecting system environment..."
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt-get update -qq"
        INSTALL_CMD="apt-get install -y -qq"
        PKG_PDNS="pdns-server"
        PKG_PDNS_MYSQL="pdns-backend-mysql"
        PKG_MYSQL_SERVER="mariadb-server"
        PKG_MYSQL_CLIENT="mariadb-client"
        PKG_BIND="bind9 bind9utils"
        PKG_UTILS="wget pwgen openssl dnsutils crudini curl jq"
        BIND_CONF_DIR="$BIND_CONF_DIR_DEBIAN"
        BIND_USER="$BIND_USER_DEBIAN"
        BIND_GROUP="$BIND_GROUP_DEBIAN"
        BIND_SLAVE_ZONE_DIR="$BIND_SLAVE_ZONE_DIR_DEBIAN"
        FIREWALL_CMD=$(command -v ufw &>/dev/null && echo "ufw" || echo "")
        PDNS_SERVICE="pdns-server"
        BIND_SERVICE="bind9"
        PDNS_API_SSL_CERT_DIR="/etc/powerdns/ssl"
    elif command -v dnf &> /dev/null || command -v yum &> /dev/null; then
        if command -v dnf &> /dev/null; then
            PKG_MANAGER="dnf"
        else
            PKG_MANAGER="yum"
        fi
        UPDATE_CMD="$PKG_MANAGER check-update -q || true"
        INSTALL_CMD="$PKG_MANAGER install -y -q"
        PKG_PDNS="pdns"
        PKG_PDNS_MYSQL="pdns-backend-mysql"
        PKG_MYSQL_SERVER="mariadb-server"
        PKG_MYSQL_CLIENT="mariadb"
        PKG_BIND="bind bind-utils"
        PKG_UTILS="wget pwgen openssl bind-utils crudini curl jq"
        BIND_CONF_DIR="$BIND_CONF_DIR_RHEL"
        BIND_USER="$BIND_USER_RHEL"
        BIND_GROUP="$BIND_GROUP_RHEL"
        BIND_SLAVE_ZONE_DIR="$BIND_SLAVE_ZONE_DIR_RHEL"
        FIREWALL_CMD=$(command -v firewall-cmd &>/dev/null && echo "firewall-cmd" || echo "")
        PDNS_SERVICE="pdns"
        BIND_SERVICE="named"
        PDNS_API_SSL_CERT_DIR="/etc/pki/pdns"
    else
        log_error "Unsupported package manager. Exiting."
    fi

    if [[ -z "$PDNS_API_SSL_CERT" ]]; then
        PDNS_API_SSL_CERT="$PDNS_API_SSL_CERT_DIR/api-cert.pem"
    fi
    if [[ -z "$PDNS_API_SSL_KEY" ]]; then
        PDNS_API_SSL_KEY="$PDNS_API_SSL_CERT_DIR/api-key.pem"
    fi

    log_info "Package Manager: $PKG_MANAGER"
    log_info "Firewall Tool: ${FIREWALL_CMD:-'None Detected'}"
    log_debug "BIND Config Dir: $BIND_CONF_DIR | BIND User/Group: $BIND_USER/$BIND_GROUP | Slave Dir: $BIND_SLAVE_ZONE_DIR"

    local missing_utils=()
    for util in "pwgen" "openssl" "dig" "curl"; do
        if ! command -v "$util" &>/dev/null; then
            missing_utils+=("$util")
        fi
    done
    if [[ ${#missing_utils[@]} -gt 0 ]]; then
        log_info "Installing required utilities: ${missing_utils[*]}"
        run_cmd $UPDATE_CMD
        for util in "${missing_utils[@]}"; do
            case "$util" in
                "pwgen") run_cmd $INSTALL_CMD pwgen || log_warn "Could not install pwgen." ;;
                "openssl") run_cmd $INSTALL_CMD openssl || log_error "Could not install openssl." ;;
                "dig") 
                    if [[ "$PKG_MANAGER" == "apt" ]]; then
                        run_cmd $INSTALL_CMD dnsutils || log_warn "Could not install dig."
                    else
                        run_cmd $INSTALL_CMD bind-utils || log_warn "Could not install dig."
                    fi ;;
                "curl") run_cmd $INSTALL_CMD curl || log_warn "Could not install curl." ;;
            esac
        done
    fi
}

install_packages() {
    log_action "Installing packages: $@"
    log_debug "Updating package lists..."
    run_cmd $UPDATE_CMD
    run_cmd $INSTALL_CMD "$@" || log_error "Failed to install packages: $@"
}

# --- Firewall Configuration ---
configure_firewall() {
    local port="$1"
    local proto="${2:-tcp}"
    local source_ip="${3:-any}"
    local direction="${4:-in}"
    local ipv6="${5:-no}"  # "yes" if IPv6 rule needed

    if [[ -z "$FIREWALL_CMD" ]]; then
        log_warn "No firewall command detected. Please configure port ${port}/${proto} manually for $direction from/to $source_ip."
        return
    fi

    log_info "Configuring firewall: Port ${port}/${proto}, Direction: ${direction}, Source/Dest: ${source_ip}, IPv6: ${ipv6}"
    if [[ "$FIREWALL_CMD" == "ufw" ]]; then
        local ufw_rule="allow ${direction}"
        [[ "$source_ip" != "any" ]] && ufw_rule+=" from $source_ip"
        ufw_rule+=" to any port $port"
        [[ "$proto" != "any" ]] && ufw_rule+=" proto $proto"
        run_cmd ufw $ufw_rule || log_warn "ufw command failed for rule: [$ufw_rule]"
    elif [[ "$FIREWALL_CMD" == "firewall-cmd" ]]; then
        local zone="public"
        if [[ "$source_ip" == "any" ]]; then
            run_cmd firewall-cmd --permanent --zone=$zone --add-port="${port}/${proto}" || log_warn "firewall-cmd failed adding port ${port}/${proto}"
        else
            if validate_ipv4 "$source_ip"; then
                if [[ "$direction" == "in" ]]; then
                    run_cmd firewall-cmd --permanent --zone=$zone --add-rich-rule="rule family='ipv4' source address='${source_ip}' port port='${port}' protocol='${proto}' accept" || log_warn "firewall-cmd rich rule failed."
                else
                    run_cmd firewall-cmd --permanent --zone=$zone --add-port="${port}/${proto}" || log_warn "firewall-cmd failed for global rule."
                fi
            elif validate_ipv6 "$source_ip" && [[ "$ipv6" == "yes" ]]; then
                if [[ "$direction" == "in" ]]; then
                    run_cmd firewall-cmd --permanent --zone=$zone --add-rich-rule="rule family='ipv6' source address='${source_ip}' port port='${port}' protocol='${proto}' accept" || log_warn "firewall-cmd IPv6 rich rule failed."
                else
                    run_cmd firewall-cmd --permanent --zone=$zone --add-port="${port}/${proto}" || log_warn "firewall-cmd failed for IPv6 global rule."
                fi
            else
                log_warn "Invalid IP address format: $source_ip"
                return 1
            fi
        fi
    else
        log_warn "Unsupported firewall tool: $FIREWALL_CMD"
    fi
}

reload_firewall() {
    if [[ "$FIREWALL_CMD" == "firewall-cmd" ]]; then
        log_info "Reloading firewall-cmd rules..."
        run_cmd firewall-cmd --reload || log_warn "firewall-cmd reload failed."
    elif [[ "$FIREWALL_CMD" == "ufw" ]]; then
        log_debug "ufw rules take effect immediately; reload not required."
    fi
}

# --- Conflict Detection ---
stop_conflicts() {
    log_info "Checking for conflicting services on port 53..."
    local services_to_check=("pdns-recursor" "systemd-resolved" "dnsmasq" "named" "bind9")
    local port_users
    port_users=$(ss -tulnp | grep ':53 ') || true
    for service in "${services_to_check[@]}"; do
        if systemctl is-active --quiet "$service"; then
            if [[ "$ROLE_TYPE" == "master" && "$service" == "pdns-server" ]]; then
                continue
            fi
            if [[ "$ROLE_TYPE" == "slave" && ( "$service" == "named" || "$service" == "bind9" ) ]]; then
                continue
            fi
            if echo "$port_users" | grep -q "$service"; then
                log_warn "Service '$service' is active on port 53. Stopping and disabling it."
                run_cmd systemctl stop "$service" || log_warn "Failed to stop $service."
                run_cmd systemctl disable "$service" || log_warn "Failed to disable $service."
            elif [[ "$service" == "systemd-resolved" ]]; then
                if grep -qE '^DNSStubListener=yes' /etc/systemd/resolved.conf &>/dev/null; then
                    log_warn "Disabling DNSStubListener in systemd-resolved."
                    backup_file /etc/systemd/resolved.conf
                    run_cmd sed -i 's/^DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
                    run_cmd systemctl restart systemd-resolved || log_warn "Failed to restart systemd-resolved."
                fi
            fi
        fi
    done
    if ss -tulnp | grep -q ':53 '; then
        local current_listener
        current_listener=$(ss -tulnp | grep ':53 ')
        if [[ "$ROLE_TYPE" == "master" && ! "$current_listener" =~ (pdns_server|pdns) ]]; then
            log_warn "Port 53 is used by unexpected process: $current_listener"
            if [[ $NONINTERACTIVE -eq 0 ]]; then
                read -p "Continue anyway? [y/N]: " cont
                [[ ! "$cont" =~ ^[Yy]$ ]] && exit 1
            fi
        fi
        if [[ "$ROLE_TYPE" == "slave" && ! "$current_listener" =~ (named|bind9) ]]; then
            log_warn "Port 53 is used by unexpected process: $current_listener"
            if [[ $NONINTERACTIVE -eq 0 ]]; then
                read -p "Continue anyway? [y/N]: " cont
                [[ ! "$cont" =~ ^[Yy]$ ]] && exit 1
            fi
        fi
    fi
}

# --- PDNS Master Functions ---
setup_master_database() {
    if [[ "$PDNS_BACKEND_TYPE" != "gmysql" ]]; then
        log_info "Skipping database setup (backend type is '$PDNS_BACKEND_TYPE')."
        return
    fi

    log_action "Setting up Master Database ($PDNS_BACKEND_TYPE)..."
    check_disk_space "/var/lib/mysql" 200
    check_memory 512
    install_packages "$PKG_MYSQL_SERVER" "$PKG_MYSQL_CLIENT"
    log_info "Ensuring MariaDB is running and enabled..."
    if ! run_cmd systemctl is-active --quiet mariadb; then
        run_cmd systemctl enable --now mariadb || log_error "Failed to start/enable mariadb."
    fi

    get_or_generate_secret "MYSQL_ROOT_PASSWORD" "MYSQL_ROOT_PASSWORD_FILE" \
        "Enter current MariaDB root password (or leave blank for passwordless access)" \
        "generate_random_string"

    local mysql_auth_opts=(-uroot)
    if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
        mysql_auth_opts+=("-p${MYSQL_ROOT_PASSWORD}")
    fi

    if ! run_cmd mysql "${mysql_auth_opts[@]}" -e "SELECT 1;" &>/dev/null; then
        if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
            log_error "Cannot connect to MariaDB as root using provided password."
        fi
        log_warn "Root connection to MariaDB failed; manual intervention may be required."
    fi

    local db_exists
    db_exists=$(run_cmd mysql "${mysql_auth_opts[@]}" -Nse "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$PDNS_DB_NAME';")
    if [[ -z "$db_exists" ]]; then
        log_info "Creating PowerDNS database '$PDNS_DB_NAME'..."
        run_cmd mysql "${mysql_auth_opts[@]}" -e "START TRANSACTION;" || log_error "Failed to start transaction."
        if ! run_cmd mysql "${mysql_auth_opts[@]}" -e "CREATE DATABASE ${PDNS_DB_NAME};"; then
            run_cmd mysql "${mysql_auth_opts[@]}" -e "ROLLBACK;" || log_warn "Failed to rollback transaction."
            log_error "Failed to create database."
        fi
        run_cmd mysql "${mysql_auth_opts[@]}" -e "COMMIT;" || log_warn "Failed to commit transaction."
    else
        log_info "Database '$PDNS_DB_NAME' exists."
    fi

    get_or_generate_secret "PDNS_DB_PASSWORD" "PDNS_DB_PASSWORD_FILE" \
        "Enter new password for database user '$PDNS_DB_USER'" \
        "generate_random_string" \
        "${CONFIG_FILE}.pdns_db_pass.generated"

    local user_exists
    user_exists=$(run_cmd mysql "${mysql_auth_opts[@]}" -Nse "SELECT User FROM mysql.user WHERE User = '$PDNS_DB_USER' AND Host = 'localhost';")
    local grants="SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES"
    if [[ -z "$user_exists" ]]; then
        log_info "Creating database user '$PDNS_DB_USER'..."
        run_cmd mysql "${mysql_auth_opts[@]}" -e "START TRANSACTION;" || log_error "Failed to start transaction."
        if ! run_cmd mysql "${mysql_auth_opts[@]}" -e "CREATE USER '${PDNS_DB_USER}'@'localhost' IDENTIFIED BY '${PDNS_DB_PASSWORD}';"; then
            run_cmd mysql "${mysql_auth_opts[@]}" -e "ROLLBACK;" || log_warn "Failed to rollback transaction."
            log_error "Failed to create database user."
        fi
        if ! run_cmd mysql "${mysql_auth_opts[@]}" -e "GRANT ${grants} ON ${PDNS_DB_NAME}.* TO '${PDNS_DB_USER}'@'localhost';"; then
            run_cmd mysql "${mysql_auth_opts[@]}" -e "ROLLBACK;" || log_warn "Failed to rollback transaction."
            log_error "Failed to grant privileges."
        fi
        run_cmd mysql "${mysql_auth_opts[@]}" -e "COMMIT;" || log_warn "Failed to commit transaction."
        run_cmd mysql "${mysql_auth_opts[@]}" -e "FLUSH PRIVILEGES;"
    else
        log_info "Database user '$PDNS_DB_USER' exists; ensuring privileges..."
        run_cmd mysql "${mysql_auth_opts[@]}" -e "GRANT ${grants} ON ${PDNS_DB_NAME}.* TO '${PDNS_DB_USER}'@'localhost';"
        run_cmd mysql "${mysql_auth_opts[@]}" -e "FLUSH PRIVILEGES;"
    fi

    local tables_exist
    tables_exist=$(run_cmd mysql "${mysql_auth_opts[@]}" "$PDNS_DB_NAME" -Nse "SHOW TABLES LIKE 'domains';")
    if [[ -z "$tables_exist" ]]; then
        log_info "Importing PowerDNS schema..."
        local SCHEMA_FILE="/tmp/pdns_schema_$(date +%s).mysql.sql"
        run_cmd wget --quiet -O "$SCHEMA_FILE" "$PDNS_SCHEMA_URL" --max-time 10 || log_error "Failed to download schema."
        run_cmd mysql -u"$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" -e "START TRANSACTION;" || log_error "Failed to start transaction."
        if ! run_cmd mysql -u"$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" < "$SCHEMA_FILE"; then
            run_cmd mysql -u"$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" -e "ROLLBACK;" || log_warn "Failed to rollback transaction."
            log_error "Failed to import schema."
        fi
        run_cmd mysql -u"$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" -e "COMMIT;" || log_warn "Failed to commit transaction."
        log_info "Schema imported."
    else
        log_info "Schema already imported (table 'domains' exists)."
    fi
    log_info "Database setup complete."
}

parse_slave_config() {
    CURRENT_SLAVES=()
    CURRENT_TSIG_KEYS=()
    if [[ ! -f "$PDNS_SLAVE_CONFIG_SNIPPET" ]]; then
        log_debug "Slave config snippet '$PDNS_SLAVE_CONFIG_SNIPPET' not found."
        return
    fi
    log_debug "Parsing slave configuration from $PDNS_SLAVE_CONFIG_SNIPPET..."
    local current_ips=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed -e 's/^[ \t]*//' -e 's/[ \t]*#.*//' -e 's/[ \t]*$//')
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^allow-axfr-ips=(.*) ]]; then
            current_ips="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ ^tsig-key=([^:]+):([^:]+):(.+) ]]; then
            local key_name="${BASH_REMATCH[1]}"
            local key_secret="${BASH_REMATCH[3]}"
            CURRENT_TSIG_KEYS["$key_name"]="$key_secret"
        fi
    done < "$PDNS_SLAVE_CONFIG_SNIPPET"
    if [[ -n "$current_ips" ]]; then
        IFS=',' read -r -a ip_array <<< "$current_ips"
        for ip in "${ip_array[@]}"; do
            local expected_key_name="tsig-key-${ip//./-}"
            if [[ "$ip" == *":"* ]]; then
                expected_key_name="tsig-key-ipv6-$(echo "$ip" | tr -c '[:alnum:]' '-')"
            fi
            if [[ -v CURRENT_TSIG_KEYS["$expected_key_name"] ]]; then
                CURRENT_SLAVES["$ip"]="$expected_key_name"
            else
                log_warn "IP '$ip' found in config without matching TSIG key '$expected_key_name'."
            fi
        done
    fi
    log_info "Parsed ${#CURRENT_SLAVES[@]} slave configuration(s)."
}

write_slave_config() {
    log_info "Writing slave config snippet to $PDNS_SLAVE_CONFIG_SNIPPET..."
    run_cmd mkdir -p "$(dirname "$PDNS_SLAVE_CONFIG_SNIPPET")"
    run_cmd chown root:"$PDNS_GROUP" "$(dirname "$PDNS_SLAVE_CONFIG_SNIPPET")"
    run_cmd chmod 750 "$(dirname "$PDNS_SLAVE_CONFIG_SNIPPET")"
    local slave_ips_comma=""
    if [[ ${#CURRENT_SLAVES[@]} -gt 0 ]]; then
        slave_ips_comma=$(IFS=,; echo "${!CURRENT_SLAVES[*]}")
    fi
    backup_file "$PDNS_SLAVE_CONFIG_SNIPPET"
    {
        echo "# PowerDNS AXFR/NOTIFY/TSIG Configuration for Slaves"
        echo "# Generated on $(date)"
        echo ""
        if [[ -n "$slave_ips_comma" ]]; then
            echo "allow-axfr-ips=$slave_ips_comma"
            echo "also-notify=$slave_ips_comma"
            echo ""
            echo "# TSIG Keys for Slaves"
            for key_name in "${!CURRENT_TSIG_KEYS[@]}"; do
                local key_used=0
                for slave_key in "${CURRENT_SLAVES[@]}"; do
                    [[ "$key_name" == "$slave_key" ]] && { key_used=1; break; }
                done
                if [[ $key_used -eq 1 ]]; then
                    echo "tsig-key=$key_name:hmac-sha256:${CURRENT_TSIG_KEYS[$key_name]}"
                fi
            done
        else
            echo "# No slaves configured yet."
        fi
    } | run_cmd tee "$PDNS_SLAVE_CONFIG_SNIPPET" > /dev/null
    run_cmd chown root:"$PDNS_GROUP" "$PDNS_SLAVE_CONFIG_SNIPPET"
    run_cmd chmod 640 "$PDNS_SLAVE_CONFIG_SNIPPET"
}

add_slave_to_master() {
    log_action "Adding new BIND slave to master..."
    parse_slave_config
    local new_slave_ip=""
    while true; do
        if [[ $NONINTERACTIVE -eq 1 ]]; then
            new_slave_ip="${NEW_SLAVE_IP:-}"
            [[ -z "$new_slave_ip" ]] && log_error "Non-interactive mode requires NEW_SLAVE_IP to be set."
        else
            read -p "Enter IP address of the new BIND slave (IPv4 or IPv6): " new_slave_ip
        fi
        if ! validate_ip "$new_slave_ip"; then
            log_warn "Invalid IP address: $new_slave_ip"
            [[ $NONINTERACTIVE -eq 1 ]] && exit 1 || continue
        elif [[ -v CURRENT_SLAVES["$new_slave_ip"] ]]; then
            log_warn "Slave with IP '$new_slave_ip' is already configured."
            return 1
        else
            break
        fi
    done

    local new_tsig_key_name
    if [[ "$new_slave_ip" == *":"* ]]; then
        new_tsig_key_name="tsig-key-ipv6-$(echo "$new_slave_ip" | tr -c '[:alnum:]' '-')"
    else
        new_tsig_key_name="tsig-key-${new_slave_ip//./-}"
    fi

    local new_tsig_key_secret
    new_tsig_key_secret=$(generate_tsig_secret)
    if [[ -v CURRENT_TSIG_KEYS["$new_tsig_key_name"] ]]; then
        log_error "Generated TSIG key name '$new_tsig_key_name' already exists."
    fi
    CURRENT_SLAVES["$new_slave_ip"]="$new_tsig_key_name"
    CURRENT_TSIG_KEYS["$new_tsig_key_name"]="$new_tsig_key_secret"
    log_info "Added slave $new_slave_ip with key $new_tsig_key_name. (Secret masked: $(mask_secret "$new_tsig_key_secret"))"

    write_slave_config
    log_info "Adding firewall rules for new slave $new_slave_ip..."
    local is_ipv6="no"
    if [[ "$new_slave_ip" == *":"* ]]; then
        is_ipv6="yes"
    fi
    configure_firewall 53 "tcp" "$new_slave_ip" "in" "$is_ipv6"
    configure_firewall 53 "udp" "$new_slave_ip" "in" "$is_ipv6"
    configure_firewall "$PDNS_API_PORT" "tcp" "$new_slave_ip" "in" "$is_ipv6"
    reload_firewall

    log_info "Reloading PowerDNS configuration..."
    if run_cmd systemctl is-active --quiet "$PDNS_SERVICE"; then
        run_cmd pdns_control reload || run_cmd systemctl reload "$PDNS_SERVICE" || log_warn "Failed to reload PDNS service."
    else
        log_warn "PDNS service not active, reload skipped."
    fi

    log_info "=== New Slave Details (Share securely) ==="
    log_info "IP Address: $new_slave_ip"
    log_info "TSIG Key Name: $new_tsig_key_name"
    log_info "TSIG Algorithm: hmac-sha256"
    log_info "TSIG Key Secret: $(mask_secret "$new_tsig_key_secret")"
    log_info "PowerDNS API Key: $(mask_secret "$PDNS_API_KEY")"
    
    local slave_details_file="/root/.pdns_slave_${new_slave_ip//[:\/.]/_}.txt"
    {
        echo "# PowerDNS Slave Configuration for $new_slave_ip"
        echo "# Generated on $(date)"
        echo "MASTER_IP=$(hostname -I | awk '{print $1}')"
        echo "SLAVE_IP=$new_slave_ip"
        echo "TSIG_KEY_NAME=$new_tsig_key_name"
        echo "TSIG_KEY_SECRET=$new_tsig_key_secret"
        echo "PDNS_API_KEY=$PDNS_API_KEY"
        echo "PDNS_API_PORT=$PDNS_API_PORT"
        if [[ "$PDNS_API_USE_SSL" == "yes" ]]; then
            echo "PDNS_API_USE_SSL=yes"
        fi
    } > "$slave_details_file"
    run_cmd chmod 600 "$slave_details_file"
    log_info "Slave configuration saved to $slave_details_file"
    return 0
}

configure_pdns_master() {
    log_action "Configuring initial PDNS Master..."
    check_disk_space "$PDNS_CONF_DIR" 50 || log_warn "Low disk space for configuration"
    CURRENT_SLAVES=()
    CURRENT_TSIG_KEYS=()
    if [[ $NONINTERACTIVE -eq 0 ]]; then
        while true; do
            read -p "Enter IP address of an initial BIND slave (IPv4 or IPv6, or press Enter to finish): " slave_ip
            [[ -z "$slave_ip" ]] && break
            if ! validate_ip "$slave_ip"; then
                log_warn "Invalid IP: '$slave_ip'."
                continue
            fi
            if [[ -v CURRENT_SLAVES["$slave_ip"] ]]; then
                log_warn "IP '$slave_ip' already entered."
                continue
            fi
            local tsig_key_name
            if [[ "$slave_ip" == *":"* ]]; then
                tsig_key_name="tsig-key-ipv6-$(echo "$slave_ip" | tr -c '[:alnum:]' '-')"
            else
                tsig_key_name="tsig-key-${slave_ip//./-}"
            fi
            local tsig_key_secret; tsig_key_secret=$(generate_tsig_secret)
            if [[ -v CURRENT_TSIG_KEYS["$tsig_key_name"] ]]; then
                log_warn "TSIG key name collision for '$tsig_key_name'."
                continue
            fi
            CURRENT_SLAVES["$slave_ip"]="$tsig_key_name"
            CURRENT_TSIG_KEYS["$tsig_key_name"]="$tsig_key_secret"
            log_info "Added initial slave: $slave_ip | Key: $tsig_key_name"
        done
    fi

    get_or_generate_secret "PDNS_API_KEY" "PDNS_API_KEY_FILE" \
        "Enter new PowerDNS API Key (leave blank to generate)" \
        "generate_random_string" \
        "${CONFIG_FILE}.pdns_api_key.generated"

    if [[ "$PDNS_API_USE_SSL" == "yes" ]]; then
        log_info "Setting up SSL for PowerDNS API..."
        generate_ssl_cert "$PDNS_API_SSL_CERT_DIR" "$PDNS_API_SSL_CERT" "$PDNS_API_SSL_KEY" "pdns-api"
    fi

    log_info "Writing main PowerDNS configuration to ${PDNS_CONF_DIR}/pdns.conf"
    run_cmd mkdir -p "$PDNS_CONF_DIR"
    if [[ ! -f "$PDNS_CONF_DIR/pdns.conf" ]]; then
        cat << EOF | run_cmd tee "$PDNS_CONF_DIR/pdns.conf" > /dev/null
# PowerDNS Main Configuration File (AXFR Master)
# Generated on $(date)
daemon=yes
guardian=yes
setuid=$PDNS_USER
setgid=$PDNS_GROUP
config-dir=$PDNS_CONF_DIR
socket-dir=/var/run/pdns
include-dir=$PDNS_CONF_D_DIR
EOF
        run_cmd chown root:"$PDNS_GROUP" "$PDNS_CONF_DIR/pdns.conf"
        run_cmd chmod 640 "$PDNS_CONF_DIR/pdns.conf"
    else
        log_debug "${PDNS_CONF_DIR}/pdns.conf already exists."
    fi

    run_cmd mkdir -p "$PDNS_CONF_D_DIR"
    run_cmd chown root:"$PDNS_GROUP" "$PDNS_CONF_D_DIR"
    run_cmd chmod 750 "$PDNS_CONF_D_DIR"

    backup_file "${PDNS_CONF_D_DIR}/00-global.conf"
    cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/00-global.conf" > /dev/null
# Global Settings
loglevel=3
log-dns-queries=yes
EOF

    backup_file "${PDNS_CONF_D_DIR}/10-api.conf"
    local slave_ips_comma=""
    if [[ ${#CURRENT_SLAVES[@]} -gt 0 ]]; then
        slave_ips_comma=$(IFS=,; echo "${!CURRENT_SLAVES[*]}")
        if [[ "$PDNS_API_USE_SSL" == "yes" ]]; then
            cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/10-api.conf" > /dev/null
# API Settings
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=0.0.0.0
webserver-port=$PDNS_API_PORT
webserver-allow-from=127.0.0.1,$slave_ips_comma
webserver-password=$PDNS_API_KEY
webserver-loglevel=none
webserver-ssl-key=$PDNS_API_SSL_KEY
webserver-ssl-cert=$PDNS_API_SSL_CERT
EOF
        else
            cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/10-api.conf" > /dev/null
# API Settings
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=0.0.0.0
webserver-port=$PDNS_API_PORT
webserver-allow-from=127.0.0.1,$slave_ips_comma
EOF
        fi
    else
        if [[ "$PDNS_API_USE_SSL" == "yes" ]]; then
            cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/10-api.conf" > /dev/null
# API Settings
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=127.0.0.1
webserver-port=$PDNS_API_PORT
webserver-password=$PDNS_API_KEY
webserver-loglevel=none
webserver-ssl-key=$PDNS_API_SSL_KEY
webserver-ssl-cert=$PDNS_API_SSL_CERT
EOF
        else
            cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/10-api.conf" > /dev/null
# API Settings
api=yes
api-key=$PDNS_API_KEY
webserver=yes
webserver-address=127.0.0.1
webserver-port=$PDNS_API_PORT
EOF
        fi
    fi

    if [[ "$PDNS_BACKEND_TYPE" == "gmysql" ]]; then
        backup_file "${PDNS_CONF_D_DIR}/20-backend-gmysql.conf"
        cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/20-backend-gmysql.conf" > /dev/null
# MySQL Backend Configuration (Master)
launch=$PDNS_BACKEND_TYPE
gmysql-host=$PDNS_DB_HOST
gmysql-port=$PDNS_DB_PORT
gmysql-dbname=$PDNS_DB_NAME
gmysql-user=$PDNS_DB_USER
gmysql-password=$PDNS_DB_PASSWORD
gmysql-dnssec=yes
EOF
    fi

    backup_file "${PDNS_CONF_D_DIR}/30-zone-settings.conf"
    if [[ "$ENABLE_DNSSEC" == "yes" ]]; then
        run_cmd mkdir -p "$DNSSEC_KEY_DIR"
        run_cmd chown "$PDNS_USER:$PDNS_GROUP" "$DNSSEC_KEY_DIR"
        run_cmd chmod 750 "$DNSSEC_KEY_DIR"
        cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/30-zone-settings.conf" > /dev/null
# Zone Settings
master=yes
slave=no
default-soa-edit=INCEPTION-INCREMENT
default-soa-edit-signed=INCEPTION-INCREMENT

# DNSSEC Configuration
dnssec-key-directory=$DNSSEC_KEY_DIR
enable-dnssec-auto-add-keys=yes
automatic-zone-key-distribution=yes
EOF
    else
        cat << EOF | run_cmd tee "${PDNS_CONF_D_DIR}/30-zone-settings.conf" > /dev/null
# Zone Settings
master=yes
slave=no
default-soa-edit=INCEPTION-INCREMENT
default-soa-edit-signed=INCEPTION-INCREMENT
EOF
    fi

    write_slave_config
    run_cmd chown root:"$PDNS_GROUP" "${PDNS_CONF_D_DIR}"/*.conf
    run_cmd chmod 640 "${PDNS_CONF_D_DIR}"/*.conf

    log_info "Configuring firewall rules for Master..."
    configure_firewall 53 "udp" "any" "in" "yes"
    configure_firewall 53 "tcp" "any" "in" "yes"
    
    if [[ ${#CURRENT_SLAVES[@]} -gt 0 ]]; then
        slave_ips_comma=$(IFS=,; echo "${!CURRENT_SLAVES[*]}")
        for slave_ip in "${!CURRENT_SLAVES[@]}"; do
            local is_ipv6="no"
            if [[ "$slave_ip" == *":"* ]]; then
                is_ipv6="yes"
            fi
            configure_firewall 53 "tcp" "$slave_ip" "in" "$is_ipv6"
            configure_firewall "$PDNS_API_PORT" "tcp" "$slave_ip" "in" "$is_ipv6"
        done
    fi
    reload_firewall

    run_cmd touch "$PDNS_MASTER_MARKER_FILE"
    run_cmd chmod 600 "$PDNS_MASTER_MARKER_FILE"
    run_cmd chown root:root "$PDNS_MASTER_MARKER_FILE"

    log_info "*** Master Initial Setup Complete ***"
    if [[ ${#CURRENT_SLAVES[@]} -gt 0 ]]; then
        log_info "Initial Slave Details (share securely):"
        for ip in "${!CURRENT_SLAVES[@]}"; do
            local key_name=${CURRENT_SLAVES[$ip]}
            local secret=${CURRENT_TSIG_KEYS[$key_name]}
            printf "Slave IP: %-15s | TSIG Key Name: %-25s | TSIG Secret: %s\n" "$ip" "$key_name" "$(mask_secret "$secret")"
        done
        log_info "API Key for slave zone discovery: $(mask_secret "$PDNS_API_KEY")"
        if [[ "$PDNS_API_USE_SSL" == "yes" ]]; then
            log_info "API is configured with SSL. Use https://<master-ip>:$PDNS_API_PORT/ for access."
        fi
        log_warn "Ensure TSIG secrets and API key are stored securely if not using secret files."
    fi
}

# --- Monitoring and Backup Functions ---
create_monitoring_scripts() {
    log_info "Creating monitoring scripts for $ROLE_TYPE..."
    
    local monitor_dir="/usr/local/bin"
    local health_check="${monitor_dir}/dns_health_check.sh"
    
    cat <<EOF | run_cmd tee "$health_check" > /dev/null
#!/bin/bash
# DNS Health Check Script
# Generated by pdns-bind-setup

LOG_FILE="/var/log/dns_health.log"
STATUS_FILE="/var/run/dns_health_status"
ALERT_EMAIL="\${ALERT_EMAIL:-root@localhost}"
TIMESTAMP=\$(date '+%Y-%m-%d %H:%M:%S')

log() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*" >> "\$LOG_FILE"
}

check_service() {
    local service="\$1"
    if ! systemctl is-active --quiet "\$service"; then
        log "ERROR: \$service is not running!"
        echo "ERROR: \$service down" > "\$STATUS_FILE"
        return 1
    fi
    return 0
}

check_dns_resolution() {
    local domain="\$1"
    if ! dig +short "\$domain" >/dev/null; then
        log "ERROR: Failed to resolve \$domain"
        echo "ERROR: resolution failure" > "\$STATUS_FILE"
        return 1
    fi
    return 0
}

mkdir -p \$(dirname "\$LOG_FILE")
touch "\$LOG_FILE"
chmod 640 "\$LOG_FILE"

log "Starting DNS health check"

EOF

    if [[ "$ROLE_TYPE" == "master" ]]; then
        cat <<EOF | run_cmd tee -a "$health_check" > /dev/null
if ! check_service "$PDNS_SERVICE"; then
    log "Attempting to restart $PDNS_SERVICE..."
    systemctl restart "$PDNS_SERVICE"
fi

if ! check_service "mariadb"; then
    log "Attempting to restart mariadb..."
    systemctl restart mariadb
fi

if ! curl -s --max-time 10 -o /dev/null -H "X-API-Key: \$PDNS_API_KEY" "http://localhost:$PDNS_API_PORT/api/v1/servers/localhost/zones"; then
    log "ERROR: PowerDNS API is not accessible"
fi

ZONE_COUNT=\$(mysql -u "$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" -Nse "SELECT COUNT(*) FROM domains;" 2>/dev/null)
if [[ -z "\$ZONE_COUNT" || "\$ZONE_COUNT" -eq 0 ]]; then
    log "WARNING: No zones found in PowerDNS database"
fi

log "Zone count: \$ZONE_COUNT"
EOF
    else
        cat <<EOF | run_cmd tee -a "$health_check" > /dev/null
if ! check_service "$BIND_SERVICE"; then
    log "Attempting to restart $BIND_SERVICE..."
    systemctl restart "$BIND_SERVICE"
fi

TRANSFER_ERRORS=\$(grep -i "failed" /var/log/syslog /var/log/messages 2>/dev/null | tail -10)
if [[ -n "\$TRANSFER_ERRORS" ]]; then
    log "WARNING: Zone transfer failures detected"
fi

ZONE_COUNT=\$(find "$BIND_SLAVE_ZONE_DIR" -type f | wc -l)
if [[ "\$ZONE_COUNT" -eq 0 ]]; then
    log "WARNING: No zone files found in $BIND_SLAVE_ZONE_DIR"
fi

log "Zone file count: \$ZONE_COUNT"
EOF
    fi

    cat <<EOF | run_cmd tee -a "$health_check" > /dev/null
if check_dns_resolution "localhost"; then
    log "Local resolution successful"
fi

exit 0
EOF

    run_cmd chmod +x "$health_check"
    
    local cron_file="/etc/cron.d/dns_health_check"
    if [[ ! -f "$cron_file" ]]; then
        cat <<EOF | run_cmd tee "$cron_file" > /dev/null
# DNS Health Check - Created by pdns-bind-setup
*/5 * * * * root $health_check > /dev/null 2>&1
EOF
        log_info "Health check cron job created at $cron_file"
    else
        log_info "Health check cron job already exists at $cron_file"
    fi
}

create_backup_script() {
    log_info "Creating backup script..."
    
    local backup_script="/usr/local/bin/pdns_backup.sh"
    local backup_dir="/var/backups/dns"
    
    cat <<EOF | run_cmd tee "$backup_script" > /dev/null
#!/bin/bash
# DNS Backup Script
# Generated by pdns-bind-setup

BACKUP_DIR="$backup_dir"
RETENTION_DAYS=30
TIMESTAMP=\$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/dns_backup.log"

log() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$*" >> "\$LOG_FILE"
}

mkdir -p "\$BACKUP_DIR"
chmod 700 "\$BACKUP_DIR"

mkdir -p \$(dirname "\$LOG_FILE")
touch "\$LOG_FILE"
chmod 640 "\$LOG_FILE"

log "Starting DNS backup"

BACKUP_SUBDIR="\$BACKUP_DIR/backup_\$TIMESTAMP"
mkdir -p "\$BACKUP_SUBDIR"

EOF

    if [[ "$ROLE_TYPE" == "master" ]]; then
        cat <<EOF | run_cmd tee -a "$backup_script" > /dev/null
log "Backing up PowerDNS database..."
if mysqldump -u "$PDNS_DB_USER" -p"$PDNS_DB_PASSWORD" "$PDNS_DB_NAME" > "\$BACKUP_SUBDIR/pdns_db_backup.sql"; then
    log "Database backup successful."
else
    log "ERROR: Database backup failed."
fi

log "Backing up configuration files..."
if tar czf "\$BACKUP_SUBDIR/pdns_config.tar.gz" "$PDNS_CONF_DIR"; then
    log "Configuration backup successful."
else
    log "ERROR: Configuration backup failed."
fi

if [[ -d "$DNSSEC_KEY_DIR" ]]; then
    log "Backing up DNSSEC keys..."
    if tar czf "\$BACKUP_SUBDIR/pdns_dnssec_keys.tar.gz" "$DNSSEC_KEY_DIR"; then
        log "DNSSEC keys backup successful."
    else
        log "ERROR: DNSSEC keys backup failed."
    fi
fi
EOF
    else
        cat <<EOF | run_cmd tee -a "$backup_script" > /dev/null
log "Backing up slave zone files..."
if tar czf "\$BACKUP_SUBDIR/bind_zones.tar.gz" "$BIND_SLAVE_ZONE_DIR"; then
    log "Zone files backup successful."
else
    log "ERROR: Zone files backup failed."
fi

log "Backing up configuration files..."
if tar czf "\$BACKUP_SUBDIR/bind_config.tar.gz" "$BIND_CONF_DIR"; then
    log "Configuration backup successful."
else
    log "ERROR: Configuration backup failed."
fi

if [[ -f "$ZONE_SYNC_ENV_FILE" ]]; then
    log "Backing up credentials..."
    if cp "$ZONE_SYNC_ENV_FILE" "\$BACKUP_SUBDIR/credentials.env"; then
        chmod 600 "\$BACKUP_SUBDIR/credentials.env"
        log "Credentials backup successful."
    else
        log "ERROR: Credentials backup failed."
    fi
fi
EOF
    fi

    cat <<EOF | run_cmd tee -a "$backup_script" > /dev/null
cd "\$BACKUP_DIR"
tar czf "backup_\$TIMESTAMP.tar.gz" "backup_\$TIMESTAMP"
rm -rf "backup_\$TIMESTAMP"

log "Cleaning up backups older than \$RETENTION_DAYS days..."
find "\$BACKUP_DIR" -name "backup_*.tar.gz" -type f -mtime +\$RETENTION_DAYS -delete

if [[ -f "\$LOG_FILE" && \$(stat -c%s "\$LOG_FILE") -gt 1048576 ]]; then
    mv "\$LOG_FILE" "\$LOG_FILE.old"
    touch "\$LOG_FILE"
    chmod 640 "\$LOG_FILE"
fi

log "Backup completed successfully."
exit 0
EOF

    run_cmd chmod +x "$backup_script"
    
    local cron_file="/etc/cron.d/dns_backup"
    if [[ ! -f "$cron_file" ]]; then
        cat <<EOF | run_cmd tee "$cron_file" > /dev/null
# DNS Backup - Created by pdns-bind-setup
0 2 * * * root $backup_script > /dev/null 2>&1
EOF
        log_info "DNS backup cron job created at $cron_file"
    else
        log_info "DNS backup cron job already exists at $cron_file"
    fi
    
    log_info "Backup script created at $backup_script"
    log_info "Backup files will be stored in $backup_dir"
}

# --- Command-line Option Parsing ---
usage() {
    echo "Usage: $SCRIPT_NAME [options]"
    echo ""
    echo "Core Options:"
    echo "  -r, --role [master|slave]       (Required) Set node role."
    echo "  -a, --action [initial|add-slave]  Action for master role (default: initial)."
    echo "  -n, --noninteractive            Run in non-interactive mode (requires env vars/config file)."
    echo ""
    echo "Configuration & Logging:"
    echo "  -c, --config FILE               Path to configuration file (default: $CONFIG_FILE)."
    echo "  --log-file FILE                 Path to log file (default: stderr only)."
    echo "  --log-level LEVEL               Log level: 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG (default: $LOG_LEVEL)."
    echo "  --log-format [plain|json]       Log output format (default: $LOG_FORMAT)."
    echo ""
    echo "Security & API Options:"
    echo "  --use-ssl [yes|no]              Use HTTPS for PowerDNS API (default: $PDNS_API_USE_SSL)."
    echo "  --ssl-cert FILE                 Path to SSL certificate (default: auto-generated)."
    echo "  --ssl-key FILE                  Path to SSL private key (default: auto-generated)."
    echo ""
    echo "Non-Interactive Slave Setup Env Vars:"
    echo "  MASTER_IP                       Master's IP address (IPv4 or IPv6)."
    echo "  TSIG_KEY_NAME                   TSIG Key name for this slave."
    echo "  TSIG_SECRET_FILE                Path to file containing TSIG secret."
    echo "  PDNS_API_KEY                    PowerDNS API key for zone discovery."
    echo "  PDNS_API_USE_SSL                Whether to use HTTPS for API access (yes/no)."
    echo "  (Alternatively, TSIG_KEY_SECRET may be provided.)"
    echo ""
    echo "Non-Interactive Add Slave Env Vars:"
    echo "  NEW_SLAVE_IP                    IP address of the new slave to add (IPv4 or IPv6)."
    echo ""
    echo "Secret Handling Env Vars:"
    echo "  PDNS_DB_PASSWORD_FILE           Path to PDNS DB password file."
    echo "  MYSQL_ROOT_PASSWORD_FILE        Path to MariaDB root password file."
    echo "  PDNS_API_KEY_FILE               Path to PDNS API Key file."
    echo ""
    echo "  -h, --help                      Show this help message."
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--role)
            ROLE_TYPE="${2,,}"; shift 2 ;;
        -a|--action)
            ACTION="${2,,}"; shift 2 ;;
        -n|--noninteractive)
            NONINTERACTIVE=1; shift ;;
        -c|--config)
            CONFIG_FILE="$2"; shift 2 ;;
        --log-file)
            LOG_FILE="$2"; shift 2 ;;
        --log-level)
            LOG_LEVEL="$2"; shift 2 ;;
        --log-format)
            LOG_FORMAT="$2"; shift 2 ;;
        --use-ssl)
            PDNS_API_USE_SSL="${2,,}"; shift 2 ;;
        --ssl-cert)
            PDNS_API_SSL_CERT="$2"; shift 2 ;;
        --ssl-key)
            PDNS_API_SSL_KEY="$2"; shift 2 ;;
        -h|--help)
            usage ;;
        *)
            log_warn "Unknown option: $1"
            usage ;;
    esac
done

log_start "Script $SCRIPT_NAME v$SCRIPT_VERSION starting."
check_bash_version
check_root
acquire_lock

if [[ -n "$CONFIG_FILE" ]]; then
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE..."
        if grep -q -v -E '^\s*#|^\s*$|^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_FILE"; then
            log_warn "Config file $CONFIG_FILE contains unsafe lines. Skipping."
        else
            # shellcheck source=/dev/null
            source "$CONFIG_FILE" || log_warn "Failed to load configuration from $CONFIG_FILE."
        fi
    else
        log_info "Configuration file $CONFIG_FILE not found; using defaults."
    fi
fi

if [[ -z "$ROLE_TYPE" || ! "$ROLE_TYPE" =~ ^(master|slave)$ ]]; then
    log_error "Role (-r or --role) must be specified as 'master' or 'slave'."
fi
if [[ "$ROLE_TYPE" == "master" && ! "$ACTION" =~ ^(initial|add-slave)$ ]]; then
    log_error "For master role, action (-a or --action) must be 'initial' or 'add-slave'."
fi
if [[ ! "$LOG_LEVEL" =~ ^[0-3]$ ]]; then
    log_warn "Invalid log level '$LOG_LEVEL'. Defaulting to 2 (INFO)."
    LOG_LEVEL=2
fi

log_info "Role: $ROLE_TYPE | Action: $ACTION | Mode: $([[ $NONINTERACTIVE -eq 1 ]] && echo 'Non-Interactive' || echo 'Interactive') | Config: $CONFIG_FILE"
detect_system

dependencies=( "wget" "pwgen" "openssl" "dig" "systemctl" "ss" "logger" "sed" "grep" "chmod" "chown" "mkdir" "rmdir" "tee" )
if [[ "$ROLE_TYPE" == "master" ]]; then
    dependencies+=( "pdns_server" "pdns_control" "mysql" )
elif [[ "$ROLE_TYPE" == "slave" ]]; then
    dependencies+=( "named" "named-checkconf" "rndc" )
fi
for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        log_error "Dependency '$dep' not found in PATH."
    fi
done
log_debug "All dependencies verified."

check_disk_space "/" || log_warn "Low disk space on system"
check_memory || log_warn "Low available memory"

if [[ "$ROLE_TYPE" == "master" && -f "$PDNS_MASTER_MARKER_FILE" ]]; then
    log_info "Existing PDNS Master configuration detected."
    if [[ "$ACTION" == "initial" ]]; then
        log_warn "Master marker exists but action is 'initial'."
        if [[ $NONINTERACTIVE -eq 0 ]]; then
            read -p "Master seems already set up. Add a slave instead? [y/N]: " add_instead
            if [[ "$add_instead" =~ ^[Yy]$ ]]; then
                ACTION="add-slave"
            else
                log_info "Exiting."
                exit 0
            fi
        else
            log_info "Forcing 'add-slave' in non-interactive mode due to marker."
            ACTION="add-slave"
        fi
    fi
    if [[ "$ACTION" == "add-slave" ]]; then
        add_slave_to_master || log_error "Failed to add slave."
    else
        log_error "Invalid action '$ACTION' for existing master configuration."
    fi
else
    if [[ "$ROLE_TYPE" == "master" && "$ACTION" != "initial" ]]; then
        log_error "Master marker not found, but action is '$ACTION'. Use 'initial' for first run."
    fi
    log_info "--- Performing Initial Setup for role '$ROLE_TYPE' ---"
    if [[ $NONINTERACTIVE -eq 0 ]]; then
        read -p "Proceed with initial setup? [y/N]: " confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && { log_info "Exiting."; exit 0; }
    fi

    stop_conflicts

    if [[ "$ROLE_TYPE" == "master" ]]; then
        log_info "Starting Initial Master Setup (PowerDNS)..."
        install_packages "$PKG_PDNS" "$PKG_PDNS_MYSQL" "$PKG_UTILS"
        if [[ "$PDNS_BACKEND_TYPE" == "gmysql" ]]; then
            setup_master_database
        else
            log_info "Skipping DB setup for backend type: $PDNS_BACKEND_TYPE."
        fi
        configure_pdns_master
        log_info "Starting services on Master..."
        if [[ "$PDNS_BACKEND_TYPE" == "gmysql" ]]; then
            run_cmd systemctl enable --now mariadb || log_warn "Failed to start mariadb."
        fi
        run_cmd systemctl enable --now "$PDNS_SERVICE" || log_error "Failed to start PDNS."
        run_cmd systemctl status "$PDNS_SERVICE" --no-pager || log_warn "PDNS status not available."
    elif [[ "$ROLE_TYPE" == "slave" ]]; then
        log_info "Starting Initial Slave Setup (BIND)..."
        install_packages "$PKG_BIND" "$PKG_UTILS"
        configure_bind_slave
        log_info "Starting BIND service on Slave..."
        local service_name="$BIND_SERVICE"
        log_info "Running named-checkconf..."
        if run_cmd named-checkconf -z; then
            run_cmd systemctl enable --now "$service_name" || log_error "Failed to start $service_name."
            run_cmd systemctl status "$service_name" --no-pager || log_warn "$service_name status not available."
            if [[ -f "$ZONE_SYNC_SCRIPT" ]]; then
                log_info "Running initial zone synchronization..."
                run_cmd "$ZONE_SYNC_SCRIPT" || log_warn "Initial zone sync returned an error. Check logs."
            fi
        else
            log_error "named-checkconf failed! Review BIND configuration."
        fi
    fi
    log_info "--- Initial Setup Complete ---"
    log_info "Your DNS master-slave setup is now configured with automatic zone synchronization."
fi

# Optionally create monitoring and backup scripts
create_monitoring_scripts
create_backup_script

log_end "Script $SCRIPT_NAME finished successfully."
exit 0
