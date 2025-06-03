[![ENGINYRING](https://cdn.enginyring.com/img/logo_dark.png)](https://www.enginyring.com)

# WORK IN PROGRESS! DO NOT USE IN PRODUCTION


# PowerDNS Master / BIND Slave Setup Script v1.2.1
A robust, production-grade Bash script for configuring PowerDNS master servers and BIND slave servers with automatic zone synchronization. This script implements a comprehensive DNS infrastructure with secure zone transfers, monitoring, and backup capabilities.

## Features

- **Automated DNS Infrastructure**:
  - Fully automated master/slave DNS setup
  - Automatic zone synchronization between master and slaves
  - Handles both initial setup and slave addition

- **Security-Focused**:
  - Secure TSIG authentication for zone transfers
  - Optional SSL/TLS for PowerDNS API access
  - Secret management with file permission checking and masked logging
  - Proper input validation and sanitization 

- **Advanced Networking Support**:
  - Full IPv6 support alongside IPv4
  - Automatic firewall configuration
  - Intelligent network conflict detection

- **Robust Operations**:
  - File-based locking using flock for atomic concurrency control
  - Comprehensive error handling with graceful failure
  - Resource checks for disk space and memory
  - Transaction-based database operations

- **Monitoring & Maintenance**:
  - Automated health check scripts with alerting
  - Scheduled backup system with retention policy
  - Cleanup of old backups and log rotation

- **Flexible Implementation**:
  - Interactive and non-interactive modes
  - Configuration file support
  - Support for both Debian/Ubuntu and RHEL/CentOS systems
  - Optional structured (JSON) logging for SIEM integration

## Requirements

- Linux system with Bash 4.0 or later
- Root or sudo access
- For PowerDNS master server:
  - PowerDNS server with MySQL backend support
  - MariaDB/MySQL server
- For BIND slave server:
  - BIND 9.x (named)
- Common utilities: wget, openssl, curl, etc.

## Installation

1. Download the script:
   ```bash
   wget https://github.com/ENGINYRING/pdns-bind-setup/raw/main/pdns_script.sh
   chmod +x pdns_script.sh
   ```

2. Run the script with appropriate options (see Usage below).

## Usage

### Setting up a PowerDNS Master Server

```bash
# Interactive mode
sudo ./pdns_script.sh --role master --action initial

# Non-interactive mode with configuration file
sudo ./pdns_script.sh --role master --action initial --noninteractive --config /path/to/config.conf
```

### Adding a New Slave to an Existing Master

```bash
# Interactive mode
sudo ./pdns_script.sh --role master --action add-slave

# Non-interactive mode
sudo NEW_SLAVE_IP=192.168.1.10 ./pdns_script.sh --role master --action add-slave --noninteractive
```

### Setting up a BIND Slave Server

```bash
# Interactive mode
sudo ./pdns_script.sh --role slave

# Non-interactive mode
sudo MASTER_IP=192.168.1.5 TSIG_KEY_NAME=tsig-key-192-168-1-5 \
     TSIG_SECRET_FILE=/path/to/secret ./pdns_script.sh --role slave --noninteractive
```

### Command Line Options

```
Core Options:
  -r, --role [master|slave]        (Required) Set node role
  -a, --action [initial|add-slave] Action for master role (default: initial)
  -n, --noninteractive             Non-interactive mode (requires env vars/config file)

Configuration & Logging:
  -c, --config FILE                Path to configuration file
  --log-file FILE                  Path to log file
  --log-level LEVEL                Log level: 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG
  --log-format [plain|json]        Log output format

Security & API Options:
  --use-ssl [yes|no]               Use HTTPS for PowerDNS API
  --ssl-cert FILE                  Path to SSL certificate
  --ssl-key FILE                   Path to SSL private key
```

## Configuration

### Configuration File

You can create a configuration file (default: `/etc/pdns-setup.conf`) with settings like:

```bash
# PowerDNS Database Settings
PDNS_BACKEND_TYPE="gmysql"
PDNS_DB_NAME="pdns_prod"
PDNS_DB_USER="pdns_user"
PDNS_DB_HOST="127.0.0.1"
PDNS_DB_PORT="3306"
PDNS_DB_PASSWORD_FILE="/etc/pdns/db_password.secret"

# API Settings
PDNS_API_PORT="8081"
PDNS_API_USE_SSL="yes"
PDNS_API_KEY_FILE="/etc/pdns/api_key.secret"

# DNSSEC Settings
ENABLE_DNSSEC="yes"
DNSSEC_KEY_DIR="/etc/powerdns/keys"

# Zone Sync Settings (for slaves)
ZONE_SYNC_CRON_SCHEDULE="0 * * * *"  # hourly by default
```

### Secret Management

The script supports secure secret management through files:

```bash
# Create a secure password file
echo "your-secure-password" > /etc/pdns/db_password.secret
chmod 600 /etc/pdns/db_password.secret
chown root:root /etc/pdns/db_password.secret
```

## Architecture

The script implements a standard DNS architecture:

1. **PowerDNS Master**:
   - Authoritative DNS server with MySQL/MariaDB backend
   - Primary zone data storage and management
   - API for zone/record management
   - Automatic notification to slaves on zone changes
   - TSIG authentication for secure zone transfers

2. **BIND Slaves**:
   - Receive zone data via AXFR/IXFR from master
   - Authenticate using TSIG keys
   - Automatically discover and configure new zones
   - Provide redundancy and load distribution

## Security Considerations

- TSIG keys secure all zone transfers
- API access can be secured with HTTPS (self-signed or custom certificates)
- Secrets are stored in permission-restricted files (600)
- Database credentials are properly secured
- Input validation prevents command injection
- Firewall rules are automatically configured to restrict access

## Monitoring and Maintenance

The script automatically installs:

1. **Health Monitoring**: 
   - Regular service checks via cron job
   - Email alerts for failures
   - Resolution testing

2. **Automated Backups**:
   - Daily backups of all configuration and data
   - 30-day retention policy
   - Backup rotation and log management

3. **Zone Synchronization**:
   - Hourly checks for new or deleted zones
   - Automatic configuration of newly discovered zones

## Troubleshooting

Common issues and their solutions:

1. **Service won't start**: Check logs with `journalctl -u pdns-server` or `journalctl -u named`

2. **Zones not transferring**: Verify TSIG key configuration and check logs for transfer errors

3. **API connectivity issues**: Check SSL certificates and firewall rules

4. **Database connection errors**: Verify credentials and database server status

5. **Resource constraints**: Ensure system meets minimum requirements for disk space and memory

## License

This script is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Author

[ENGINYRING](https://github.com/ENGINYRING)
