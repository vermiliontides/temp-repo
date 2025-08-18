#!/bin/bash
# Filename: airgapped_installer.sh
# Description: Airgapped installer for Project Sentinel and its dependencies.
# This script is designed to be run from a USB drive on a fresh Linux installation
# with no internet access. It will install Sentinel, configure rsyslog, and install VictoriaLogs.
# Path: deploy/airgapped/airgapped_installer.sh

# --- Installer Version ---
INSTALLER_VERSION="1.1.0" # Increment this for new installer versions

# --- Configuration Variables ---
SENTINEL_BINARY_NAME="sentinel"
VICTORIALOGS_ARCHIVE="victorialogs-linux-amd64.tar.gz" # Expected VictoriaLogs archive name
VICTORIALOGS_DIR="/opt/victorialogs"

# --- Utility Functions ---
log_info() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }
log_warn() { echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; }
log_error() { echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
    fi
}

check_dependencies() {
    log_info "Checking for required system commands..."
    command -v systemctl >/dev/null 2>&1 || log_error "systemctl command not found. Is this a systemd-based Linux distribution?"
    command -v tar >/dev/null 2>&1 || log_error "tar command not found. Please install it (e.g., apt install tar)."
    command -v cp >/dev/null 2>&1 || log_error "cp command not found."
    command -v chmod >/dev/null 2>&1 || log_error "chmod command not found."
    command -v mkdir >/dev/null 2>&1 || log_error "mkdir command not found."
    command -v find >/dev/null 2>&1 || log_error "find command not found."
    command -v cat >/dev/null 2>&1 || log_error "cat command not found."
    log_info "All required system commands found."
}

# --- Main Installation Logic ---
install_sentinel() {
    log_info "Installing Sentinel binary..."
    if [[ ! -f "./$SENTINEL_BINARY_NAME" ]]; then
        log_error "Sentinel binary not found in current directory. Expected: ./$SENTINEL_BINARY_NAME"
    fi
    cp "./$SENTINEL_BINARY_NAME" /usr/local/bin/ || log_error "Failed to copy Sentinel binary."
    chmod +x /usr/local/bin/$SENTINEL_BINARY_NAME || log_error "Failed to make Sentinel binary executable."
    log_info "Sentinel binary installed to /usr/local/bin/."

    log_info "Setting up Sentinel systemd service..."
    if [[ ! -f "./sentinel.service" ]]; then
        log_error "Sentinel systemd service file not found. Expected: ./sentinel.service"
    fi
    cp "./sentinel.service" /etc/systemd/system/ || log_error "Failed to copy systemd service file."
    systemctl daemon-reload || log_error "Failed to reload systemd daemon."
    systemctl enable $SENTINEL_BINARY_NAME || log_error "Failed to enable Sentinel service."
    systemctl start $SENTINEL_BINARY_NAME || log_error "Failed to start Sentinel service."
    log_info "Sentinel systemd service configured and started."

    log_info "Creating Sentinel configuration directory..."
    mkdir -p /etc/sentinel/ || log_error "Failed to create /etc/sentinel/."
    if [[ ! -f "./config.yaml" ]]; then
        log_warn "Sentinel config.yaml not found in current directory. Please copy it manually to /etc/sentinel/."
    else
        cp "./config.yaml" /etc/sentinel/ || log_error "Failed to copy config.yaml."
        log_info "Sentinel config.yaml copied to /etc/sentinel/."
    fi
}

install_victorialogs() {
    log_info "Installing VictoriaLogs..."
    if [[ ! -f "./$VICTORIALOGS_ARCHIVE" ]]; then
        log_error "VictoriaLogs archive not found in current directory. Expected: ./$VICTORIALOGS_ARCHIVE"
    fi

    mkdir -p "$VICTORIALOGS_DIR" || log_error "Failed to create VictoriaLogs directory."
    tar -xzf "./$VICTORIALOGS_ARCHIVE" -C "$VICTORIALOGS_DIR" --strip-components=1 || log_error "Failed to extract VictoriaLogs archive."
    
    # Assuming the extracted binary is named 'victoria-logs' or similar, adjust if needed
    VICTORIALOGS_BINARY="$(find "$VICTORIALOGS_DIR" -maxdepth 1 -type f -executable -name 'victoria-logs*')"
    if [[ -z "$VICTORIALOGS_BINARY" ]]; then
        log_error "VictoriaLogs binary not found after extraction in $VICTORIALOGS_DIR. Please check archive content and expected binary name."
    fi

    # Create a simple systemd service for VictoriaLogs
    log_info "Creating VictoriaLogs systemd service..."
    cat <<EOF > /etc/systemd/system/victorialogs.service
[Unit]
Description=VictoriaLogs Time Series Database
After=network.target

[Service]
Type=simple
ExecStart=$VICTORIALOGS_BINARY -retentionPeriod=1m # Adjust retention as needed
WorkingDirectory=$VICTORIALOGS_DIR
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || log_error "Failed to reload systemd daemon for VictoriaLogs."
    systemctl enable victorialogs || log_error "Failed to enable VictoriaLogs service."
    systemctl start victorialogs || log_error "Failed to start VictoriaLogs service."
    log_info "VictoriaLogs installed and started."
}

configure_rsyslog() {
    log_info "Configuring rsyslog for Sentinel logs..."
    mkdir -p /var/log/sentinel || log_error "Failed to create /var/log/sentinel/."
    chmod 755 /var/log/sentinel || log_warn "Failed to set permissions for /var/log/sentinel/."

    if [[ ! -f "./sentinel-rsyslog.conf" ]]; then
        log_error "Rsyslog config file not found. Expected: ./sentinel-rsyslog.conf"
    fi
    cp "./sentinel-rsyslog.conf" /etc/rsyslog.d/sentinel.conf || log_error "Failed to copy rsyslog config."
    systemctl restart rsyslog || log_error "Failed to restart rsyslog."
    log_info "Rsyslog configured for Sentinel logs."
}

# --- Main Execution ---
check_root
check_dependencies

log_info "Starting Project Sentinel Airgapped Installation (Version: $INSTALLER_VERSION)..."

install_sentinel
install_victorialogs
configure_rsyslog

log_info "Project Sentinel Airgapped Installation Complete!"
log_info "Please refer to docs/airgapped_deployment.md for post-installation steps and verification."


# --- Utility Functions ---
log_info() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }
log_warn() { echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; }
log_error() { echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; exit 1; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root or with sudo."
    fi
}

# --- Main Installation Logic ---
install_sentinel() {
    log_info "Installing Sentinel binary..."
    if [[ ! -f "./$SENTINEL_BINARY_NAME" ]]; then
        log_error "Sentinel binary not found in current directory. Expected: ./$SENTINEL_BINARY_NAME"
    fi
    cp "./$SENTINEL_BINARY_NAME" /usr/local/bin/ || log_error "Failed to copy Sentinel binary."
    chmod +x /usr/local/bin/$SENTINEL_BINARY_NAME || log_error "Failed to make Sentinel binary executable."
    log_info "Sentinel binary installed to /usr/local/bin/."

    log_info "Setting up Sentinel systemd service..."
    if [[ ! -f "./sentinel.service" ]]; then
        log_error "Sentinel systemd service file not found. Expected: ./sentinel.service"
    fi
    cp "./sentinel.service" /etc/systemd/system/ || log_error "Failed to copy systemd service file."
    systemctl daemon-reload || log_error "Failed to reload systemd daemon."
    systemctl enable $SENTINEL_BINARY_NAME || log_error "Failed to enable Sentinel service."
    systemctl start $SENTINEL_BINARY_NAME || log_error "Failed to start Sentinel service."
    log_info "Sentinel systemd service configured and started."

    log_info "Creating Sentinel configuration directory..."
    mkdir -p /etc/sentinel/ || log_error "Failed to create /etc/sentinel/."
    if [[ ! -f "./config.yaml" ]]; then
        log_warn "Sentinel config.yaml not found in current directory. Please copy it manually to /etc/sentinel/."
    else
        cp "./config.yaml" /etc/sentinel/ || log_error "Failed to copy config.yaml."
        log_info "Sentinel config.yaml copied to /etc/sentinel/."
    fi
}

install_victorialogs() {
    log_info "Installing VictoriaLogs..."
    if [[ ! -f "./$VICTORIALOGS_ARCHIVE" ]]; then
        log_error "VictoriaLogs archive not found in current directory. Expected: ./$VICTORIALOGS_ARCHIVE"
    fi

    mkdir -p "$VICTORIALOGS_DIR" || log_error "Failed to create VictoriaLogs directory."
    tar -xzf "./$VICTORIALOGS_ARCHIVE" -C "$VICTORIALOGS_DIR" --strip-components=1 || log_error "Failed to extract VictoriaLogs archive."
    
    # Assuming the extracted binary is named 'victoria-logs' or similar, adjust if needed
    VICTORIALOGS_BINARY="$(find "$VICTORIALOGS_DIR" -maxdepth 1 -type f -executable -name 'victoria-logs*')"
    if [[ -z "$VICTORIALOGS_BINARY" ]]; then
        log_error "VictoriaLogs binary not found after extraction. Please check archive content."
    fi

    # Create a simple systemd service for VictoriaLogs
    log_info "Creating VictoriaLogs systemd service..."
    cat <<EOF > /etc/systemd/system/victorialogs.service
[Unit]
Description=VictoriaLogs Time Series Database
After=network.target

[Service]
Type=simple
ExecStart=$VICTORIALOGS_BINARY -retentionPeriod=1m # Adjust retention as needed
WorkingDirectory=$VICTORIALOGS_DIR
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || log_error "Failed to reload systemd daemon for VictoriaLogs."
    systemctl enable victorialogs || log_error "Failed to enable VictoriaLogs service."
    systemctl start victorialogs || log_error "Failed to start VictoriaLogs service."
    log_info "VictoriaLogs installed and started."
}

configure_rsyslog() {
    log_info "Configuring rsyslog for Sentinel logs..."
    mkdir -p /var/log/sentinel || log_error "Failed to create /var/log/sentinel/."
    chmod 755 /var/log/sentinel || log_warn "Failed to set permissions for /var/log/sentinel/."

    if [[ ! -f "./sentinel-rsyslog.conf" ]]; then
        log_error "Rsyslog config file not found. Expected: ./sentinel-rsyslog.conf"
    fi
    cp "./sentinel-rsyslog.conf" /etc/rsyslog.d/sentinel.conf || log_error "Failed to copy rsyslog config."
    systemctl restart rsyslog || log_error "Failed to restart rsyslog."
    log_info "Rsyslog configured for Sentinel logs."
}

# --- Main Execution ---
check_root

log_info "Starting Project Sentinel Airgapped Installation..."

install_sentinel
install_victorialogs
configure_rsyslog

log_info "Project Sentinel Airgapped Installation Complete!"
log_info "Please refer to docs/airgapped_deployment.md for post-installation steps and verification."
