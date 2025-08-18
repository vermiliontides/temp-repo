
# Lucid Vigil (Sentinel)

## Overview

Lucid Vigil is a sophisticated security monitoring agent designed to run on a host system (Linux) to continuously monitor various subsystems for signs of malicious activity or security weaknesses. It operates as a central scheduler that runs multiple independent monitors, each focused on a specific area like filesystem integrity, process behavior, network traffic, and persistence mechanisms.

## Features

- **Modular Monitoring:** A plug-and-play architecture with independent monitors for different security domains.
- **Process Monitoring:** Detects high resource usage, suspicious process names, and hidden processes.
- **Filesystem Integrity:** Monitors critical files for changes and checks for unauthorized SUID/SGID binaries.
- **Network Analysis:** Monitors network connections, bandwidth, and DNS queries for anomalies.
- **Persistence Detection:** Scans for common persistence techniques used by attackers (cron, systemd, etc.).
- **Rootkit Detection:** Performs checks for common rootkit artifacts.
- **Configurable Actions:** Can be configured to take defensive actions like blocking IPs or killing processes.
- **Flexible Deployment:** Ready for deployment via Docker, Kubernetes, or as a bare-metal service.

## Tech Stack

- **Primary Language:** Go
- **Logging:** Zerolog for structured JSON logging, VictoriaLogs for centralized storage.
- **Configuration:** Viper (YAML + Environment Variables)
- **Deployment:** Docker, Docker Compose, Kubernetes

## Getting Started

### Prerequisites

- Go 1.18+
- Docker & Docker Compose (for containerized setup)
- `iptables` and `tcpdump` (for full monitor functionality)

### Local Installation & Run

1.  **Clone the repository:**
    ```sh
    git clone <repository-url>
    ```
2.  **Build the binary:**
    ```sh
    go build -o sentinel ./cmd/lucid-vigil/main.go
    ```
3.  **Run the agent (requires sudo for some monitors):**
    ```sh
    sudo ./sentinel
    ```

### Dockerized Run

To run the agent and its dependencies in Docker:

```sh
docker-compose up --build
```

## Configuration

The agent is configured via `config.yaml`. This file allows you to enable/disable monitors, set check intervals, and define thresholds.

Configuration values can be overridden with environment variables. For example, to change the log level, you can set `SENTINEL_LOG_LEVEL=debug`.

## Deployment

For detailed deployment instructions for Docker, Kubernetes, and air-gapped environments, please see the [Deployment Guide](./docs/deployment.md).

## Project Structure

- `/cmd`: Main application entrypoint.
- `/pkg`: Core application logic, separated into modules:
  - `/api`: Health check and metrics API.
  - `/actions`: Defensive actions (kill process, block IP).
  - `/config`: Configuration loading.
  - `/monitors`: All security monitoring modules.
  - `/scheduler`: The core scheduler for running monitors.
- `/deploy`: Deployment manifests for Kubernetes, Docker, and bare-metal.
- `/docs`: In-depth documentation.
