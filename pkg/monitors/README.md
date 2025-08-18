# Monitors Module

## Overview

This module contains all the individual security monitors. Each monitor is a self-contained package responsible for a specific security domain. Monitors are registered with the central scheduler to run at configured intervals.

## Components

- **`/base`**: A base monitor implementation providing common functionality.
- **`/process`**: Monitors running processes for anomalies.
- **`/filesystem`**: Monitors for filesystem integrity and suspicious file changes.
- **`/network`**: Monitors network connections and traffic.
- **`/persistence`**: Scans for persistence mechanisms.
- **`/rootkit`**: Checks for signs of rootkits.
- *And others...*

## Usage

Each monitor implements the `scheduler.Monitor` interface. They are registered in `cmd/lucid-vigil/main.go`.
