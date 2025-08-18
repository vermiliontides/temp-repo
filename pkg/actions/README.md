# Actions Module

## Overview

This module defines the defensive actions the agent can take in response to a detected threat. Actions are triggered by monitors based on the rules in `config.yaml`.

## Components

- **`action.go`**: Defines the `Action` interface.
- **`/block_ip`**: An action to block an IP address using `iptables`.
- **`/kill_process`**: An action to terminate a process by its PID.

## Usage

Actions are not yet dynamically dispatched. They are currently hard-coded within specific monitors but are designed for a future event-driven system.
