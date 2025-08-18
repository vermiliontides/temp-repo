# Config Module

## Overview

This module handles loading and parsing the application configuration from `config.yaml` and environment variables using the Viper library.

## Components

- **`config.go`**: Defines the configuration structs and the `LoadConfig` function.

## Usage

The configuration is loaded once at startup in `cmd/lucid-vigil/main.go`.
