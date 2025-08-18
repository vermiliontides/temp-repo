# Scheduler Module

## Overview

This module contains the core scheduling logic for the agent. It is responsible for running registered monitors at their configured intervals.

## Components

- **`scheduler.go`**: The main scheduler implementation.
- **`scheduler_test.go`**: Unit tests for the scheduler.

## Usage

The scheduler is initialized in `main.go`, monitors are registered, and then `scheduler.Start()` is called to begin execution.
