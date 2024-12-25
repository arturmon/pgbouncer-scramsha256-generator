# SCRAM-SHA-256 Hash Generator

A simple Go program to generate SCRAM-SHA-256 hashes, commonly used for authentication systems like PgBouncer.

## Features

- Generates SCRAM-SHA-256 hashes with customizable iterations.
- Uses a random 16-byte salt.
- Outputs the hash in the format: `SCRAM-SHA-256$iterations:salt:stored_key:server_key`.

## Requirements

- Go 1.18 or later.

## Installation

1. Clone this repository:
   ```bash
   git clone https://your-repository-url.git
   cd scram-sha256-generator
