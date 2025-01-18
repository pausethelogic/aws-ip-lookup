# aws-ip-lookup

A command-line tool for checking if a public IP address belongs to AWS.

The tool downloads the latest AWS IP ranges from the official [AWS IP Address Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) file and caches them locally for faster lookups. The tool can search by any combination of IP address, AWS service, and AWS region.

## Features

- Search AWS IP ranges by IP address
- Filter by AWS service (e.g., AMAZON, EC2)
- Filter by AWS region (e.g., us-east-1)
- List all available AWS services in the IP ranges file
- List all AWS regions in the IP ranges file
- Multiple output formats (text, JSON, YAML, CSV)
- Local caching of IP ranges for faster lookups
- Colored output for better readability

## Installation

Preequisites:
- Go 1.23 or later 
- Add Go bin directory to your PATH environment variable by adding the following line to your shell profile file (e.g., ~/.bashrc, ~/.zshrc): `export PATH=$PATH:$(go env GOPATH)/bin`

```bash
# Clone the repository
git clone https://github.com/pausethelogic/aws-ip-lookup.git

# Build the tool
cd aws-ip-lookup
go build ./cmd/aws-ip-lookup
```

## Usage

### Basic Commands

Get detailed help:
```bash
aws-ip-lookup help
```

List all AWS services:
```bash
aws-ip-lookup services
aws-ip-lookup services -o json
```

List all AWS regions:
```bash
aws-ip-lookup regions
aws-ip-lookup regions -o yaml
```

### Search Commands

Search by IP address:
```bash
aws-ip-lookup search -i 54.231.0.1
```

Filter by service:
```bash
aws-ip-lookup search -s AMAZON
```

Filter by region:
```bash
aws-ip-lookup search -r us-east-1
```

### Output Formats

All commands support different output formats using the -o or --output flag:

Text output (default):
```bash
aws-ip-lookup search -i 54.231.0.1
```

JSON output:
```bash
aws-ip-lookup search -i 54.231.0.1 -o json
```

YAML output:
```bash
aws-ip-lookup search -s EC2 -o yaml
```

CSV output:
```bash
aws-ip-lookup search -r us-east-1 -o csv
```

### Example Outputs

Text format (default):
```
Found 1 matching ranges:

IP Prefix: 54.231.0.0/17
Service: AMAZON
Region: us-east-1
Network: us-east-1
```

JSON format:
```json
{
  "IPPrefix": "54.231.0.0/17",
  "Service": "AMAZON",
  "Region": "us-east-1",
  "Network": "us-east-1"
}
```

CSV format:
```csv
IP Prefix,Service,Region,Network
54.231.0.0/17,AMAZON,us-east-1,us-east-1
```

## Cache Management

The tool automatically:
- Maintains a local cache in ~/.aws-ip-lookup/
- Checks for updates using AWS's SyncToken
- Downloads new IP ranges only when needed
- Falls back to cache when offline

## TODO

- Add support for checking if an IP address belongs to a specific AWS account
- Add support for checking if an IP address belongs to a specific resource you own (e.g., EC2 instance, NAT Gateway, ALB, etc)
