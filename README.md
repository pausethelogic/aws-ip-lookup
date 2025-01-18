# aws-ip-tool

A command-line tool for checking if a public IP address belongs to an AWS service.

The tool downloads the latest AWS IP ranges from the official [AWS IP Address Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) page and caches them locally for faster lookups. The tool can search by any combination of IP address, AWS service, and AWS region.

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

```bash
# Clone the repository
git clone https://github.com/pausethelogic/aws-ip-tool.git

# Build the tool
cd aws-ip-tool
go build ./cmd/aws-ip-tool
```

## Usage

### Basic Commands

Get detailed help:
```bash
aws-ip-tool help
```

List all AWS services:
```bash
aws-ip-tool services
aws-ip-tool services -o json
```

List all AWS regions:
```bash
aws-ip-tool regions
aws-ip-tool regions -o yaml
```

### Search Commands

Search by IP address:
```bash
aws-ip-tool search -i 54.231.0.1
```

Filter by service:
```bash
aws-ip-tool search -s AMAZON
```

Filter by region:
```bash
aws-ip-tool search -r us-east-1
```

### Output Formats

All commands support different output formats using the -o or --output flag:

Text output (default):
```bash
aws-ip-tool search -i 54.231.0.1
```

JSON output:
```bash
aws-ip-tool search -i 54.231.0.1 -o json
```

YAML output:
```bash
aws-ip-tool search -s EC2 -o yaml
```

CSV output:
```bash
aws-ip-tool search -r us-east-1 -o csv
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
- Maintains a local cache in ~/.aws-ip-tool/
- Checks for updates using AWS's SyncToken
- Downloads new IP ranges only when needed
- Falls back to cache when offline

