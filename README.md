# aws-ip-lookup

A CLI tool for querying AWS public IP ranges by region, service, or IP.

The tool downloads the latest AWS IP ranges from the official [AWS IP Address Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) file and caches them locally for faster lookups. The tool can search by any combination of IP address, AWS service, and AWS region.

## Features

- Search AWS IP ranges by IP address
- Filter by AWS service (e.g., ROUTE53, CLOUDFRONT, EC2)
- Filter by AWS region (e.g., us-east-1)
- Filter by network border group (e.g., us-east-1-msp-1a)
- List all available AWS services in the IP ranges file
- List all AWS regions in the IP ranges file
- Multiple output formats (text, JSON, YAML, CSV)
- Local caching of IP ranges for faster lookups
- Colorful output for better readability

## Installation

### Prebuilt Binaries
Prebuilt binaries are available for Linux, macOS, and Windows on the [Releases](github.com/pausethelogic/aws-ip-lookup/releases) page.

Binary versions are based on the latest release tag, which is defined in the .version file at the root of the repository.

Once you've downloaded the binary, run it on macOS and Linux with the following command:
```bash
./aws-ip-lookup
```
On Windows, double click the binary, or run the binary with the following command:
```bash
aws-ip-lookup.exe
```
### Build from Source

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

List all network border groups:
```bash
aws-ip-lookup network-border-groups
aws-ip-lookup network-border-groups -o json
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

Filter by network border group:
```bash
aws-ip-lookup search -n us-east-1
```

Combined search:
```bash
aws-ip-lookup search -s EC2 -r us-east-1 --network-border-group us-east-1
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
Network Border Group: us-east-1
```

JSON format:
```json
{
  "IPPrefix": "70.132.0.0/18",
  "Service": "CLOUDFRONT",
  "Region": "GLOBAL",
  "Network Border Group": "GLOBAL"
}
```

CSV format:
```csv
IP Prefix,IPv6 Prefix,Service,Region,Network Border Group
54.231.0.0/17,,AMAZON,us-east-1,us-east-1
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
