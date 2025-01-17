# aws-ip-tool

A command-line tool for checking if a public IP address belongs to an AWS service.

The tool downloads the latest AWS IP ranges from the official [AWS IP Address Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) page and caches them locally for faster lookups. The tool can search by IP address, AWS service, and AWS region.

## Features

- Search AWS IP ranges by IP address
- Filter by AWS service (e.g., AMAZON, EC2)
- Filter by AWS region (e.g., us-east-1)
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

Get detailed help:
```bash
aws-ip-tool help
```

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

Combine filters:
```bash
aws-ip-tool search -i 54.231.0.1 -s AMAZON -r us-east-1
```

Check version:
```bash
aws-ip-tool version
```

Example output:
```
Found 1 matching ranges:

IP Prefix: 54.231.0.0/17
Service: AMAZON
Region: us-east-1
Network: us-east-1
```

## How it works

### Data flow: 

User Input -> Cache Check -> AWS Download (if needed) -> Search based on user input -> Display result or error

