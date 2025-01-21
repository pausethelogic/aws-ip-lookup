// main.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

const version = "1.0.0"

type IPRange struct {
	IPPrefix   string `json:"ip_prefix,omitempty"`
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`
	Region     string `json:"region"`
	Service    string `json:"service"`
	Network    string `json:"network_border_group"`
}

type IPRanges struct {
	SyncToken    string    `json:"syncToken"`
	CreateDate   string    `json:"createDate"`
	Prefixes     []IPRange `json:"prefixes"`
	IPv6Prefixes []IPRange `json:"ipv6_prefixes"`
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "aws-ip-lookup",
		Short: "AWS IP ranges lookup tool",
		Long: `AWS IP Lookup - A command-line utility for searching AWS IP ranges

This tool helps you find AWS IP ranges and determine if an IP address belongs
to AWS infrastructure. It downloads and caches the official AWS IP ranges
for quick lookups.

Available Commands:
  search                  Search AWS IP ranges using various filters
  services                List all available AWS services
  regions                 List all AWS regions
  network-border-groups   List all network border groups
  version                Show tool version
  help                   Show help for any command

Common Flags:
  -o, --output string   Output format (text, json, yaml, csv)

Use "aws-ip-lookup [command] --help" for more information about a command.`,
	}

	var searchCmd = &cobra.Command{
		Use:          "search",
		Short:        "Search AWS IP ranges",
		SilenceUsage: true,
		Long: `Search AWS IP ranges using various filters.

You can search by:
- IP address or CIDR (-i, --ip): Find which AWS service owns a specific IP or overlaps with CIDR range
- Service (-s, --service): List all IP ranges for a specific AWS service
- Region (-r, --region): List all IP ranges in a specific AWS region
- Network Border Group (-n, --network-border-group): List all IP ranges in a specific network border group

Output Formats Available:
- text (default): Human-readable colored output
- json: JSON formatted output
- yaml: YAML formatted output
- csv: CSV format with headers

Examples:
  # Search by IP address with default output
  aws-ip-lookup search -i 54.231.0.1

  # Search by CIDR range
  aws-ip-lookup search -i 54.231.0.0/24

  # List all EC2 ranges in JSON format
  aws-ip-lookup search -s EC2 -o json

  # List all ranges in us-east-1 as CSV
  aws-ip-lookup search -r us-east-1 -o csv

  # List all ranges in a specific network border group
  aws-ip-lookup search -n us-east-1

  # Combine filters with YAML output
  aws-ip-lookup search -s EC2 -r us-east-1 -n us-east-1 -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if any args were provided without flags
			if len(args) > 0 {
				return fmt.Errorf("unexpected argument(s): %v\nUse flags to specify search criteria, see 'aws-ip-lookup search --help'", args)
			}

			ip, _ := cmd.Flags().GetString("ip")
			service, _ := cmd.Flags().GetString("service")
			region, _ := cmd.Flags().GetString("region")
			network, _ := cmd.Flags().GetString("network-border-group")

			// Check if at least one flag was provided
			if ip == "" && service == "" && region == "" && network == "" {
				return fmt.Errorf("at least one search flag is required\nUse 'aws-ip-lookup search --help' for usage examples")
			}

			if ip != "" {
				if strings.Contains(ip, "/") {
					if _, err := netip.ParsePrefix(ip); err != nil {
						return fmt.Errorf("invalid CIDR range: %s\nUse 'aws-ip-lookup help' for usage examples", ip)
					}
				} else if _, err := netip.ParseAddr(ip); err != nil {
					return fmt.Errorf("invalid IP address: %s\nUse 'aws-ip-lookup help' for usage examples", ip)
				}
			}

			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			filtered := filterRanges(ranges, ip, service, region, network)
			if len(filtered) == 0 {
				message := "No matching IP ranges found"
				if ip != "" {
					message += fmt.Sprintf("\nIP %s does not belong to any AWS range", ip)
				}
				if service != "" {
					message += fmt.Sprintf("\nService filter: %s", service)
				}
				if region != "" {
					message += fmt.Sprintf("\nRegion filter: %s", region)
				}
				if network != "" {
					message += fmt.Sprintf("\nNetwork filter: %s", network)
				}
				return fmt.Errorf("%s", message)
			}

			format, _ := cmd.Flags().GetString("output")
			return outputResults(filtered, format)
		},
	}

	var versionCmd = &cobra.Command{
		Use:          "version",
		Short:        "Print version",
		SilenceUsage: true,
		Long:         `Display the current version of aws-ip-lookup.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aws-ip-lookup version %s\n", version)
		},
	}

	var servicesCmd = &cobra.Command{
		Use:          "services",
		Short:        "List all AWS services",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			services := make(map[string]bool)
			for _, prefix := range ranges.Prefixes {
				services[prefix.Service] = true
			}

			var uniqueServices []string
			for service := range services {
				uniqueServices = append(uniqueServices, service)
			}
			sort.Strings(uniqueServices)

			format, _ := cmd.Flags().GetString("output")
			return outputResults(uniqueServices, format)
		},
	}

	var regionsCmd = &cobra.Command{
		Use:          "regions",
		Short:        "List all AWS regions",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			regions := make(map[string]bool)
			for _, prefix := range ranges.Prefixes {
				regions[prefix.Region] = true
			}

			var uniqueRegions []string
			for region := range regions {
				uniqueRegions = append(uniqueRegions, region)
			}
			sort.Strings(uniqueRegions)

			format, _ := cmd.Flags().GetString("output")
			return outputResults(uniqueRegions, format)
		},
	}

	var networkBorderGroupsCmd = &cobra.Command{
		Use:          "network-border-groups",
		Short:        "List all AWS network border groups",
		SilenceUsage: true,
		Long:         `List all available AWS network border groups from the IP ranges file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			networks := make(map[string]bool)
			for _, prefix := range ranges.Prefixes {
				networks[prefix.Network] = true
			}

			var uniqueNetworks []string
			for network := range networks {
				uniqueNetworks = append(uniqueNetworks, network)
			}
			sort.Strings(uniqueNetworks)

			format, _ := cmd.Flags().GetString("output")
			return outputResults(uniqueNetworks, format)
		},
	}

	searchCmd.Flags().StringP("ip", "i", "", "IP address or CIDR range to search (e.g., 54.231.0.1 or 54.231.0.0/24)")
	searchCmd.Flags().StringP("service", "s", "", "AWS service name (e.g., AMAZON, EC2, S3, ROUTE53)")
	searchCmd.Flags().StringP("region", "r", "", "AWS region code (e.g., us-east-1, eu-west-1)")
	searchCmd.Flags().StringP("network-border-group", "n", "", "Network border group (e.g., us-east-1, us-west-2)")
	searchCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")
	servicesCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")
	regionsCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")
	networkBorderGroupsCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")

	rootCmd.AddCommand(searchCmd, versionCmd, servicesCmd, regionsCmd, networkBorderGroupsCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %v", err)
	}
	configDir := filepath.Join(homeDir, ".aws-ip-lookup")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}
	return configDir, nil
}

func getCacheFilePath() (string, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "ip-ranges.json"), nil
}

func saveJSONToCache(data []byte) error {
	path, err := getCacheFilePath()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %v", err)
	}
	return nil
}

func loadJSONFromCache() ([]byte, error) {
	path, err := getCacheFilePath()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func downloadIPRanges() (*IPRanges, error) {
	var cachedRanges IPRanges
	if cached, err := loadJSONFromCache(); err == nil {
		if err := json.Unmarshal(cached, &cachedRanges); err == nil {
			// Check if we need to update by comparing SyncToken
			if upToDate, err := isCacheUpToDate(cachedRanges.SyncToken); err == nil && upToDate {
				return &cachedRanges, nil
			}
		}
	}

	fmt.Println("Downloading latest IP ranges from AWS...")
	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		// If download fails but we have cache, use the cache as fallback
		if cached, err := loadJSONFromCache(); err == nil {
			if err := json.Unmarshal(cached, &cachedRanges); err == nil {
				fmt.Println("Warning: Using cached IP ranges file due to download failure")
				return &cachedRanges, nil
			}
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if err := saveJSONToCache(body); err != nil {
		fmt.Printf("Warning: Failed to cache JSON: %v\n", err)
	}

	var ranges IPRanges
	if err := json.Unmarshal(body, &ranges); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	return &ranges, nil
}

func isCacheUpToDate(cachedToken string) (bool, error) {
	// Get just the syncToken from AWS to minimize data transfer
	resp, err := http.Head("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// AWS includes the syncToken in the ETag header
	etag := resp.Header.Get("ETag")
	if etag == "" {
		return false, fmt.Errorf("no ETag found in response")
	}

	// Remove quotes from ETag
	etag = strings.Trim(etag, "\"")

	// Compare with cached token
	return etag == cachedToken, nil
}

func filterRanges(ranges *IPRanges, ip, service, region, network string) []IPRange {
	var results []IPRange

	// Process IPv4 ranges
	for _, prefix := range ranges.Prefixes {
		if !matchesFilters(prefix, ip, service, region, network) {
			continue
		}
		results = append(results, prefix)
	}

	// Process IPv6 ranges
	for _, prefix := range ranges.IPv6Prefixes {
		if !matchesFilters(prefix, ip, service, region, network) {
			continue
		}
		results = append(results, prefix)
	}

	return results
}

func matchesFilters(r IPRange, ip, service, region, network string) bool {
	if service != "" && !strings.EqualFold(r.Service, service) {
		return false
	}
	if region != "" && !strings.EqualFold(r.Region, region) {
		return false
	}
	if network != "" && !strings.EqualFold(r.Network, network) {
		return false
	}
	if ip != "" {
		var searchPrefix netip.Prefix
		if strings.Contains(ip, "/") {
			// Handle CIDR range
			var err error
			searchPrefix, err = netip.ParsePrefix(ip)
			if err != nil {
				return false
			}
		} else {
			// Handle single IP
			searchIP, err := netip.ParseAddr(ip)
			if err != nil {
				return false
			}
			searchPrefix = netip.PrefixFrom(searchIP, searchIP.BitLen())
		}

		// Check IPv4 prefix
		if r.IPPrefix != "" {
			prefix, err := netip.ParsePrefix(r.IPPrefix)
			if err != nil {
				return false
			}
			if prefix.Overlaps(searchPrefix) {
				return true
			}
		}

		// Check IPv6 prefix
		if r.IPv6Prefix != "" {
			prefix, err := netip.ParsePrefix(r.IPv6Prefix)
			if err != nil {
				return false
			}
			if prefix.Overlaps(searchPrefix) {
				return true
			}
		}
		return false
	}
	return true
}

func printResults(ranges []IPRange) {
	bold := color.New(color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	fmt.Printf("Found %s matching ranges:\n\n", bold(len(ranges)))

	for _, r := range ranges {
		if r.IPPrefix != "" {
			fmt.Printf("%s %s\n", bold("IP Prefix:"), cyan(r.IPPrefix))
		}
		if r.IPv6Prefix != "" {
			fmt.Printf("%s %s\n", bold("IPv6 Prefix:"), cyan(r.IPv6Prefix))
		}
		fmt.Printf("%s %s\n", bold("Service:"), green(r.Service))
		fmt.Printf("%s %s\n", bold("Region:"), yellow(r.Region))
		fmt.Printf("%s %s\n\n", bold("Network Border Group:"), r.Network)
	}
}

func outputResults(data interface{}, format string) error {
	switch format {
	case "json":
		output, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		fmt.Println(string(output))

	case "yaml":
		output, err := yaml.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %v", err)
		}
		fmt.Println(string(output))

	case "csv":
		w := csv.NewWriter(os.Stdout)
		switch v := data.(type) {
		case []IPRange:
			if err := w.Write([]string{"IP Prefix", "IPv6 Prefix", "Service", "Region", "Network Border Group"}); err != nil {
				return fmt.Errorf("failed to write CSV header: %v", err)
			}
			for _, r := range v {
				if err := w.Write([]string{r.IPPrefix, r.IPv6Prefix, r.Service, r.Region, r.Network}); err != nil {
					return fmt.Errorf("failed to write CSV record: %v", err)
				}
			}
		case []string:
			if err := w.Write([]string{"Value"}); err != nil {
				return fmt.Errorf("failed to write CSV header: %v", err)
			}
			for _, s := range v {
				if err := w.Write([]string{s}); err != nil {
					return fmt.Errorf("failed to write CSV record: %v", err)
				}
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return fmt.Errorf("CSV writer error: %v", err)
		}

	default: // "text"
		switch v := data.(type) {
		case []IPRange:
			printResults(v)
		case []string:
			for _, s := range v {
				fmt.Println(s)
			}
		}
	}
	return nil
}
