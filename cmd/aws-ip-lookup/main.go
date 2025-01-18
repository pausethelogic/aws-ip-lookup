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
	IPPrefix string `json:"ip_prefix,omitempty"`
	Region   string `json:"region"`
	Service  string `json:"service"`
	Network  string `json:"network_border_group"`
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
  search    Search AWS IP ranges using various filters
  services  List all available AWS services
  regions   List all AWS regions
  version   Show tool version
  help      Show help for any command

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
- IP address (-i, --ip): Find which AWS service owns a specific IP
- Service (-s, --service): List all IP ranges for a specific AWS service
- Region (-r, --region): List all IP ranges in a specific AWS region

Output Formats Available:
- text (default): Human-readable colored output
- json: JSON formatted output
- yaml: YAML formatted output
- csv: CSV format with headers

Examples:
  # Search by IP address with default output
  aws-ip-lookup search -i 54.231.0.1

  # List all EC2 ranges in JSON format
  aws-ip-lookup search -s EC2 -o json

  # List all ranges in us-east-1 as CSV
  aws-ip-lookup search -r us-east-1 -o csv

  # Combine filters with YAML output
  aws-ip-lookup search -s EC2 -r us-east-1 -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if any args were provided without flags
			if len(args) > 0 {
				return fmt.Errorf("unexpected argument(s): %v\nUse flags to specify search criteria, see 'aws-ip-lookup search --help'", args)
			}

			ip, _ := cmd.Flags().GetString("ip")
			service, _ := cmd.Flags().GetString("service")
			region, _ := cmd.Flags().GetString("region")

			// Check if at least one flag was provided
			if ip == "" && service == "" && region == "" {
				return fmt.Errorf("at least one search flag is required\nUse 'aws-ip-lookup search --help' for usage examples")
			}

			if ip != "" {
				if _, err := netip.ParseAddr(ip); err != nil {
					return fmt.Errorf("invalid IP address: %s\nUse 'aws-ip-lookup help' for usage examples", ip)
				}
			}

			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			filtered := filterRanges(ranges, ip, service, region)
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

	searchCmd.Flags().StringP("ip", "i", "", "IP address to search (e.g., 54.231.0.1)")
	searchCmd.Flags().StringP("service", "s", "", "AWS service name (e.g., AMAZON, EC2, S3, ROUTE53)")
	searchCmd.Flags().StringP("region", "r", "", "AWS region code (e.g., us-east-1, eu-west-1)")
	searchCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")
	servicesCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")
	regionsCmd.Flags().StringP("output", "o", "text", "Output format (text, json, yaml, csv)")

	rootCmd.AddCommand(searchCmd, versionCmd, servicesCmd, regionsCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	configDir := filepath.Join(homeDir, ".aws-ip-lookup")
	os.MkdirAll(configDir, 0755)
	return configDir
}

func getCacheFilePath() string {
	return filepath.Join(getConfigDir(), "ip-ranges.json")
}

func saveJSONToCache(data []byte) error {
	return os.WriteFile(getCacheFilePath(), data, 0644)
}

func loadJSONFromCache() ([]byte, error) {
	return os.ReadFile(getCacheFilePath())
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := saveJSONToCache(body); err != nil {
		fmt.Printf("Warning: Failed to cache JSON: %v\n", err)
	}

	var ranges IPRanges
	if err := json.Unmarshal(body, &ranges); err != nil {
		return nil, err
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

func filterRanges(ranges *IPRanges, ip, service, region string) []IPRange {
	var results []IPRange

	for _, prefix := range ranges.Prefixes {
		if !matchesFilters(prefix, ip, service, region) {
			continue
		}
		results = append(results, prefix)
	}

	return results
}

func matchesFilters(r IPRange, ip, service, region string) bool {
	if service != "" && !strings.EqualFold(r.Service, service) {
		return false
	}
	if region != "" && !strings.EqualFold(r.Region, region) {
		return false
	}
	if ip != "" {
		searchIP, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		prefix, err := netip.ParsePrefix(r.IPPrefix)
		if err != nil {
			return false
		}
		if !prefix.Contains(searchIP) {
			return false
		}
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
		fmt.Printf("%s %s\n", bold("IP Prefix:"), cyan(r.IPPrefix))
		fmt.Printf("%s %s\n", bold("Service:"), green(r.Service))
		fmt.Printf("%s %s\n", bold("Region:"), yellow(r.Region))
		fmt.Printf("%s %s\n\n", bold("Network:"), r.Network)
	}
}

func outputResults(data interface{}, format string) error {
	switch format {
	case "json":
		output, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(output))

	case "yaml":
		output, err := yaml.Marshal(data)
		if err != nil {
			return err
		}
		fmt.Println(string(output))

	case "csv":
		w := csv.NewWriter(os.Stdout)
		switch v := data.(type) {
		case []IPRange:
			w.Write([]string{"IP Prefix", "Service", "Region", "Network"})
			for _, r := range v {
				w.Write([]string{r.IPPrefix, r.Service, r.Region, r.Network})
			}
		case []string:
			w.Write([]string{"Value"})
			for _, s := range v {
				w.Write([]string{s})
			}
		}
		w.Flush()

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
