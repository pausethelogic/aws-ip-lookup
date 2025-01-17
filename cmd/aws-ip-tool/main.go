// main.go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
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
		Use:   "aws-ip-tool",
		Short: "AWS IP ranges lookup tool",
		Long: `A command-line tool to search and filter AWS IP ranges.
Example: aws-ip-tool search -i 52.94.76.5 -s AMAZON -r us-east-1`,
	}

	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search AWS IP ranges",
		Long: `Search AWS IP ranges by IP address, service, and/or region.
All filters are optional. If no filters are provided, all ranges will be displayed.`,
		Example: `  aws-ip-tool search -i 52.94.76.5
  aws-ip-tool search -s AMAZON
  aws-ip-tool search -r us-east-1
  aws-ip-tool search -s AMAZON -r us-east-1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ip, _ := cmd.Flags().GetString("ip")
			service, _ := cmd.Flags().GetString("service")
			region, _ := cmd.Flags().GetString("region")

			if ip != "" {
				if _, err := netip.ParseAddr(ip); err != nil {
					return fmt.Errorf("invalid IP address: %s", ip)
				}
			}

			ranges, err := downloadIPRanges()
			if err != nil {
				return fmt.Errorf("failed to get IP ranges: %v", err)
			}

			filtered := filterRanges(ranges, ip, service, region)
			if len(filtered) == 0 {
				return fmt.Errorf("no matching IP ranges found")
			}

			printResults(filtered)
			return nil
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aws-ip-tool version %s\n", version)
		},
	}

	searchCmd.Flags().StringP("ip", "i", "", "IP address to search")
	searchCmd.Flags().StringP("service", "s", "", "AWS service to filter (e.g., AMAZON, EC2)")
	searchCmd.Flags().StringP("region", "r", "", "AWS region to filter (e.g., us-east-1)")

	rootCmd.AddCommand(searchCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getConfigDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	configDir := filepath.Join(homeDir, ".aws-ip-tool")
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
	if cached, err := loadJSONFromCache(); err == nil {
		var ranges IPRanges
		if err := json.Unmarshal(cached, &ranges); err == nil {
			return &ranges, nil
		}
	}

	fmt.Println("Downloading latest IP ranges from AWS...")
	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
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
