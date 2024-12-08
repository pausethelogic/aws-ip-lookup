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

	"github.com/spf13/cobra"
)

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
	var rootCmd = &cobra.Command{Use: "aws-ip-tool"}

	var searchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search AWS IP ranges",
		RunE: func(cmd *cobra.Command, args []string) error {
			ip, _ := cmd.Flags().GetString("ip")
			service, _ := cmd.Flags().GetString("service")
			region, _ := cmd.Flags().GetString("region")

			ranges, err := downloadIPRanges()
			if err != nil {
				return err
			}

			filtered := filterRanges(ranges, ip, service, region)
			printResults(filtered)
			return nil
		},
	}

	searchCmd.Flags().StringP("ip", "i", "", "IP address to search")
	searchCmd.Flags().StringP("service", "s", "", "AWS service to filter")
	searchCmd.Flags().StringP("region", "r", "", "AWS region to filter")

	rootCmd.AddCommand(searchCmd)
	rootCmd.Execute()
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

// Modified download function
func downloadIPRanges() (*IPRanges, error) {
	// Try cache first
	if cached, err := loadJSONFromCache(); err == nil {
		var ranges IPRanges
		if err := json.Unmarshal(cached, &ranges); err == nil {
			return &ranges, nil
		}
	}

	// Download if cache fails
	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Save to cache
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
	for _, r := range ranges {
		fmt.Printf("IP Prefix: %s\nService: %s\nRegion: %s\nNetwork: %s\n\n",
			r.IPPrefix, r.Service, r.Region, r.Network)
	}
}
