// main.go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/netip"
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

func downloadIPRanges() (*IPRanges, error) {
    resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
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

func