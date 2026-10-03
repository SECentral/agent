//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/secentral/agent/metadata"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "inspect":
		inspect()
	case "collect":
		collect(os.Args[2:])
	case "validate":
		validate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func inspect() {
	report, err := metadata.InspectCatalogSource()
	if err != nil {
		fatal(err)
	}
	if report.Complete() && report.Clean() {
		fmt.Println("No local SELinux customizations detected.")
		return
	}
	fmt.Println("Local SELinux customization or inspection problem detected:")
	for _, name := range report.LocalBooleans {
		fmt.Printf("Boolean: %s\n", name)
	}
	for _, port := range report.LocalPorts {
		fmt.Printf("Port: %s/%d-%d -> %s\n", port.Protocol, port.Start, port.End, port.Type)
	}
	for _, context := range report.LocalFileContexts {
		fmt.Printf("File context: %s -> %s\n", context.Pattern, context.Context)
	}
	for _, diagnostic := range report.Diagnostics {
		fmt.Printf("Inspection: %s\n", diagnostic)
	}
	os.Exit(1)
}

func collect(args []string) {
	flags := flag.NewFlagSet("collect", flag.ExitOnError)
	output := flags.String("output", "", "catalog JSON output path")
	flags.Parse(args)
	if *output == "" {
		fatal(fmt.Errorf("collect requires -output"))
	}
	artifact, inspection, err := metadata.CollectCatalog()
	if err != nil {
		printInspection(inspection)
		fatal(err)
	}
	data, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, append(data, '\n'), 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("Catalog created\nPolicy: %s\nPolicy digest: %s\nBooleans: %d\nPorts: %d\nContent digest: %s\n", artifact.Catalog.Policy.Type, artifact.Catalog.Policy.LoadedPolicyDigest, len(artifact.Catalog.Families.Booleans.Entries), len(artifact.Catalog.Families.Ports.Mappings), artifact.ContentDigest)
}

func validate(args []string) {
	if len(args) != 1 {
		fatal(fmt.Errorf("validate requires one catalog path"))
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fatal(err)
	}
	var artifact metadata.CatalogArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		fatal(err)
	}
	if err := metadata.ValidateCatalog(artifact); err != nil {
		fatal(err)
	}
	fmt.Println("Valid.")
}

func printInspection(report metadata.CatalogInspection) {
	for _, name := range report.LocalBooleans {
		fmt.Fprintf(os.Stderr, "Local boolean: %s\n", name)
	}
	for _, port := range report.LocalPorts {
		fmt.Fprintf(os.Stderr, "Local port: %s/%d-%d -> %s\n", port.Protocol, port.Start, port.End, port.Type)
	}
	for _, context := range report.LocalFileContexts {
		fmt.Fprintf(os.Stderr, "Local file context: %s -> %s\n", context.Pattern, context.Context)
	}
	for _, diagnostic := range report.Diagnostics {
		fmt.Fprintf(os.Stderr, "Inspection: %s\n", diagnostic)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: secentral-catalog-collector inspect | collect -output FILE | validate FILE")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
