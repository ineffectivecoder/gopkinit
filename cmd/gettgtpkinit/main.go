package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ineffectivecoder/gopkinit/pkg/ccache"
	"github.com/ineffectivecoder/gopkinit/pkg/pkinit"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/messages"
)

const usage = `gettgtpkinit - Request a TGT using Kerberos PKINIT

Usage:
  gettgtpkinit [options] <domain/username> <ccache>

Arguments:
  domain/username   Domain and username in the certificate
  ccache            Output file path for the credential cache

Options:
  -cert-pfx string      PFX/PKCS12 certificate file
  -pfx-pass string      PFX file password (optional)
  -pfx-base64 string    PFX file as base64 string
  -cert-pem string      Certificate in PEM format (not yet implemented)
  -key-pem string       Private key in PEM format (not yet implemented)
  -dc-ip string         DC IP or hostname to use as KDC (defaults to domain)
  -proxy string         SOCKS5 proxy address (e.g., 127.0.0.1:1080)
  -v                    Verbose output

Examples:
  gettgtpkinit -cert-pfx user.pfx -pfx-pass password DOMAIN.COM/user output.ccache
  gettgtpkinit -cert-pfx user.pfx -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache
  gettgtpkinit -cert-pfx user.pfx -proxy 127.0.0.1:1080 -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache
`

func main() {
	// Define flags
	certPFX := flag.String("cert-pfx", "", "PFX/PKCS12 certificate file")
	pfxPass := flag.String("pfx-pass", "", "PFX file password")
	pfxBase64 := flag.String("pfx-base64", "", "PFX file as base64 string")
	certPEM := flag.String("cert-pem", "", "Certificate in PEM format")
	keyPEM := flag.String("key-pem", "", "Private key in PEM format")
	dcIP := flag.String("dc-ip", "", "DC IP or hostname to use as KDC")
	proxyAddr := flag.String("proxy", "", "SOCKS5 proxy address (e.g., 127.0.0.1:1080)")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
	}

	flag.Parse()

	// Check positional arguments
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Error: Missing required arguments")
		flag.Usage()
		os.Exit(1)
	}

	identity := flag.Arg(0)
	ccachePath := flag.Arg(1)

	// Parse identity (domain/username)
	parts := strings.Split(identity, "/")
	if len(parts) != 2 {
		log.Fatalf("Invalid identity format. Expected 'domain/username', got '%s'", identity)
	}
	domain := parts[0]
	username := parts[1]

	if *verbose {
		log.Printf("Domain: %s", domain)
		log.Printf("Username: %s", username)
	}

	// Load certificate
	var client *pkinit.PKINITClient
	var err error

	if *pfxBase64 != "" {
		if *verbose {
			log.Println("Loading certificate from base64-encoded PFX...")
		}
		pfxData, err := base64.StdEncoding.DecodeString(*pfxBase64)
		if err != nil {
			log.Fatalf("Failed to decode base64 PFX: %v", err)
		}
		client, err = pkinit.NewFromPFXData(pfxData, *pfxPass)
		if err != nil {
			log.Fatalf("Failed to load PFX data: %v", err)
		}
	} else if *certPFX != "" {
		if *verbose {
			log.Printf("Loading certificate from PFX file: %s", *certPFX)
		}
		client, err = pkinit.NewFromPFX(*certPFX, *pfxPass)
		if err != nil {
			log.Fatalf("Failed to load PFX: %v", err)
		}
	} else if *certPEM != "" && *keyPEM != "" {
		log.Fatal("PEM format not yet implemented. Please use -cert-pfx instead.")
	} else {
		fmt.Fprintln(os.Stderr, "Error: You must specify either -cert-pfx or -pfx-base64")
		flag.Usage()
		os.Exit(1)
	}

	if *verbose {
		log.Printf("Certificate loaded. Issuer: %s", client.GetIssuer())
	}

	// Determine KDC address
	kdcAddr := *dcIP
	if kdcAddr == "" {
		kdcAddr = domain
		if *verbose {
			log.Printf("No DC IP specified, using domain name: %s", kdcAddr)
		}
	}

	if *verbose {
		log.Printf("Connecting to KDC: %s", kdcAddr)
	}

	// Request TGT
	if *verbose {
		if *proxyAddr != "" {
			log.Printf("Using SOCKS5 proxy: %s", *proxyAddr)
		}
	}

	result, err := client.GetTGT(domain, username, kdcAddr, *proxyAddr)
	if err != nil {
		log.Fatalf("Failed to get TGT: %v", err)
	}

	if *verbose {
		log.Println("TGT received successfully")
	}

	// Print AS-REP encryption key (needed for getnthash)
	fmt.Printf("AS-REP encryption key (you might need this later):\n")
	fmt.Println(result.ASRepKey)

	// Convert standard asn1.BitString to gofork/asn1.BitString
	goforkFlags := asn1.BitString{
		Bytes:     result.EncPart.Flags.Bytes,
		BitLength: result.EncPart.Flags.BitLength,
	}

	// Convert EncASRepPart to messages.EncKDCRepPart for ccache
	encKDCRepPart := messages.EncKDCRepPart{
		Key:           result.SessionKey,
		LastReqs:      []messages.LastReq{},
		Nonce:         0,
		KeyExpiration: result.EncPart.KeyExpiration,
		Flags:         goforkFlags,
		AuthTime:      result.EncPart.AuthTime,
		StartTime:     result.EncPart.StartTime,
		EndTime:       result.EncPart.EndTime,
		RenewTill:     result.EncPart.RenewTill,
		SRealm:        result.EncPart.SRealm,
		SName:         result.EncPart.SName,
		CAddr:         result.EncPart.CAddr,
	}

	// Write ccache
	if *verbose {
		log.Printf("Writing TGT to ccache file: %s", ccachePath)
	}

	err = ccache.WriteCCache(ccachePath, result.Ticket, encKDCRepPart, result.SessionKey, result.Realm, result.CName)
	if err != nil {
		log.Fatalf("Failed to write ccache: %v", err)
	}

	log.Println("Saved TGT to file")

	if *verbose {
		log.Println("Done!")
	}
}
