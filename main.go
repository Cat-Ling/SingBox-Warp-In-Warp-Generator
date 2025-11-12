package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// Configuration Constants
const (
	DefaultWarpServer = "engage.cloudflareclient.com"
	DefaultWarpPort   = "2408"
	DefaultNetPort    = "1080"
	DefaultDnsDetour  = "warp-out-o"
	CFWarpRegURL      = "https://api.cloudflareclient.com/v0a2025/reg"
)

// Internal structures for the Cloudflare API interaction
type cfRegisterRequest struct {
	TOS      string `json:"tos"`
	Key      string `json:"key"`
	Referrer string `json:"referrer,omitempty"`
}

// Matching the actual nested structure of the CF API response 
// is safer than grepping for "v4" and hoping we get the right one.
type cfRegisterResponse struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	Account  struct {
		License string `json:"license"`
	} `json:"account"`
	Config   struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

// WarpResponse represents the normalized data we need for the final config
type WarpResponse struct {
	Client string
	V4     string
	V6     string
	Key    string // Servrr Public Key
	Secret string // Client Private Key
}

// -- [Existing Config STructures remain unchanges] --
type Config struct {
	Log          LogConfig    `json:"log"`
	Experimental Experimental `json:"experimental"`
	DNS          DNSConfig    `json:"dns"`
	Route        RouteConfig  `json:"route"`
	Inbounds     []Inbound    `json:"inbounds"`
	Endpoints    []Endpoint   `json:"endpoints"`
	Outbounds    []Outbound   `json:"outbounds"`
}
type LogConfig struct { Level string `json:"level"` }
type Experimental struct { ClashAPI ClashAPI `json:"clash_api"` }
type ClashAPI struct {
	ExternalController       string `json:"external_controller"`
	ExternalUI               string `json:"external_ui"`
	ExternalUIDownloadURL    string `json:"external_ui_download_url"`
	ExternalUIDownloadDetour string `json:"external_ui_download_detour"`
	DefaultMode              string `json:"default_mode"`
}
type DNSConfig struct {
	Servers        []DNSServer `json:"servers"`
	Final          string      `json:"final"`
	ReverseMapping bool        `json:"reverse_mapping"`
}
type DNSServer struct {
	Tag            string `json:"tag"`
	Type           string `json:"type"`
	Server         string `json:"server"`
	DomainResolver string `json:"domain_resolver,omitempty"`
	Detour         string `json:"detour"`
}
type RouteConfig struct {
	Rules                 []Rule `json:"rules"`
	AutoDetectInterface   bool   `json:"auto_detect_interface"`
	Final                 string `json:"final"`
	DefaultDomainResolver string `json:"default_domain_resolver"`
}
type Rule struct {
	Inbound     string   `json:"inbound,omitempty"`
	Action      string   `json:"action"`
	Protocol    string   `json:"protocol,omitempty"`
	IPIsPrivate bool     `json:"ip_is_private,omitempty"`
	IPCidr      []string `json:"ip_cidr,omitempty"`
	Outbound    string   `json:"outbound,omitempty"`
}
type Inbound struct {
	Type        string   `json:"type"`
	Stack       string   `json:"stack,omitempty"`
	Tag         string   `json:"tag"`
	MTU         int      `json:"mtu,omitempty"`
	Address     []string `json:"address,omitempty"`
	AutoRoute   bool     `json:"auto_route,omitempty"`
	StrictRoute bool     `json:"strict_route,omitempty"`
	Listen      string   `json:"listen,omitempty"`
	ListenPort  int      `json:"listen_port,omitempty"`
}
type Endpoint struct {
	Type           string   `json:"type"`
	Tag            string   `json:"tag"`
	System         bool     `json:"system"`
	Name           string   `json:"name"`
	MTU            int      `json:"mtu"`
	Address        []string `json:"address"`
	PrivateKey     string   `json:"private_key"`
	Peers          []Peer   `json:"peers"`
	DomainResolver string   `json:"domain_resolver"`
	Detour         string   `json:"detour,omitempty"`
	Workers        int      `json:"workers"`
}
type Peer struct {
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Reserved   []uint8  `json:"reserved"`
}
type Outbound struct {
	Type          string `json:"type"`
	Tag           string `json:"tag"`
	BindInterface string `json:"bind_interface,omitempty"`
}

// -- [Helpers] --

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func resolveWarpServer(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return host
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	if len(ips) > 0 {
		return fmt.Sprintf("[%s]", ips[0].String())
	}
	return host
}

// GenerateKeys creates a fresh X25519 keypair using crypto/ecdh (Go 1.20+)
func generateKeys() (string, string, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubKey := privKey.PublicKey()

	privB64 := base64.StdEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(pubKey.Bytes())

	return privB64, pubB64, nil
}

// FetchWarpConfig performs the pure Go registration logic
func fetchWarpConfig() (WarpResponse, error) {
	// 1. Generate Keys
	privKey, pubKey, err := generateKeys()
	if err != nil {
		return WarpResponse{}, fmt.Errorf("key generation failed: %v", err)
	}

	// 2. Prepare Payload
	// Standard RFC3339 is usually fine for TOS, no need for awkward grep/awk hacks
	tos := time.Now().Format(time.RFC3339) 
	
	reqPayload := cfRegisterRequest{
		TOS: tos,
		Key: pubKey,
	}
	jsonPayload, err := json.Marshal(reqPayload)
	if err != nil {
		return WarpResponse{}, fmt.Errorf("payload marshal failed: %v", err)
	}

	// 3. Make HTTP Request
	req, err := http.NewRequest("POST", CFWarpRegURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return WarpResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return WarpResponse{}, fmt.Errorf("http request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return WarpResponse{}, fmt.Errorf("API returned non-200 status: %d, body: %s", resp.StatusCode, string(body))
	}

	// 4. Parse Response
	var cfResp cfRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return WarpResponse{}, fmt.Errorf("failed to decode response: %v", err)
	}

	// Validate essential fields
	if len(cfResp.Config.Peers) == 0 {
		return WarpResponse{}, fmt.Errorf("no peers found in response")
	}

	return WarpResponse{
		Client: cfResp.Config.ClientID,
		V4:     cfResp.Config.Interface.Addresses.V4,
		V6:     cfResp.Config.Interface.Addresses.V6,
		Key:    cfResp.Config.Peers[0].PublicKey, // Server's Public Key
		Secret: privKey,                          // Our Private Key
	}, nil
}

func getReserved(clientID string) ([]uint8, error) {
	decoded, err := base64.StdEncoding.DecodeString(clientID)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 3 {
		return nil, fmt.Errorf("client ID too short")
	}
	return []uint8{decoded[0], decoded[1], decoded[2]}, nil
}

func main() {
	// Environment Variables
	warpServer := getEnv("WARP_SERVER", DefaultWarpServer)
	warpPort := getEnv("WARP_PORT", DefaultWarpPort)
	netPort := getEnv("NET_PORT", DefaultNetPort)
	disableIPv6 := getEnv("DISABLE_IPV6", "0") == "1"
	dnsDetour := getEnv("DNS_DETOUR", DefaultDnsDetour)
	warpOutIf := getEnv("WARP_OUT_IF", "wg-warp-out")
	warpInIf := getEnv("WARP_IN_IF", "wg-warp-in")

	// Resolve IP
	serverAddr := resolveWarpServer(warpServer)

	// Fetch Warp Configs
	fmt.Println("Registering Warp Identity (Out)...")
	resOut, err := fetchWarpConfig()
	if err != nil {
		log.Fatalf("Error registering OUT identity: %v", err)
	}

	fmt.Println("Registering Warp Identity (In)...")
	resIn, err := fetchWarpConfig()
	if err != nil {
		log.Fatalf("Error registering IN identity: %v", err)
	}

	// Calculate Reserved Bytes
	reservedOut, err := getReserved(resOut.Client)
	if err != nil {
		log.Fatalf("Error calculating reserved bytes for OUT: %v", err)
	}
	reservedIn, err := getReserved(resIn.Client)
	if err != nil {
		log.Fatalf("Error calculating reserved bytes for IN: %v", err)
	}

	// Construct Addresses
	var outAddr, inAddr, tunAddr []string
	
	outAddr = []string{resOut.V4 + "/32", resOut.V6 + "/128"}
	inAddr = []string{resIn.V4 + "/32", resIn.V6 + "/128"}
	tunAddr = []string{"172.31.100.1/24", "2606:4700:110:82bf:4e06:f866:35d8:406f/64"}

	if disableIPv6 {
		outAddr = []string{resOut.V4 + "/32"}
		inAddr = []string{resIn.V4 + "/32"}
		tunAddr = []string{"172.31.100.1/32"}
	}

	// Parse ports
	var wPort int
	fmt.Sscanf(warpPort, "%d", &wPort)
	var nPort int
	fmt.Sscanf(netPort, "%d", &nPort)

	// Build JSON Structure
	config := Config{
		Log: LogConfig{Level: "error"},
		Experimental: Experimental{
			ClashAPI: ClashAPI{
				ExternalController:       "0.0.0.0:9090",
				ExternalUI:               "metacubexd",
				ExternalUIDownloadURL:    "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
				ExternalUIDownloadDetour: dnsDetour,
				DefaultMode:              "global",
			},
		},
		DNS: DNSConfig{
			Servers: []DNSServer{
				{Tag: "remote", Type: "tls", Server: "1.1.1.1", DomainResolver: "local", Detour: dnsDetour},
				{Tag: "local", Type: "tls", Server: "1.0.0.1", Detour: dnsDetour},
			},
			Final:          "remote",
			ReverseMapping: true,
		},
		Route: RouteConfig{
			Rules: []Rule{
				{Inbound: "mixed-in", Action: "sniff"},
				{Inbound: "tun-in", Action: "sniff"},
				{Protocol: "dns", Action: "hijack-dns"},
				{IPIsPrivate: true, Outbound: "direct-out"},
				{IPCidr: []string{
					"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
					"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
					"52.80.0.0/16", "112.95.0.0/16",
				}, Outbound: "direct-out"},
			},
			AutoDetectInterface:   true,
			Final:                 "warp-in-o",
			DefaultDomainResolver: "local",
		},
		Inbounds: []Inbound{
			{
				Type: "tun", Stack: "gvisor", Tag: "tun-in", MTU: 1280,
				Address: tunAddr, AutoRoute: true, StrictRoute: true,
			},
			{
				Type: "mixed", Tag: "mixed-in", Listen: "::", ListenPort: nPort,
			},
		},
		Endpoints: []Endpoint{
			{
				Type: "wireguard", Tag: "warp-out", System: true, Name: warpOutIf, MTU: 1280,
				Address: outAddr, PrivateKey: resOut.Secret,
				Peers: []Peer{{
					Address: serverAddr, Port: wPort, PublicKey: resOut.Key,
					AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Reserved: reservedOut,
				}},
				DomainResolver: "local", Workers: 4,
			},
			{
				Type: "wireguard", Tag: "warp-in", System: true, Name: warpInIf, MTU: 1280,
				Address: inAddr, PrivateKey: resIn.Secret,
				Peers: []Peer{{
					Address: serverAddr, Port: wPort, PublicKey: resIn.Key,
					AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Reserved: reservedIn,
				}},
				DomainResolver: "local", Detour: "warp-out-o", Workers: 4,
			},
		},
		Outbounds: []Outbound{
			{Type: "direct", Tag: "direct-out"},
			{Type: "direct", Tag: "warp-out-o", BindInterface: warpOutIf},
			{Type: "direct", Tag: "warp-in-o", BindInterface: warpInIf},
		},
	}

	// Write config,json
	file, err := os.Create("config.json")
	if err != nil {
		log.Fatalf("Error creating config.json: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		log.Fatalf("Error writing config JSON: %v", err)
	}

	fmt.Println("Successfully generated config.json")
}
