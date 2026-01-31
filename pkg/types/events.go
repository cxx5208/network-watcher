// Package types defines simple types for the Process Network Watcher
package types

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Connection represents a single outbound network connection from an app
type Connection struct {
	Timestamp   time.Time `json:"timestamp"`
	ProcessName string    `json:"process_name"`
	PID         uint32    `json:"pid"`
	DestIP      net.IP    `json:"dest_ip"`
	DestPort    uint16    `json:"dest_port"`
	IsKnownApp  bool      `json:"is_known_app"`
}

// String returns a friendly description of the connection
func (c *Connection) String() string {
	status := "OK"
	if !c.IsKnownApp {
		status = "UNKNOWN"
	}
	return fmt.Sprintf("[%s] %s -> %s:%d (%s)",
		c.Timestamp.Format("15:04:05"),
		c.ProcessName,
		c.DestIP,
		c.DestPort,
		status,
	)
}

// AppSummary shows network activity for one application
type AppSummary struct {
	ProcessName  string    `json:"process_name"`
	Connections  int       `json:"connections"`
	Destinations []string  `json:"destinations"`
	IsKnownApp   bool      `json:"is_known_app"`
	LastSeen     time.Time `json:"last_seen"`
}

// Alert represents an unusual app accessing the network
type Alert struct {
	ProcessName string    `json:"process_name"`
	PID         uint32    `json:"pid"`
	Destination string    `json:"destination"`
	Timestamp   time.Time `json:"timestamp"`
	Reason      string    `json:"reason"`
}

// KnownApps is the list of applications that are expected to access the internet
// Anything not on this list will trigger an alert
var KnownApps = map[string]string{
	// Browsers
	"chrome":   "Web browser",
	"chromium": "Web browser",
	"firefox":  "Web browser",
	"safari":   "Web browser",
	"brave":    "Web browser",
	"opera":    "Web browser",
	"edge":     "Web browser",

	// Development tools
	"node":    "Node.js runtime",
	"npm":     "Node package manager",
	"npx":     "Node package runner",
	"yarn":    "Node package manager",
	"pip":     "Python package manager",
	"pip3":    "Python package manager",
	"python":  "Python runtime",
	"python3": "Python runtime",
	"go":      "Go compiler",
	"git":     "Version control",
	"docker":  "Container runtime",
	"kubectl": "Kubernetes CLI",
	"code":    "VS Code",
	"cursor":  "Cursor IDE",

	// Command line tools
	"curl":  "HTTP client",
	"wget":  "Download tool",
	"ssh":   "Secure shell",
	"scp":   "Secure copy",
	"rsync": "File sync",

	// Communication apps
	"slack":    "Team chat",
	"discord":  "Chat app",
	"zoom":     "Video calls",
	"teams":    "Microsoft Teams",
	"telegram": "Messaging",
	"signal":   "Messaging",

	// System services
	"apt":             "Package manager",
	"apt-get":         "Package manager",
	"snap":            "Package manager",
	"systemd-resolve": "DNS resolver",
	"NetworkManager":  "Network service",
	"snapd":           "Snap daemon",

	// Cloud CLIs
	"aws":    "AWS CLI",
	"gcloud": "Google Cloud CLI",
	"az":     "Azure CLI",

	// VM and container processes
	"lima-guestagent": "Lima VM agent",
	"guestagent":      "VM guest agent",
	"qemu":            "QEMU emulator",
	"containerd":      "Container daemon",
	"systemd":         "System daemon",
}

// IsKnownApp checks if a process name is in the known apps list
func IsKnownApp(processName string) bool {
	// Normalize: lowercase and remove path
	name := strings.ToLower(processName)

	// Check exact match
	if _, ok := KnownApps[name]; ok {
		return true
	}

	// Check if any known app is contained in the name
	for known := range KnownApps {
		if strings.Contains(name, known) {
			return true
		}
	}

	return false
}

// GetAppDescription returns a description for a known app
func GetAppDescription(processName string) string {
	name := strings.ToLower(processName)
	if desc, ok := KnownApps[name]; ok {
		return desc
	}
	for known, desc := range KnownApps {
		if strings.Contains(name, known) {
			return desc
		}
	}
	return "Unknown application"
}

// IsPrivateIP checks if an IP is private/local (not internet)
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Loopback
		if ip4[0] == 127 {
			return true
		}
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
	}
	return false
}
