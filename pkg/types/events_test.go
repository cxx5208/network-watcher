package types

import (
	"net"
	"testing"
	"time"
)

func TestConnectionString(t *testing.T) {
	conn := Connection{
		Timestamp:   time.Date(2024, 1, 15, 14, 30, 45, 0, time.UTC),
		ProcessName: "curl",
		PID:         1234,
		DestIP:      net.ParseIP("8.8.8.8"),
		DestPort:    443,
		IsKnownApp:  true,
	}

	str := conn.String()

	if str == "" {
		t.Error("String() returned empty string")
	}
	if !contains(str, "curl") {
		t.Error("String() should contain process name")
	}
	if !contains(str, "8.8.8.8") {
		t.Error("String() should contain IP")
	}
	if !contains(str, "443") {
		t.Error("String() should contain port")
	}
	if !contains(str, "OK") {
		t.Error("String() should contain OK for known app")
	}
}

func TestConnectionStringUnknown(t *testing.T) {
	conn := Connection{
		Timestamp:   time.Now(),
		ProcessName: "mystery",
		DestIP:      net.ParseIP("1.2.3.4"),
		DestPort:    80,
		IsKnownApp:  false,
	}

	str := conn.String()

	if !contains(str, "UNKNOWN") {
		t.Error("String() should contain UNKNOWN for unknown app")
	}
}

func TestIsKnownApp(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"curl", true},
		{"wget", true},
		{"chrome", true},
		{"firefox", true},
		{"node", true},
		{"python", true},
		{"python3", true},
		{"go", true},
		{"git", true},
		{"docker", true},
		{"ssh", true},
		{"mystery-app", false},
		{"malware", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKnownApp(tt.name)
			if result != tt.expected {
				t.Errorf("IsKnownApp(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestIsKnownAppCaseInsensitive(t *testing.T) {
	tests := []string{"CURL", "Curl", "cUrL", "WGET", "Chrome", "FIREFOX"}

	for _, name := range tests {
		if !IsKnownApp(name) {
			t.Errorf("IsKnownApp(%s) should be true (case insensitive)", name)
		}
	}
}

func TestIsKnownAppPartialMatch(t *testing.T) {
	// Should match if known app name is contained
	tests := []struct {
		name     string
		expected bool
	}{
		{"google-chrome", true},
		{"python3.11", true},
		{"node-v18", true},
		{"totally-unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsKnownApp(tt.name)
			if result != tt.expected {
				t.Errorf("IsKnownApp(%s) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestGetAppDescription(t *testing.T) {
	tests := []struct {
		name        string
		shouldMatch bool
	}{
		{"curl", true},
		{"chrome", true},
		{"mystery", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := GetAppDescription(tt.name)
			if tt.shouldMatch && desc == "Unknown application" {
				t.Errorf("GetAppDescription(%s) should return a description", tt.name)
			}
			if !tt.shouldMatch && desc != "Unknown application" {
				t.Errorf("GetAppDescription(%s) should return 'Unknown application'", tt.name)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// Private IPs
		{"127.0.0.1", true},
		{"127.0.0.255", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"142.250.185.14", false},
		{"172.15.0.1", false},  // Just outside 172.16.x.x range
		{"172.32.0.1", false},  // Just outside 172.16-31.x.x range
		{"192.167.1.1", false}, // Just outside 192.168.x.x range
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IsPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIPNil(t *testing.T) {
	if IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) should return false")
	}
}

func TestKnownAppsMap(t *testing.T) {
	// Verify essential apps are in the list
	essential := []string{
		"curl", "wget", "chrome", "firefox", "node", "npm",
		"python", "go", "git", "docker", "ssh", "apt",
	}

	for _, app := range essential {
		if _, ok := KnownApps[app]; !ok {
			t.Errorf("KnownApps should contain %s", app)
		}
	}
}

func TestKnownAppsDescriptions(t *testing.T) {
	// All apps should have non-empty descriptions
	for name, desc := range KnownApps {
		if desc == "" {
			t.Errorf("KnownApps[%s] has empty description", name)
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
