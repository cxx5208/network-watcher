package store

import (
	"net"
	"testing"
	"time"

	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/types"
)

func TestNew(t *testing.T) {
	s := New(100)
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.maxSize != 100 {
		t.Errorf("maxSize = %d, want 100", s.maxSize)
	}
}

func TestAdd(t *testing.T) {
	s := New(100)

	conn := types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "curl",
		PID:         1234,
		DestIP:      net.ParseIP("8.8.8.8"),
		DestPort:    443,
		IsKnownApp:  true,
	}

	s.Add(conn)

	if len(s.connections) != 1 {
		t.Errorf("connections count = %d, want 1", len(s.connections))
	}
}

func TestAddUnknownAppCreatesAlert(t *testing.T) {
	s := New(100)

	conn := types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "mystery-app",
		PID:         5678,
		DestIP:      net.ParseIP("1.2.3.4"),
		DestPort:    80,
		IsKnownApp:  false,
	}

	s.Add(conn)

	if len(s.alerts) != 1 {
		t.Errorf("alerts count = %d, want 1", len(s.alerts))
	}
	if s.alerts[0].ProcessName != "mystery-app" {
		t.Errorf("alert process = %s, want mystery-app", s.alerts[0].ProcessName)
	}
}

func TestAddKnownAppNoAlert(t *testing.T) {
	s := New(100)

	conn := types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "curl",
		PID:         1234,
		DestIP:      net.ParseIP("8.8.8.8"),
		DestPort:    443,
		IsKnownApp:  true,
	}

	s.Add(conn)

	if len(s.alerts) != 0 {
		t.Errorf("alerts count = %d, want 0", len(s.alerts))
	}
}

func TestMaxSize(t *testing.T) {
	s := New(5)

	for i := 0; i < 10; i++ {
		conn := types.Connection{
			Timestamp:   time.Now(),
			ProcessName: "test",
			PID:         uint32(i),
			DestIP:      net.ParseIP("1.1.1.1"),
			DestPort:    80,
			IsKnownApp:  true,
		}
		s.Add(conn)
	}

	if len(s.connections) != 5 {
		t.Errorf("connections count = %d, want 5 (maxSize)", len(s.connections))
	}
}

func TestGetActiveApps(t *testing.T) {
	s := New(100)

	// Add connections for two different apps
	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "curl",
		DestIP:      net.ParseIP("8.8.8.8"),
		DestPort:    443,
		IsKnownApp:  true,
	})
	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "curl",
		DestIP:      net.ParseIP("1.1.1.1"),
		DestPort:    80,
		IsKnownApp:  true,
	})
	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "wget",
		DestIP:      net.ParseIP("9.9.9.9"),
		DestPort:    443,
		IsKnownApp:  true,
	})

	apps := s.GetActiveApps(time.Hour)

	if len(apps) != 2 {
		t.Errorf("apps count = %d, want 2", len(apps))
	}

	// Find curl and verify its connection count
	var curlApp *types.AppSummary
	for i := range apps {
		if apps[i].ProcessName == "curl" {
			curlApp = &apps[i]
			break
		}
	}

	if curlApp == nil {
		t.Fatal("curl app not found")
	}
	if curlApp.Connections != 2 {
		t.Errorf("curl connections = %d, want 2", curlApp.Connections)
	}
}

func TestGetActiveAppsFiltersOldConnections(t *testing.T) {
	s := New(100)

	// Add an old connection
	s.Add(types.Connection{
		Timestamp:   time.Now().Add(-2 * time.Hour),
		ProcessName: "old-app",
		DestIP:      net.ParseIP("1.1.1.1"),
		DestPort:    80,
		IsKnownApp:  true,
	})

	// Add a recent connection
	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "new-app",
		DestIP:      net.ParseIP("2.2.2.2"),
		DestPort:    443,
		IsKnownApp:  true,
	})

	apps := s.GetActiveApps(time.Hour)

	if len(apps) != 1 {
		t.Errorf("apps count = %d, want 1", len(apps))
	}
	if apps[0].ProcessName != "new-app" {
		t.Errorf("app name = %s, want new-app", apps[0].ProcessName)
	}
}

func TestCheckApp(t *testing.T) {
	s := New(100)

	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "curl",
		DestIP:      net.ParseIP("8.8.8.8"),
		DestPort:    443,
		IsKnownApp:  true,
	})

	result := s.CheckApp("curl", time.Hour)
	if result == nil {
		t.Fatal("CheckApp returned nil for existing app")
	}
	if result.ProcessName != "curl" {
		t.Errorf("ProcessName = %s, want curl", result.ProcessName)
	}

	// Check non-existent app
	result = s.CheckApp("nonexistent", time.Hour)
	if result != nil {
		t.Error("CheckApp should return nil for non-existent app")
	}
}

func TestGetAlerts(t *testing.T) {
	s := New(100)

	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "unknown-app",
		DestIP:      net.ParseIP("5.5.5.5"),
		DestPort:    8080,
		IsKnownApp:  false,
	})

	alerts := s.GetAlerts(time.Hour)

	if len(alerts) != 1 {
		t.Errorf("alerts count = %d, want 1", len(alerts))
	}
}

func TestGetStats(t *testing.T) {
	s := New(100)

	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "app1",
		DestIP:      net.ParseIP("1.1.1.1"),
		DestPort:    80,
		IsKnownApp:  true,
	})
	s.Add(types.Connection{
		Timestamp:   time.Now(),
		ProcessName: "app2",
		DestIP:      net.ParseIP("2.2.2.2"),
		DestPort:    443,
		IsKnownApp:  false,
	})

	conns, alerts := s.GetStats()

	if conns != 2 {
		t.Errorf("connections = %d, want 2", conns)
	}
	if alerts != 1 {
		t.Errorf("alerts = %d, want 1", alerts)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New(1000)

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			s.Add(types.Connection{
				Timestamp:   time.Now(),
				ProcessName: "test",
				DestIP:      net.ParseIP("1.1.1.1"),
				DestPort:    uint16(i),
				IsKnownApp:  i%2 == 0,
			})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			s.GetActiveApps(time.Hour)
			s.GetAlerts(time.Hour)
			s.GetStats()
		}
		done <- true
	}()

	<-done
	<-done
}
