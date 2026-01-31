// Package store tracks network connections from applications
package store

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/types"
)

// Store keeps track of all network connections
type Store struct {
	mu          sync.RWMutex
	connections []types.Connection
	maxSize     int
	alerts      []types.Alert
}

// New creates a new connection store
func New(maxSize int) *Store {
	return &Store{
		connections: make([]types.Connection, 0, maxSize),
		maxSize:     maxSize,
		alerts:      make([]types.Alert, 0),
	}
}

// Add records a new connection
func (s *Store) Add(conn types.Connection) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store the connection (IsKnownApp is already set by the collector)
	s.connections = append(s.connections, conn)

	// Trim if over max size
	if len(s.connections) > s.maxSize {
		s.connections = s.connections[len(s.connections)-s.maxSize:]
	}

	// Create alert for unknown apps
	if !conn.IsKnownApp {
		alert := types.Alert{
			ProcessName: conn.ProcessName,
			PID:         conn.PID,
			Destination: fmt.Sprintf("%s:%d", conn.DestIP, conn.DestPort),
			Timestamp:   conn.Timestamp,
			Reason:      "Unknown application accessing the internet",
		}
		s.alerts = append(s.alerts, alert)

		// Keep only recent alerts (last 100)
		if len(s.alerts) > 100 {
			s.alerts = s.alerts[len(s.alerts)-100:]
		}
	}
}

// GetActiveApps returns a summary of apps that accessed the internet
func (s *Store) GetActiveApps(since time.Duration) []types.AppSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-since)

	// Group connections by process name
	appData := make(map[string]*appInfo)

	for _, conn := range s.connections {
		if conn.Timestamp.Before(cutoff) {
			continue
		}

		info, exists := appData[conn.ProcessName]
		if !exists {
			info = &appInfo{
				name:         conn.ProcessName,
				isKnown:      conn.IsKnownApp,
				destinations: make(map[string]bool),
			}
			appData[conn.ProcessName] = info
		}

		info.count++
		info.destinations[fmt.Sprintf("%s:%d", conn.DestIP, conn.DestPort)] = true
		if conn.Timestamp.After(info.lastSeen) {
			info.lastSeen = conn.Timestamp
		}
	}

	// Convert to summaries
	var summaries []types.AppSummary
	for _, info := range appData {
		dests := make([]string, 0, len(info.destinations))
		for d := range info.destinations {
			dests = append(dests, d)
		}

		summaries = append(summaries, types.AppSummary{
			ProcessName:  info.name,
			Connections:  info.count,
			Destinations: dests,
			IsKnownApp:   info.isKnown,
			LastSeen:     info.lastSeen,
		})
	}

	// Sort by connection count (most active first)
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Connections > summaries[j].Connections
	})

	return summaries
}

// helper struct for grouping
type appInfo struct {
	name         string
	count        int
	isKnown      bool
	destinations map[string]bool
	lastSeen     time.Time
}

// CheckApp returns details about a specific app's network activity
func (s *Store) CheckApp(processName string, since time.Duration) *types.AppSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	destinations := make(map[string]bool)
	var count int
	var lastSeen time.Time
	var isKnown bool

	for _, conn := range s.connections {
		if conn.Timestamp.Before(cutoff) {
			continue
		}
		if conn.ProcessName != processName {
			continue
		}

		count++
		isKnown = conn.IsKnownApp
		destinations[fmt.Sprintf("%s:%d", conn.DestIP, conn.DestPort)] = true
		if conn.Timestamp.After(lastSeen) {
			lastSeen = conn.Timestamp
		}
	}

	if count == 0 {
		return nil
	}

	dests := make([]string, 0, len(destinations))
	for d := range destinations {
		dests = append(dests, d)
	}

	return &types.AppSummary{
		ProcessName:  processName,
		Connections:  count,
		Destinations: dests,
		IsKnownApp:   isKnown,
		LastSeen:     lastSeen,
	}
}

// GetAlerts returns recent alerts for unknown apps
func (s *Store) GetAlerts(since time.Duration) []types.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-since)
	var recent []types.Alert

	for _, alert := range s.alerts {
		if alert.Timestamp.After(cutoff) {
			recent = append(recent, alert)
		}
	}

	return recent
}

// GetStats returns simple stats
func (s *Store) GetStats() (totalConnections int, totalAlerts int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.connections), len(s.alerts)
}
