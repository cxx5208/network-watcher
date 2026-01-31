// Network Watcher - Production-Ready eBPF Security Monitor
// Features: GeoIP, Risk Scoring, Security Headers, Rate Limiting, Structured Logging
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/collector"
	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/store"
	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/types"
	"github.com/gorilla/websocket"
)

// SafeConn wraps websocket with mutex for thread-safe writes
type SafeConn struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (c *SafeConn) WriteJSON(v any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteJSON(v)
}

func (c *SafeConn) Close() error {
	return c.conn.Close()
}

// Application state
var (
	eventStore   *store.Store
	clients      = make(map[*SafeConn]bool)
	clientsMu    sync.Mutex
	upgrader     = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	startTime    = time.Now()
	geoCache     = make(map[string]*GeoInfo)
	geoCacheMu   sync.RWMutex
	dnsCache     = make(map[string]string)
	dnsCacheMu   sync.RWMutex
	rateLimit    = make(map[string]int)
	rateLimitMu  sync.Mutex
	whitelist    = make(map[string]bool)
	whitelistMu  sync.RWMutex
	connPerMin   int
	connPerMinMu sync.Mutex
)

// GeoInfo holds IP geolocation data
type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// ThreatRule for pattern matching
type ThreatRule struct {
	Pattern  *regexp.Regexp
	Name     string
	Severity string
	Points   int
}

// High-risk countries for scoring
var highRiskCountries = map[string]bool{
	"CN": true, "RU": true, "KP": true, "IR": true,
}

// Threat detection rules
var threatRules = []ThreatRule{
	{regexp.MustCompile(`(?i)miner`), "Cryptominer", "critical", 40},
	{regexp.MustCompile(`(?i)crypto`), "Crypto Activity", "high", 35},
	{regexp.MustCompile(`(?i)botnet`), "Botnet", "critical", 45},
	{regexp.MustCompile(`(?i)backdoor`), "Backdoor", "critical", 45},
	{regexp.MustCompile(`(?i)reverse.*shell`), "Reverse Shell", "critical", 45},
	{regexp.MustCompile(`(?i)^nc$`), "Netcat", "high", 30},
	{regexp.MustCompile(`(?i)^ncat$`), "Ncat", "high", 30},
	{regexp.MustCompile(`(?i)^socat$`), "Socat", "medium", 25},
}

// Unusual ports for scoring
var unusualPorts = map[uint16]bool{
	4444: true, 5555: true, 6666: true, 31337: true, 12345: true,
}

// Known port services
var portNames = map[uint16]string{
	22: "SSH", 80: "HTTP", 443: "HTTPS", 53: "DNS", 8080: "HTTP",
	3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB",
}

func main() {
	if os.Geteuid() != 0 {
		log.Fatal(`{"level":"error","msg":"requires root privileges"}`)
	}

	eventStore = store.New(10000)
	ctx, cancel := context.WithCancel(context.Background())

	// Reset connections per minute counter
	go func() {
		for range time.Tick(time.Minute) {
			connPerMinMu.Lock()
			connPerMin = 0
			connPerMinMu.Unlock()
		}
	}()

	// Reset rate limits every minute
	go func() {
		for range time.Tick(time.Minute) {
			rateLimitMu.Lock()
			rateLimit = make(map[string]int)
			rateLimitMu.Unlock()
		}
	}()

	// Start eBPF collector
	coll, err := collector.New()
	if err != nil {
		logJSON("error", "collector_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	defer coll.Close()

	logJSON("info", "loading_ebpf", nil)
	if err := coll.Start(ctx); err != nil {
		logJSON("error", "ebpf_start_failed", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	logJSON("info", "ebpf_loaded", nil)

	// Process events
	go func() {
		for e := range coll.Events() {
			connPerMinMu.Lock()
			connPerMin++
			connPerMinMu.Unlock()
			eventStore.Add(e)
			broadcast(e)
		}
	}()

	// Graceful shutdown
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logJSON("info", "shutting_down", nil)
		clientsMu.Lock()
		for c := range clients {
			c.Close()
		}
		clientsMu.Unlock()
		cancel()
		os.Exit(0)
	}()

	// Create custom fetcher for demo
	exec.Command("cp", "/usr/bin/curl", "/tmp/url-fetcher").Run()
	exec.Command("chmod", "+x", "/tmp/url-fetcher").Run()

	// Routes with middleware
	http.HandleFunc("/", withSecurity(serveHTML))
	http.HandleFunc("/ws", handleWS)
	http.HandleFunc("/health", withSecurity(handleHealth))
	http.HandleFunc("/api/data", withSecurity(handleData))
	http.HandleFunc("/api/fetch", withSecurity(withRateLimit(handleFetch)))
	http.HandleFunc("/api/whitelist", withSecurity(handleWhitelist))
	http.HandleFunc("/api/export/json", withSecurity(handleExportJSON))
	http.HandleFunc("/api/export/csv", withSecurity(handleExportCSV))

	logJSON("info", "server_started", map[string]any{"port": 8080})
	fmt.Println("\n  Network Watcher - http://localhost:8080\n")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// Structured JSON logging
func logJSON(level, event string, data map[string]any) {
	entry := map[string]any{
		"time":  time.Now().Format(time.RFC3339),
		"level": level,
		"event": event,
	}
	for k, v := range data {
		entry[k] = v
	}
	b, _ := json.Marshal(entry)
	fmt.Println(string(b))
}

// Security headers middleware
func withSecurity(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next(w, r)
	}
}

// Rate limiting middleware
func withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		rateLimitMu.Lock()
		rateLimit[ip]++
		count := rateLimit[ip]
		rateLimitMu.Unlock()

		if count > 10 {
			http.Error(w, `{"error":"rate limit exceeded"}`, 429)
			return
		}
		next(w, r)
	}
}

// Health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	conns, alerts := eventStore.GetStats()
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "healthy",
		"uptime_secs": int(time.Since(startTime).Seconds()),
		"connections": conns,
		"alerts":      alerts,
		"clients":     len(clients),
	})
}

// GeoIP lookup with caching
func getGeoInfo(ip string) *GeoInfo {
	if net.ParseIP(ip) == nil || types.IsPrivateIP(net.ParseIP(ip)) {
		return nil
	}

	geoCacheMu.RLock()
	if cached, ok := geoCache[ip]; ok {
		geoCacheMu.RUnlock()
		return cached
	}
	geoCacheMu.RUnlock()

	resp, err := http.Get("http://ip-api.com/json/" + ip + "?fields=country,countryCode,city,lat,lon")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var geo GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil
	}

	geoCacheMu.Lock()
	geoCache[ip] = &geo
	geoCacheMu.Unlock()

	return &geo
}

// DNS resolution with caching
func resolveDNS(ip string) string {
	dnsCacheMu.RLock()
	if cached, ok := dnsCache[ip]; ok {
		dnsCacheMu.RUnlock()
		return cached
	}
	dnsCacheMu.RUnlock()

	names, err := net.LookupAddr(ip)
	result := ""
	if err == nil && len(names) > 0 {
		result = strings.TrimSuffix(names[0], ".")
	}

	dnsCacheMu.Lock()
	dnsCache[ip] = result
	dnsCacheMu.Unlock()

	return result
}

// Calculate risk score for a connection
func calculateRisk(processName string, port uint16, countryCode string, isKnown bool) int {
	score := 0

	// Unknown app
	if !isKnown {
		score += 30
	}

	// Check whitelist
	whitelistMu.RLock()
	if whitelist[strings.ToLower(processName)] {
		whitelistMu.RUnlock()
		return 0
	}
	whitelistMu.RUnlock()

	// Threat patterns
	for _, rule := range threatRules {
		if rule.Pattern.MatchString(processName) {
			score += rule.Points
		}
	}

	// Unusual port
	if unusualPorts[port] {
		score += 20
	}

	// High-risk country
	if highRiskCountries[countryCode] {
		score += 25
	}

	if score > 100 {
		score = 100
	}
	return score
}

// WebSocket handler
func handleWS(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := &SafeConn{conn: wsConn}
	defer conn.Close()

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	conn.WriteJSON(map[string]any{"type": "init", "data": getData()})

	for {
		if _, _, err := wsConn.ReadMessage(); err != nil {
			clientsMu.Lock()
			delete(clients, conn)
			clientsMu.Unlock()
			break
		}
	}
}

// Broadcast event to all clients
func broadcast(e types.Connection) {
	ip := e.DestIP.String()
	hostname := resolveDNS(ip)
	geo := getGeoInfo(ip)

	countryCode := ""
	if geo != nil {
		countryCode = geo.CountryCode
	}

	risk := calculateRisk(e.ProcessName, e.DestPort, countryCode, e.IsKnownApp)

	msg := map[string]any{
		"type": "event",
		"data": map[string]any{
			"name": e.ProcessName, "ip": ip, "hostname": hostname,
			"port": e.DestPort, "known": e.IsKnownApp, "time": e.Timestamp,
			"geo": geo, "risk": risk,
		},
	}

	if risk >= 70 {
		logJSON("warn", "high_risk_connection", map[string]any{
			"process": e.ProcessName, "ip": ip, "risk": risk,
		})
	}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	for c := range clients {
		if err := c.WriteJSON(msg); err != nil {
			c.Close()
			delete(clients, c)
		}
	}
}

// Get all dashboard data
func getData() map[string]any {
	apps := eventStore.GetActiveApps(60 * time.Minute)

	// Enrich with geo and risk
	var enriched []map[string]any
	var locations []map[string]any
	seenLocs := make(map[string]bool)

	for _, app := range apps {
		appData := map[string]any{
			"process_name": app.ProcessName,
			"connections":  app.Connections,
			"is_known_app": app.IsKnownApp,
			"destinations": app.Destinations,
			"risk":         0,
		}

		maxRisk := 0
		for _, dest := range app.Destinations {
			parts := strings.Split(dest, ":")
			if len(parts) >= 1 {
				ip := strings.Split(parts[0], " ")[0]
				if strings.Contains(parts[0], "(") {
					start := strings.Index(parts[0], "(")
					end := strings.Index(parts[0], ")")
					if start != -1 && end != -1 {
						ip = parts[0][start+1 : end]
					}
				}
				geo := getGeoInfo(ip)
				var port uint16
				if len(parts) >= 2 {
					fmt.Sscanf(parts[len(parts)-1], "%d", &port)
				}
				cc := ""
				if geo != nil {
					cc = geo.CountryCode
					locKey := fmt.Sprintf("%.1f,%.1f", geo.Lat, geo.Lon)
					if !seenLocs[locKey] && geo.Lat != 0 {
						seenLocs[locKey] = true
						locations = append(locations, map[string]any{
							"lat": geo.Lat, "lon": geo.Lon,
							"country": geo.Country, "city": geo.City,
						})
					}
				}
				risk := calculateRisk(app.ProcessName, port, cc, app.IsKnownApp)
				if risk > maxRisk {
					maxRisk = risk
				}
			}
		}
		appData["risk"] = maxRisk
		enriched = append(enriched, appData)
	}

	// Sort by risk
	sort.Slice(enriched, func(i, j int) bool {
		return enriched[i]["risk"].(int) > enriched[j]["risk"].(int)
	})

	connPerMinMu.Lock()
	cpm := connPerMin
	connPerMinMu.Unlock()

	return map[string]any{
		"apps":      enriched,
		"analysis":  analyze(apps),
		"locations": locations,
		"stats": map[string]any{
			"connections_per_min": cpm,
			"uptime_secs":         int(time.Since(startTime).Seconds()),
		},
	}
}

// AI Analysis
func analyze(apps []types.AppSummary) map[string]any {
	total, unknown, threats := 0, 0, 0
	var threatList []map[string]any
	portMap := make(map[uint16]int)

	for _, app := range apps {
		total += app.Connections
		if !app.IsKnownApp {
			unknown++
		}
		for _, rule := range threatRules {
			if rule.Pattern.MatchString(app.ProcessName) {
				threats++
				threatList = append(threatList, map[string]any{
					"process": app.ProcessName, "threat": rule.Name,
					"severity": rule.Severity, "points": rule.Points,
				})
			}
		}
		for _, d := range app.Destinations {
			parts := strings.Split(d, ":")
			if len(parts) >= 2 {
				var port uint16
				fmt.Sscanf(parts[len(parts)-1], "%d", &port)
				portMap[port]++
			}
		}
	}

	// Top ports
	type pstat struct {
		Port    uint16 `json:"port"`
		Count   int    `json:"count"`
		Service string `json:"service"`
	}
	var topPorts []pstat
	for p, c := range portMap {
		svc := portNames[p]
		if svc == "" {
			svc = "Other"
		}
		topPorts = append(topPorts, pstat{p, c, svc})
	}
	sort.Slice(topPorts, func(i, j int) bool { return topPorts[i].Count > topPorts[j].Count })
	if len(topPorts) > 5 {
		topPorts = topPorts[:5]
	}

	// Risk level
	level, avgRisk := "low", 0
	if threats > 0 {
		level, avgRisk = "critical", 85
	} else if unknown > 2 {
		level, avgRisk = "high", 65
	} else if unknown > 0 {
		level, avgRisk = "medium", 40
	}

	summary := "All systems secure. No suspicious activity."
	if threats > 0 {
		summary = fmt.Sprintf("CRITICAL: %d threat pattern(s) detected.", threats)
	} else if unknown > 0 {
		summary = fmt.Sprintf("%d unrecognized application(s) accessing network.", unknown)
	} else if total == 0 {
		summary = "Monitoring active. Awaiting connections..."
	}

	return map[string]any{
		"summary": summary, "level": level, "risk": avgRisk,
		"total": total, "apps": len(apps), "unknown": unknown,
		"ports": topPorts, "threats": threatList,
	}
}

// Handle URL fetch
func handleFetch(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	mode := r.URL.Query().Get("mode")
	if url == "" {
		http.Error(w, `{"error":"missing url"}`, 400)
		return
	}
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	go func() {
		bin := "/tmp/url-fetcher"
		if mode == "known" {
			bin = "curl"
		}
		exec.Command(bin, "-s", "-m", "10", url).Run()
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "url": url})
}

// Handle whitelist add
func handleWhitelist(w http.ResponseWriter, r *http.Request) {
	app := r.URL.Query().Get("app")
	if app == "" {
		http.Error(w, `{"error":"missing app"}`, 400)
		return
	}
	whitelistMu.Lock()
	whitelist[strings.ToLower(app)] = true
	whitelistMu.Unlock()

	logJSON("info", "app_whitelisted", map[string]any{"app": app})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "whitelisted", "app": app})
}

// Handle data endpoint
func handleData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(getData())
}

// Export JSON
func handleExportJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=network-watcher.json")
	json.NewEncoder(w).Encode(getData())
}

// Export CSV
func handleExportCSV(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=network-watcher.csv")
	apps := eventStore.GetActiveApps(60 * time.Minute)
	wr := csv.NewWriter(w)
	wr.Write([]string{"Process", "Connections", "Status", "Risk", "Destinations"})
	for _, app := range apps {
		status := "Known"
		if !app.IsKnownApp {
			status = "Unknown"
		}
		wr.Write([]string{app.ProcessName, fmt.Sprintf("%d", app.Connections), status, "0", strings.Join(app.Destinations, "; ")})
	}
	wr.Flush()
}

// Serve embedded HTML
func serveHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, htmlPage)
}

const htmlPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Watcher</title>
<style>
:root{--bg:#0a0a0a;--card:#111;--border:#222;--text:#fff;--muted:#888;--green:#00d26a;--yellow:#ffc107;--red:#ff4757;--blue:#5c7cfa}
[data-theme=light]{--bg:#f5f5f5;--card:#fff;--border:#ddd;--text:#111;--muted:#666}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
.wrap{max-width:1400px;margin:0 auto;padding:24px}

.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:16px}
.logo{font-size:24px;font-weight:700}
.logo span{color:var(--muted);font-weight:400;font-size:14px;margin-left:8px}
.header-actions{display:flex;gap:8px;align-items:center}
.btn{background:var(--card);border:1px solid var(--border);color:var(--text);padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px;transition:all .2s}
.btn:hover{background:var(--border)}
.btn-primary{background:var(--text);color:var(--bg)}
.status{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{50%{opacity:.5}}

.input-row{display:flex;gap:8px;margin-bottom:24px}
.input-row input{flex:1;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;color:var(--text);font-size:14px}
.input-row input:focus{outline:none;border-color:var(--blue)}
.hint{font-size:11px;color:var(--muted);text-align:center;margin:-16px 0 24px}

.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:24px}
@media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}}
@media(max-width:500px){.stats{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center}
.stat-value{font-size:28px;font-weight:700}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.stat.warn .stat-value{color:var(--yellow)}
.stat.danger .stat-value{color:var(--red)}

.grid{display:grid;grid-template-columns:1fr 300px;gap:16px;margin-bottom:24px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}

.panel{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.panel-title{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.badge{padding:4px 10px;border-radius:100px;font-size:11px;font-weight:600}
.badge-low{background:rgba(0,210,106,.15);color:var(--green)}
.badge-medium{background:rgba(255,193,7,.15);color:var(--yellow)}
.badge-high,.badge-critical{background:rgba(255,71,87,.15);color:var(--red)}
.summary{font-size:15px;margin-bottom:16px;padding:12px;background:var(--bg);border-radius:8px}
.ports{display:flex;flex-wrap:wrap;gap:6px}
.port{background:var(--bg);padding:4px 10px;border-radius:4px;font-size:12px;font-family:monospace}

#map{height:180px;background:var(--bg);border-radius:8px;position:relative;overflow:hidden}
#mapCanvas{width:100%;height:100%}

.apps{display:flex;flex-direction:column;gap:8px}
.app{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;display:flex;align-items:center;gap:12px;transition:all .2s}
.app:hover{border-color:var(--muted)}
.app.high-risk{border-color:var(--red)}
.app.new{animation:slideIn .3s}
@keyframes slideIn{from{opacity:0;transform:translateY(-8px)}}
.app-info{flex:1;min-width:0}
.app-name{font-size:14px;font-weight:500}
.app-meta{font-size:12px;color:var(--muted)}
.app-dests{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.dest{background:var(--bg);padding:2px 8px;border-radius:4px;font-size:11px;font-family:monospace;color:var(--muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.risk-score{min-width:40px;text-align:center;padding:6px 10px;border-radius:6px;font-size:12px;font-weight:600}
.risk-0{background:rgba(0,210,106,.15);color:var(--green)}
.risk-30{background:rgba(255,193,7,.15);color:var(--yellow)}
.risk-60{background:rgba(255,71,87,.15);color:var(--red)}
.risk-80{background:var(--red);color:#fff}
.actions{display:flex;gap:4px}
.actions button{background:var(--bg);border:1px solid var(--border);color:var(--muted);padding:4px 8px;border-radius:4px;font-size:11px;cursor:pointer}
.actions button:hover{color:var(--text);border-color:var(--muted)}

.toast{position:fixed;bottom:20px;right:20px;background:var(--card);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:8px;padding:12px 16px;max-width:320px;opacity:0;transform:translateY(10px);transition:all .2s;z-index:100}
.toast.show{opacity:1;transform:translateY(0)}
.toast.danger{border-left-color:var(--red)}
.toast-title{font-weight:600;font-size:13px}
.toast-body{font-size:12px;color:var(--muted)}

.empty{text-align:center;padding:40px;color:var(--muted)}
.kbd{background:var(--bg);padding:2px 6px;border-radius:4px;font-size:11px;font-family:monospace;border:1px solid var(--border)}

.shortcuts{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;justify-content:center;z-index:200}
.shortcuts.show{display:flex}
.shortcuts-content{background:var(--card);border-radius:12px;padding:24px;max-width:300px;width:90%}
.shortcuts h3{margin-bottom:16px}
.shortcut{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">Network Watcher<span>eBPF Security</span></div>
    <div class="status"><span class="dot" id="dot"></span><span id="statusTxt">Connecting</span></div>
    <div class="header-actions">
      <button class="btn" onclick="toggleTheme()" title="Toggle theme">Theme</button>
      <button class="btn" onclick="showShortcuts()" title="Keyboard shortcuts">?</button>
      <button class="btn" onclick="exportJSON()">Export</button>
    </div>
  </div>

  <div class="input-row">
    <input type="text" id="urlInput" placeholder="Enter URL to test (google.com, github.com...)" onkeydown="if(event.key==='Enter')fetchURL('unknown')">
    <button class="btn" onclick="fetchURL('known')">Safe</button>
    <button class="btn btn-primary" onclick="fetchURL('unknown')">Test</button>
  </div>
  <div class="hint">Safe = curl (known) | Test = triggers alert (unknown app)</div>

  <div class="stats">
    <div class="stat"><div class="stat-value" id="sApps">0</div><div class="stat-label">Apps</div></div>
    <div class="stat"><div class="stat-value" id="sConns">0</div><div class="stat-label">Connections</div></div>
    <div class="stat"><div class="stat-value" id="sCpm">0</div><div class="stat-label">/minute</div></div>
    <div class="stat warn"><div class="stat-value" id="sUnknown">0</div><div class="stat-label">Unknown</div></div>
    <div class="stat danger"><div class="stat-value" id="sThreats">0</div><div class="stat-label">Threats</div></div>
    <div class="stat"><div class="stat-value" id="sRisk">0</div><div class="stat-label">Risk</div></div>
  </div>

  <div class="grid">
    <div>
      <div class="panel">
        <div class="panel-title">AI Analysis <span class="badge badge-low" id="level">LOW</span></div>
        <div class="summary" id="summary">Initializing...</div>
        <div id="portsWrap" style="display:none"><div style="font-size:11px;color:var(--muted);margin-bottom:6px">TOP PORTS</div><div class="ports" id="ports"></div></div>
      </div>
    </div>
    <div>
      <div class="panel">
        <div class="panel-title">Connection Map</div>
        <div id="map"><canvas id="mapCanvas"></canvas></div>
      </div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">Active Applications</div>
    <div class="apps" id="appList">
      <div class="empty">Waiting for connections...<br>Enter a URL above to test</div>
    </div>
  </div>
</div>

<div class="toast" id="toast">
  <div class="toast-title" id="toastTitle"></div>
  <div class="toast-body" id="toastBody"></div>
</div>

<div class="shortcuts" id="shortcuts" onclick="hideShortcuts()">
  <div class="shortcuts-content" onclick="event.stopPropagation()">
    <h3>Keyboard Shortcuts</h3>
    <div class="shortcut"><span>Focus URL input</span><span class="kbd">F</span></div>
    <div class="shortcut"><span>Refresh data</span><span class="kbd">R</span></div>
    <div class="shortcut"><span>Export JSON</span><span class="kbd">E</span></div>
    <div class="shortcut"><span>Toggle theme</span><span class="kbd">T</span></div>
    <div class="shortcut"><span>Show shortcuts</span><span class="kbd">?</span></div>
    <button class="btn" style="margin-top:16px;width:100%" onclick="hideShortcuts()">Close</button>
  </div>
</div>

<script>
let ws,apps=[],analysis={},locations=[],stats={};

// Theme
function toggleTheme(){
  const t=document.documentElement.dataset.theme==='light'?'':'light';
  document.documentElement.dataset.theme=t;
  localStorage.setItem('theme',t);
}
if(localStorage.getItem('theme')==='light')document.documentElement.dataset.theme='light';

// Shortcuts
function showShortcuts(){document.getElementById('shortcuts').classList.add('show')}
function hideShortcuts(){document.getElementById('shortcuts').classList.remove('show')}
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT')return;
  if(e.key==='f')document.getElementById('urlInput').focus();
  if(e.key==='r')location.reload();
  if(e.key==='e')exportJSON();
  if(e.key==='t')toggleTheme();
  if(e.key==='?')showShortcuts();
  if(e.key==='Escape')hideShortcuts();
});

// Map
const mapPoints=[];
function drawMap(){
  const canvas=document.getElementById('mapCanvas');
  const ctx=canvas.getContext('2d');
  const rect=canvas.getBoundingClientRect();
  canvas.width=rect.width*2;canvas.height=rect.height*2;
  ctx.scale(2,2);
  ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--bg');
  ctx.fillRect(0,0,rect.width,rect.height);
  
  // Draw points
  locations.forEach(loc=>{
    const x=((loc.lon+180)/360)*rect.width;
    const y=((90-loc.lat)/180)*rect.height;
    ctx.beginPath();
    ctx.arc(x,y,4,0,Math.PI*2);
    ctx.fillStyle='rgba(92,124,250,.8)';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x,y,8,0,Math.PI*2);
    ctx.fillStyle='rgba(92,124,250,.2)';
    ctx.fill();
  });
}

// WebSocket
function connect(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  ws=new WebSocket(proto+'//'+location.host+'/ws');
  ws.onopen=()=>{document.getElementById('dot').style.background='var(--green)';document.getElementById('statusTxt').textContent='Live'};
  ws.onclose=()=>{document.getElementById('dot').style.background='var(--red)';document.getElementById('statusTxt').textContent='Reconnecting';setTimeout(connect,2000)};
  ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.type==='init'){apps=m.data.apps||[];analysis=m.data.analysis||{};locations=m.data.locations||[];stats=m.data.stats||{};render()}else if(m.type==='event'){handleEvent(m.data)}};
}

function handleEvent(e){
  showToast(e);
  if(e.geo&&e.geo.lat){locations.push({lat:e.geo.lat,lon:e.geo.lon,country:e.geo.country})}
  const idx=apps.findIndex(a=>a.process_name===e.name);
  const dest=e.hostname?e.hostname+' ('+e.ip+'):'+e.port:e.ip+':'+e.port;
  if(idx>=0){apps[idx].connections++;apps[idx].risk=Math.max(apps[idx].risk||0,e.risk);if(!apps[idx].destinations.includes(dest))apps[idx].destinations.unshift(dest)}
  else{apps.unshift({process_name:e.name,connections:1,destinations:[dest],is_known_app:e.known,risk:e.risk,isNew:true})}
  apps.sort((a,b)=>(b.risk||0)-(a.risk||0));
  if(!e.known){analysis.unknown=(analysis.unknown||0)+1}
  analysis.total=(analysis.total||0)+1;
  render();
}

function showToast(e){
  const t=document.getElementById('toast');
  document.getElementById('toastTitle').textContent=e.name+(e.risk>=60?' [RISK:'+e.risk+']':'');
  const loc=e.geo?e.geo.country+' ':'';
  document.getElementById('toastBody').textContent=loc+(e.hostname||e.ip)+':'+e.port;
  t.classList.toggle('danger',e.risk>=60);
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'),3000);
}

function fetchURL(mode){
  const url=document.getElementById('urlInput').value.trim();
  if(!url)return;
  fetch('/api/fetch?url='+encodeURIComponent(url)+'&mode='+mode);
  document.getElementById('urlInput').value='';
}

function whitelist(app){
  fetch('/api/whitelist?app='+encodeURIComponent(app));
  apps=apps.map(a=>{if(a.process_name===app){a.is_known_app=true;a.risk=0}return a});
  render();
}

function exportJSON(){window.open('/api/export/json','_blank')}

function riskClass(r){
  if(r>=80)return'risk-80';
  if(r>=60)return'risk-60';
  if(r>=30)return'risk-30';
  return'risk-0';
}

function render(){
  const total=apps.reduce((s,a)=>s+(a.connections||0),0);
  const unk=apps.filter(a=>!a.is_known_app).length;
  const threats=(analysis.threats||[]).length;
  const avgRisk=apps.length?Math.round(apps.reduce((s,a)=>s+(a.risk||0),0)/apps.length):0;

  document.getElementById('sApps').textContent=apps.length;
  document.getElementById('sConns').textContent=total;
  document.getElementById('sCpm').textContent=stats.connections_per_min||0;
  document.getElementById('sUnknown').textContent=unk;
  document.getElementById('sThreats').textContent=threats;
  document.getElementById('sRisk').textContent=avgRisk;

  document.getElementById('summary').textContent=analysis.summary||'Analyzing...';
  const lvl=analysis.level||'low';
  const badge=document.getElementById('level');
  badge.className='badge badge-'+lvl;
  badge.textContent=lvl.toUpperCase();

  const pw=document.getElementById('portsWrap'),pc=document.getElementById('ports');
  if(analysis.ports&&analysis.ports.length){pw.style.display='block';pc.innerHTML=analysis.ports.map(p=>'<span class="port">:'+p.port+' '+p.service+'</span>').join('')}
  else{pw.style.display='none'}

  const al=document.getElementById('appList');
  if(!apps.length){al.innerHTML='<div class="empty">Waiting for connections...<br>Enter a URL above to test</div>';drawMap();return}
  al.innerHTML=apps.slice(0,20).map(a=>{
    const n=a.isNew;a.isNew=false;
    const r=a.risk||0;
    return '<div class="app'+(r>=60?' high-risk':'')+(n?' new':'')+'"><div class="app-info"><div class="app-name">'+a.process_name+'</div><div class="app-meta">'+a.connections+' conn'+(a.connections!==1?'s':'')+'</div><div class="app-dests">'+a.destinations.slice(0,2).map(d=>'<span class="dest" title="'+d+'">'+d+'</span>').join('')+(a.destinations.length>2?'<span class="dest">+'+(a.destinations.length-2)+'</span>':'')+'</div></div><div class="actions">'+(a.is_known_app?'':'<button onclick="whitelist(\''+a.process_name+'\')">Whitelist</button>')+'</div><div class="risk-score '+riskClass(r)+'">'+r+'</div></div>'
  }).join('');
  drawMap();
}

connect();
setInterval(()=>fetch('/api/data').then(r=>r.json()).then(d=>{stats=d.stats||{};document.getElementById('sCpm').textContent=stats.connections_per_min||0}),10000);
</script>
</body>
</html>`
