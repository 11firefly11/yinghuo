package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type scanManager struct {
	mu    sync.RWMutex
	scans map[string]*Scan
}

func newManager() *scanManager { return &scanManager{scans: map[string]*Scan{}} }

func (m *scanManager) add(s *Scan) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scans[s.ID] = s
}

func (m *scanManager) get(id string) (*Scan, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scans[id]
	return s, ok
}

func (m *scanManager) update(id string, fn func(*Scan)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.scans[id]; ok {
		fn(s)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONFile(path string, v any) error {
	b, _ := json.MarshalIndent(v, "", "  ")
	return os.WriteFile(path, b, 0644)
}

func mustHostname() string { h, _ := os.Hostname(); return h }
func userHome() string     { h, _ := os.UserHomeDir(); return h }
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func sanitizeID(s string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)
	out := re.ReplaceAllString(s, "_")
	if out == "" {
		return "task"
	}
	return out
}

func previewText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "\n...（预览截断，点完整日志查看全部）"
}

func compact(s string, n int) string {
	s = strings.TrimSpace(regexp.MustCompile(`[\t ]+`).ReplaceAllString(s, " "))
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "..."
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	case "pass":
		return 0
	}
	return 0
}

func onlyHeaders(s string) bool {
	lines, meaningful := 0, 0
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "===") {
			continue
		}
		lines++
		if strings.Contains(l, ":") && !strings.HasSuffix(l, ":") {
			meaningful++
		}
	}
	return lines < 4 || meaningful == 0
}

func findLine(s string, re *regexp.Regexp) string {
	for _, l := range strings.Split(s, "\n") {
		if re.MatchString(l) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

func findAround(s, needle string, width int) string {
	i := strings.Index(strings.ToLower(s), strings.ToLower(needle))
	if i < 0 {
		return ""
	}
	start := i - width/2
	if start < 0 {
		start = 0
	}
	end := i + width/2
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func findAroundRegex(s string, re *regexp.Regexp, width int) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return ""
	}
	start := loc[0] - width/2
	if start < 0 {
		start = 0
	}
	end := loc[1] + width/2
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func isExternalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return !(parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() ||
		parsed.IsMulticast() || parsed.IsUnspecified())
}

func isCommonDNSResolverIP(ip string) bool {
	normalized := strings.TrimSpace(strings.Trim(ip, "[]"))
	if normalized == "" {
		return false
	}
	_, ok := commonDNSResolvers[normalized]
	return ok
}

var commonDNSResolvers = map[string]string{
	"1.0.0.1":         "Cloudflare",
	"1.1.1.1":         "Cloudflare",
	"1.2.4.8":         "CNNIC",
	"8.8.4.4":         "Google Public DNS",
	"8.8.8.8":         "Google Public DNS",
	"9.9.9.9":         "Quad9",
	"64.6.64.6":       "Verisign Public DNS",
	"64.6.65.6":       "Verisign Public DNS",
	"77.88.8.8":       "Yandex DNS",
	"77.88.8.1":       "Yandex DNS",
	"80.80.80.80":     "Freenom World",
	"80.80.81.81":     "Freenom World",
	"101.226.4.6":     "DNSPai",
	"114.114.114.114": "114DNS",
	"114.114.115.115": "114DNS",
	"119.29.29.29":    "DNSPod Public DNS",
	"149.112.112.112": "Quad9",
	"180.76.76.76":    "Baidu DNS",
	"182.254.116.116": "DNSPod Public DNS",
	"202.96.113.94":   "China Telecom ISP DNS",
	"202.96.128.86":   "China Telecom ISP DNS",
	"202.96.128.166":  "China Telecom ISP DNS",
	"202.96.134.133":  "China Telecom ISP DNS",
	"208.67.220.220":  "OpenDNS",
	"208.67.222.222":  "OpenDNS",
	"210.2.4.8":       "CNNIC",
	"218.30.118.6":    "DNSPai",
	"223.5.5.5":       "AliDNS",
	"223.6.6.6":       "AliDNS",
}

func openURL(u string) error {
	browserAttempts := [][]string{
		{filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"), "--app=" + u},
		{filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe"), "--app=" + u},
		{filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Edge", "Application", "msedge.exe"), "--app=" + u},
		{filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"), "--app=" + u},
		{filepath.Join(os.Getenv("ProgramFiles(x86)"), "Google", "Chrome", "Application", "chrome.exe"), "--app=" + u},
		{filepath.Join(os.Getenv("LOCALAPPDATA"), "Google", "Chrome", "Application", "chrome.exe"), "--app=" + u},
	}
	var lastErr error
	for _, args := range browserAttempts {
		if args[0] == "" || !pathExists(args[0]) {
			continue
		}
		if err := exec.Command(args[0], args[1:]...).Start(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	attempts := [][]string{
		{"explorer.exe", u},
		{"rundll32.exe", "url.dll,FileProtocolHandler", u},
		{"cmd.exe", "/c", "start", "", u},
	}
	for _, args := range attempts {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func atoiDefault(s string, d int) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return i
}

func powershellUTF8Prefix() string {
	return `$ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $OutputEncoding=[System.Text.UTF8Encoding]::new($false); `
}

func resolveStaticDir(flagValue string) string {
	candidates := []string{}
	if flagValue != "" {
		candidates = append(candidates, flagValue)
	}
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	candidates = append(candidates,
		filepath.Join(cwd, "web", "dist"),
		filepath.Join(exeDir, "web", "dist"),
		filepath.Join(exeDir, "..", "web", "dist"),
		filepath.Join(cwd, "windows-ir-gui", "web", "dist"),
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	if len(candidates) > 0 {
		abs, _ := filepath.Abs(candidates[0])
		return abs
	}
	return ""
}
