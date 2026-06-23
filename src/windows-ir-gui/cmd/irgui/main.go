package main

import (
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	webview "github.com/webview/webview_go"
)

//go:embed all:embedded/dist
var embeddedWeb embed.FS

func main() {
	initStartupLog()
	defer recoverStartupPanic()
	logStartupMilestone("process-start")

	var addr string
	var staticFlag string
	var browser bool
	var noWindow bool
	var debugWindow bool
	var forceWebView bool
	flag.StringVar(&addr, "addr", "127.0.0.1:8765", "listen address")
	flag.StringVar(&staticFlag, "static-dir", "", "React build directory; default auto-detects web/dist")
	flag.BoolVar(&browser, "browser", false, "open external browser instead of desktop client window")
	flag.BoolVar(&noWindow, "no-window", false, "start backend only without opening a desktop client window")
	flag.BoolVar(&debugWindow, "debug-window", false, "enable WebView developer tools")
	flag.BoolVar(&forceWebView, "webview", false, "force built-in WebView window even on Windows Server")
	flag.Parse()

	if runtime.GOOS != "windows" {
		log.Println("warning: this GUI collector is intended for Windows; Linux collection is provided by linux-ir/ir_linux_collect.sh")
	}

	staticDir := resolveStaticDir(staticFlag)
	mgr := newManager()
	mux := http.NewServeMux()
	registerAPI(mux, mgr)
	registerStatic(mux, staticDir)

	listener, err := net.Listen("tcp", addr)
	if err != nil && addr == "127.0.0.1:8765" {
		log.Printf("default port %s is busy, falling back to an available localhost port: %v", addr, err)
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		startupFatal("\u542f\u52a8\u5931\u8d25", "\u76d1\u542c\u672c\u673a\u7aef\u53e3\u5931\u8d25\uff1a"+err.Error()+"\n\n\u8bf7\u68c0\u67e5\u662f\u5426\u5df2\u6709\u7a0b\u5e8f\u5360\u7528\u7aef\u53e3\uff0c\u6216\u91cd\u65b0\u53cc\u51fb\u542f\u52a8\u3002")
	}
	addr = listener.Addr().String()
	url := "http://" + addr + "/"
	server := &http.Server{Handler: withCORS(mux)}
	go func() {
		log.Printf("IR GUI backend listening on %s", url)
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("backend server stopped: %v", err)
		}
	}()
	time.Sleep(450 * time.Millisecond)
	logStartupMilestone("backend-ready " + url)

	switch {
	case noWindow:
		logStartupMilestone("no-window-mode")
		select {}
	case browser:
		logStartupMilestone("browser-mode-explicit")
		fallbackToBrowser(url, errors.New("browser mode requested"))
	case runtime.GOOS == "windows" && isWindowsServer() && !forceWebView:
		logStartupMilestone("windows-server-browser-compat")
		fallbackToBrowser(url, errors.New("Windows Server detected: "+windowsProductName()))
	default:
		logStartupMilestone("webview-open-start")
		if err := openDesktopWindow(url, debugWindow); err != nil {
			log.Printf("desktop window unavailable, fallback to browser: %v", err)
			fallbackToBrowser(url, err)
		}
	}
}

func openDesktopWindow(url string, debug bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("WebView2 window creation failed: " + anyToString(r))
		}
	}()
	if runtime.GOOS == "windows" && !hasWebView2Runtime() {
		return errors.New("Microsoft Edge WebView2 Runtime not detected")
	}
	w := webview.New(debug)
	if w == nil {
		return errors.New("WebView2 returned nil window")
	}
	defer w.Destroy()
	w.SetTitle("\u8424\u706b\u5e94\u6025\u54cd\u5e94\u5de5\u5177")
	setAppWindowIcon(w.Window())
	w.SetSize(1280, 800, webview.HintNone)
	w.Navigate(url)
	w.Dispatch(func() {
		setAppWindowIcon(w.Window())
	})
	go func() {
		time.Sleep(1200 * time.Millisecond)
		w.Dispatch(func() {
			setAppWindowIcon(w.Window())
		})
	}()
	logStartupMilestone("webview-run")
	w.Run()
	logStartupMilestone("webview-closed")
	return nil
}

func registerAPI(mux *http.ServeMux, mgr *scanManager) {
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"version":  appVersion,
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
			"hostname": mustHostname(),
			"time":     time.Now().Format(time.RFC3339),
			"skills": []map[string]any{
				{"name": "emergency-response", "installed": pathExists(filepath.Join(userHome(), ".codex", "skills", "emergency-response", "SKILL.md")), "path": filepath.Join(userHome(), ".codex", "skills", "emergency-response")},
				{"name": "corporate-emergency-response-guidance-skill", "installed": pathExists(filepath.Join(userHome(), ".codex", "skills", "corporate-emergency-response-guidance-skill", "SKILL.md")), "path": filepath.Join(userHome(), ".codex", "skills", "corporate-emergency-response-guidance-skill")},
			},
			"profiles": []map[string]string{
				{"id": "combined", "name": "双 Skill 综合排查", "desc": "应急响应方法论 + 企业工程化闭环"},
				{"id": "emergency-response", "name": "基础主机入侵排查", "desc": "账户、进程、网络、持久化、文件、日志"},
				{"id": "corporate", "name": "企业证据链与日志优先", "desc": "VBR、WAL 思路、关键日志、横向定损"},
			},
		})
	})
	registerProcessAPI(mux)
	registerInventoryAPI(mux)
	registerFilesAPI(mux)
	registerToolboxAPI(mux)
	registerAIAuditAPI(mux)
	registerOpenPathAPI(mux)

	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var opt ScanOptions
		if err := json.NewDecoder(r.Body).Decode(&opt); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeOptions(&opt)
		id := newID()
		outDir, err := prepareOutputDir(opt.OutputDir, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tasks := windowsTasks(opt)
		s := &Scan{ID: id, Status: "running", Options: opt, StartedAt: time.Now(), OutputDir: outDir, Tasks: tasks}
		mgr.add(s)
		go runScan(mgr, s.ID)
		writeJSON(w, s)
	})

	mux.HandleFunc("/api/scans/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/api/scans/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		s, ok := mgr.get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(parts) > 1 {
			switch parts[1] {
			case "report":
				if s.ReportPath == "" {
					http.Error(w, "report not ready", http.StatusAccepted)
					return
				}
				http.ServeFile(w, r, s.ReportPath)
				return
			case "open-report":
				if s.ReportPath == "" {
					http.Error(w, "report not ready", http.StatusAccepted)
					return
				}
				_ = openURL("file:///" + filepath.ToSlash(s.ReportPath))
				writeJSON(w, map[string]any{"ok": true, "reportPath": s.ReportPath})
				return
			case "raw":
				if len(parts) < 3 {
					http.NotFound(w, r)
					return
				}
				taskID := sanitizeID(parts[2])
				file := filepath.Join(s.OutputDir, "raw", taskID+".txt")
				http.ServeFile(w, r, file)
				return
			}
		}
		writeJSON(w, scanPublic(s))
	})
}

func registerStatic(mux *http.ServeMux, staticDir string) {
	var diskServer http.Handler
	if staticDir != "" && pathExists(staticDir) {
		diskServer = http.FileServer(http.Dir(staticDir))
	}
	embeddedDist, hasEmbedded := embeddedStaticFS()
	var embeddedServer http.Handler
	var embeddedIndex []byte
	if hasEmbedded {
		embeddedServer = http.FileServer(http.FS(embeddedDist))
		embeddedIndex, _ = fs.ReadFile(embeddedDist, "index.html")
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "api endpoint not found",
				"path":  r.URL.Path,
			})
			return
		}
		isHTML := r.URL.Path == "/" || strings.HasSuffix(strings.ToLower(r.URL.Path), ".html")
		if isHTML {
			w.Header().Set("Cache-Control", "no-store, must-revalidate")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}

		if diskServer != nil {
			diskPath := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
			if isHTML || !pathExists(diskPath) {
				http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
				return
			}
			diskServer.ServeHTTP(w, r)
			return
		}

		if hasEmbedded {
			cleanURLPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
			if cleanURLPath == "." || cleanURLPath == "" {
				cleanURLPath = "index.html"
			}
			if isHTML || !embeddedPathExists(embeddedDist, cleanURLPath) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(embeddedIndex)
				return
			}
			embeddedServer.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>萤火应急响应工具</title><style>body{font-family:Segoe UI,Microsoft YaHei,Arial,sans-serif;margin:40px;background:#f8fafc;color:#0f172a}.card{max-width:760px;background:#fff;border:1px solid #e2e8f0;border-radius:18px;padding:24px;box-shadow:0 10px 30px #0001}</style><div class="card"><h1>萤火应急响应工具后端已启动</h1><p>未找到内嵌或外部前端资源，请重新构建 exe。</p><p>API 状态：<a href="/api/status">/api/status</a></p></div>`))
	})
}

func embeddedStaticFS() (fs.FS, bool) {
	sub, err := fs.Sub(embeddedWeb, "embedded/dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}

func embeddedPathExists(fsys fs.FS, name string) bool {
	if fsys == nil || name == "" {
		return false
	}
	_, err := fs.Stat(fsys, name)
	return err == nil
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeOptions(opt *ScanOptions) {
	if opt.Profile == "" {
		opt.Profile = "combined"
	}
	if opt.LookbackDays < 0 {
		opt.LookbackDays = 0
	}
	if opt.LookbackDays > 3650 {
		opt.LookbackDays = 3650
	}
	if opt.MaxEvents <= 0 || opt.MaxEvents > 5000 {
		opt.MaxEvents = 800
	}
	if opt.TimeoutSec <= 0 || opt.TimeoutSec > 600 {
		opt.TimeoutSec = 180
	}
}

func prepareOutputDir(base, id string) (string, error) {
	if strings.TrimSpace(base) == "" {
		base = filepath.Join(os.TempDir(), "IRToolLite", "runs")
	}
	clean := filepath.Clean(base)
	if !filepath.IsAbs(clean) {
		cwd, _ := os.Getwd()
		clean = filepath.Join(cwd, clean)
	}
	cleanupOldRunDirs(clean, 3)
	dir := filepath.Join(clean, time.Now().Format("20060102-150405")+"-"+id)
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func cleanupOldRunDirs(base string, keep int) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	type runDir struct {
		path string
		mod  time.Time
	}
	dirs := []runDir{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		dirs = append(dirs, runDir{path: filepath.Join(base, entry.Name()), mod: info.ModTime()})
	}
	if len(dirs) <= keep {
		return
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod.After(dirs[j].mod) })
	for _, dir := range dirs[keep:] {
		_ = os.RemoveAll(dir.path)
	}
}

func scanPublic(s *Scan) *Scan {
	cp := *s
	cp.Results = make([]TaskResult, len(s.Results))
	for i, r := range s.Results {
		r.Stdout = ""
		r.Stderr = ""
		cp.Results[i] = r
	}
	return &cp
}
