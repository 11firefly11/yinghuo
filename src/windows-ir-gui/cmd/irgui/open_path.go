package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type OpenPathRequest struct {
	Path string `json:"path"`
}

type OpenPathResponse struct {
	OK        bool   `json:"ok"`
	Path      string `json:"path"`
	Dir       string `json:"dir"`
	Message   string `json:"message"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

func registerOpenPathAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/open-path", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req OpenPathRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := openContainingDirectory(req.Path)
		if !resp.OK {
			w.WriteHeader(http.StatusBadRequest)
		}
		writeJSON(w, resp)
	})
}

func openContainingDirectory(raw string) OpenPathResponse {
	resp := OpenPathResponse{Timestamp: time.Now().Format(time.RFC3339)}
	if runtime.GOOS != "windows" {
		resp.Message = "open directory is supported on Windows only"
		resp.Error = "unsupported OS"
		return resp
	}

	target, dir, selectFile, err := resolveExplorerTarget(raw)
	resp.Path = target
	resp.Dir = dir
	if err != nil {
		resp.Message = err.Error()
		resp.Error = err.Error()
		return resp
	}

	if err := openDirectoryVisible(dir); err != nil {
		resp.Message = "failed to open directory"
		resp.Error = err.Error()
		return resp
	}

	resp.OK = true
	if selectFile != "" {
		resp.Message = fmt.Sprintf("opened containing directory: %s", dir)
	} else {
		resp.Message = fmt.Sprintf("opened directory: %s", dir)
	}
	return resp
}

func openDirectoryVisible(dir string) error {
	if _, err := shellExecuteOpenTarget(dir, ""); err == nil {
		return nil
	}
	candidates := []*exec.Cmd{
		exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", dir),
		exec.Command(explorerPath(), dir),
	}
	var lastErr error
	for _, cmd := range candidates {
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func shellExecuteOpenTarget(target, workDir string) (int, error) {
	if strings.TrimSpace(target) == "" {
		return 0, fmt.Errorf("empty target path")
	}
	operation, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return 0, err
	}
	file, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return 0, err
	}
	var dirPtr *uint16
	if strings.TrimSpace(workDir) != "" {
		dirPtr, err = syscall.UTF16PtrFromString(workDir)
		if err != nil {
			return 0, err
		}
	}
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteW")
	ret, _, callErr := proc.Call(
		0,
		uintptr(unsafe.Pointer(operation)),
		uintptr(unsafe.Pointer(file)),
		0,
		uintptr(unsafe.Pointer(dirPtr)),
		1,
	)
	if ret <= 32 {
		if callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, fmt.Errorf("ShellExecuteW failed with code %d", ret)
	}
	return 0, nil
}

func resolveExplorerTarget(raw string) (target string, dir string, selectFile string, err error) {
	for _, candidate := range openPathCandidates(raw) {
		candidate = cleanOpenPath(candidate)
		if candidate == "" {
			continue
		}
		if st, statErr := os.Stat(candidate); statErr == nil {
			if st.IsDir() {
				return candidate, candidate, "", nil
			}
			return candidate, filepath.Dir(candidate), candidate, nil
		}
		candidateDir := filepath.Dir(candidate)
		if candidateDir != "." && candidateDir != "" {
			if st, statErr := os.Stat(candidateDir); statErr == nil && st.IsDir() {
				return candidate, candidateDir, "", nil
			}
		}
	}
	return "", "", "", fmt.Errorf("cannot resolve existing directory from path: %s", strings.TrimSpace(raw))
}

func openPathCandidates(raw string) []string {
	normalized := normalizeOpenTarget(raw)
	exeFromRaw := extractExecutablePath(raw)
	exeFromNormalized := extractExecutablePath(normalized)
	pidPath := processPathFromPIDToken(raw)
	candidates := []string{pidPath, exeFromRaw, exeFromNormalized, normalized}

	fields := strings.Fields(strings.TrimSpace(raw))
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), ".exe") ||
			strings.Contains(strings.ToLower(f), ".dll") ||
			strings.Contains(strings.ToLower(f), ".ps1") ||
			strings.Contains(strings.ToLower(f), ".bat") ||
			strings.Contains(strings.ToLower(f), ".cmd") ||
			strings.Contains(strings.ToLower(f), ".vbs") ||
			strings.Contains(strings.ToLower(f), ".js") {
			candidates = append(candidates, f)
		}
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		c = cleanOpenPath(c)
		key := strings.ToLower(c)
		if c == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func processPathFromPIDToken(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if !strings.HasPrefix(s, "pid:") {
		return ""
	}
	pidText := strings.TrimSpace(strings.TrimPrefix(s, "pid:"))
	if pidText == "" {
		return ""
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	script := fmt.Sprintf(`$pidValue=%d; $p=Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue" -ErrorAction SilentlyContinue; if($p -and $p.ExecutablePath){$p.ExecutablePath; exit}; try{$gp=Get-Process -Id $pidValue -ErrorAction SilentlyContinue; if($gp -and $gp.Path){$gp.Path}}catch{}`, pid)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func normalizeOpenTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.Contains(s, "\x00") {
		return ""
	}
	if strings.ContainsAny(s, "\r\n") {
		s = strings.Fields(s)[0]
	}
	return cleanOpenPath(s)
}

func cleanOpenPath(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimPrefix(s, `\??\`)
	s = strings.TrimPrefix(s, `\\?\`)
	s = strings.TrimPrefix(s, `file:///`)
	s = strings.ReplaceAll(s, "/", `\`)
	s = os.ExpandEnv(s)
	if s == "" {
		return ""
	}
	return filepath.Clean(s)
}

func explorerPath() string {
	if windir := os.Getenv("WINDIR"); windir != "" {
		p := filepath.Join(windir, "explorer.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "explorer.exe"
}
