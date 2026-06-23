package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ToolboxItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Icon        string   `json:"icon"`
	IconData    string   `json:"iconData,omitempty"`
	Category    string   `json:"category"`
	Scenario    string   `json:"scenario"`
	Description string   `json:"description"`
	Path        string   `json:"path"`
	WorkDir     string   `json:"workDir"`
	ProcessName string   `json:"processName"`
	Exists      bool     `json:"exists"`
	Running     bool     `json:"running"`
	NeedAdmin   bool     `json:"needAdmin"`
	Tags        []string `json:"tags"`
	Advice      string   `json:"advice"`
	LaunchKind  string   `json:"openMode"`
	Relative    string   `json:"-"`
}

var toolboxIconCache sync.Map

type ToolLaunchResult struct {
	OK        bool   `json:"ok"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	PID       int    `json:"pid"`
	Message   string `json:"message"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

func registerToolboxAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/tools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items := toolboxItems()
		writeJSON(w, map[string]any{
			"items":     items,
			"count":     len(items),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/tools/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/tools/"), "/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || parts[1] != "launch" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		result := launchToolboxItem(parts[0])
		if !result.OK {
			w.WriteHeader(http.StatusBadRequest)
		}
		writeJSON(w, result)
	})
}

func toolboxItems() []ToolboxItem {
	running := runningProcessSet()
	defs := []ToolboxItem{
		{
			ID:          "huorong-sword",
			Name:        "火绒剑",
			Icon:        "火",
			Category:    "进程/驱动",
			Scenario:    "异常进程、驱动、启动项、网络连接深度排查",
			Description: "直接启动 SecAnalysis.exe，可查看进程树、模块、句柄、驱动、启动项和网络连接。若系统弹出 UAC，请选择允许。",
			Relative:    filepath.Join("应急工具", "火绒5.0独立版", "SecAnalysis.exe"),
			ProcessName: "SecAnalysis.exe",
			NeedAdmin:   true,
			Tags:        []string{"进程树", "驱动", "句柄", "网络连接", "启动项"},
			Advice:      "先记录 PID、路径和模块，再结合本工具的进程清除页处置。",
			LaunchKind:  "exe",
		},
		{
			ID:          "d-shield",
			Name:        "D盾",
			Icon:        "D",
			Category:    "Web/账号",
			Scenario:    "WebShell、隐藏账号、克隆账号、IIS 站点应急排查",
			Description: "直接启动 D_Safe_Manage.exe，可进行 WebShell 扫描、隐藏账号检测、克隆账号检测和站点安全快速检查。",
			Relative:    filepath.Join("应急工具", "d盾", "D_Safe_Manage.exe"),
			ProcessName: "D_Safe_Manage.exe",
			NeedAdmin:   true,
			Tags:        []string{"WebShell", "隐藏账号", "IIS", "克隆账号"},
			Advice:      "扫描前保留站点目录副本；命中 WebShell 后关联访问日志和文件时间线。",
			LaunchKind:  "exe",
		},
		{
			ID:          "arthas-memory",
			Name:        "Arthas 内存马查杀",
			Icon:        "A",
			Category:    "Java 内存马",
			Scenario:    "Java 进程、ClassLoader、Filter/Servlet 内存马排查",
			Description: "打开 Arthas 工具目录，按需运行 as.bat/arthas-boot.jar 后检查异常 Class、Filter、Servlet、Listener 和动态加载痕迹。",
			Relative:    filepath.Join("应急工具", "arthas-内存马查杀工具"),
			ProcessName: "java.exe",
			NeedAdmin:   false,
			Tags:        []string{"Java", "内存马", "ClassLoader", "Filter", "Servlet"},
			Advice:      "优先选择可疑 Java Web 进程，结合 Web 日志、JAR 修改时间和类加载信息判断。",
			LaunchKind:  "folder",
		},
		{
			ID:          "silverfox-killer",
			Name:        "银狐查杀",
			Icon:        "银",
			Category:    "专项查杀",
			Scenario:    "银狐木马、远控木马、异常落地文件专项排查",
			Description: "直接启动银狐查杀.exe，用于银狐木马及相关远控载荷的快速扫描、查杀与处置。",
			Relative:    filepath.Join("应急工具", "银狐查杀", "银狐查杀.exe"),
			ProcessName: "银狐查杀.exe",
			NeedAdmin:   true,
			Tags:        []string{"银狐木马", "专项查杀", "远控", "落地文件"},
			Advice:      "查杀前先保留本工具报告；命中后记录文件路径、哈希、启动项和关联外联 IP，再执行隔离或清除。",
			LaunchKind:  "exe",
		},
		{
			ID:          "everything-search",
			Name:        "Everything 文件搜索",
			Icon:        "E",
			Category:    "文件搜索",
			Scenario:    "快速搜索可疑样本、WebShell、脚本、压缩包、近期落地文件",
			Description: "直接启动 everything.exe，用于快速按文件名、后缀、路径关键字定位可疑文件和取证目标。",
			Relative:    filepath.Join("应急工具", "Everything", "everything.exe"),
			ProcessName: "everything.exe",
			NeedAdmin:   false,
			Tags:        []string{"文件搜索", "IOC 定位", "WebShell", "落地文件"},
			Advice:      "优先搜索 .php/.jsp/.aspx/.ps1/.vbs/.bat/.exe/.dll、异常文件名、攻击 IP/域名相关痕迹；命中后回到文件取证模块记录路径、时间和哈希。",
			LaunchKind:  "exe",
		},
	}
	for i := range defs {
		path := resolveToolPath(defs[i].Relative)
		defs[i].Path = path
		if defs[i].LaunchKind == "folder" {
			defs[i].WorkDir = path
		} else {
			defs[i].WorkDir = filepath.Dir(path)
		}
		defs[i].Exists = path != "" && pathExists(path)
		defs[i].Running = defs[i].ProcessName != "" && running[strings.ToLower(defs[i].ProcessName)]
		if defs[i].Exists && defs[i].LaunchKind == "exe" {
			defs[i].IconData = toolIconDataURI(path)
		}
	}
	return defs
}

func launchToolboxItem(id string) ToolLaunchResult {
	items := toolboxItems()
	for _, item := range items {
		if item.ID != id {
			continue
		}
		result := ToolLaunchResult{
			ID:        item.ID,
			Name:      item.Name,
			Path:      item.Path,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		if !item.Exists {
			result.Message = "工具文件不存在"
			result.Error = fmt.Sprintf("not found: %s", item.Relative)
			return result
		}
		pid, err := startToolProcess(item)
		if err != nil {
			result.Message = "工具启动失败"
			result.Error = err.Error()
			return result
		}
		result.OK = true
		result.PID = pid
		if item.LaunchKind == "folder" {
			result.Message = "已打开目录：" + item.Name
		} else {
			result.Message = "已启动 " + item.Name
		}
		return result
	}
	return ToolLaunchResult{ID: id, Message: "未知工具", Error: "tool not found", Timestamp: time.Now().Format(time.RFC3339)}
}

func startToolProcess(item ToolboxItem) (int, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("toolbox launch is only supported on Windows")
	}
	return shellExecuteOpenTarget(item.Path, item.WorkDir)
}

func resolveToolPath(relative string) string {
	roots := toolSearchRoots()
	relatives := []string{relative}
	toolPrefix := "应急工具" + string(filepath.Separator)
	cleanRelative := filepath.Clean(relative)
	if strings.HasPrefix(cleanRelative, toolPrefix) {
		relatives = append(relatives, strings.TrimPrefix(cleanRelative, toolPrefix))
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		for _, rel := range relatives {
			candidate := filepath.Join(root, rel)
			if pathExists(candidate) {
				abs, _ := filepath.Abs(candidate)
				return abs
			}
		}
	}
	if filepath.IsAbs(relative) && pathExists(relative) {
		return relative
	}
	return filepath.Join(firstNonEmpty(roots...), relative)
}

func toolSearchRoots() []string {
	seen := map[string]bool{}
	add := func(items *[]string, p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			p = abs
		}
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return
		}
		seen[key] = true
		*items = append(*items, p)
	}
	roots := []string{}
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	add(&roots, cwd)
	add(&roots, exeDir)
	add(&roots, filepath.Dir(cwd))
	add(&roots, filepath.Dir(exeDir))
	add(&roots, filepath.Dir(filepath.Dir(exeDir)))
	return roots
}

func runningProcessSet() map[string]bool {
	running := map[string]bool{}
	if runtime.GOOS != "windows" {
		return running
	}
	cmd := exec.Command("tasklist.exe", "/FO", "CSV", "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return running
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) == 0 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(fields[0]), `"`)
		if name != "" {
			running[strings.ToLower(name)] = true
		}
	}
	return running
}

func toolIconDataURI(path string) string {
	if runtime.GOOS != "windows" || strings.TrimSpace(path) == "" {
		return ""
	}
	key := strings.ToLower(filepath.Clean(path))
	if v, ok := toolboxIconCache.Load(key); ok {
		return v.(string)
	}
	data := extractAssociatedIconDataURI(path)
	toolboxIconCache.Store(key, data)
	return data
}

func extractAssociatedIconDataURI(path string) string {
	if strings.Contains(path, "\x00") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	encodedPath := base64.StdEncoding.EncodeToString([]byte(path))
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$p=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
$icon=[System.Drawing.Icon]::ExtractAssociatedIcon($p)
if($null -eq $icon){ exit 2 }
$bmp=$icon.ToBitmap()
$ms=[System.IO.MemoryStream]::new()
try {
  $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
  [Convert]::ToBase64String($ms.ToArray())
} finally {
  $ms.Dispose()
  $bmp.Dispose()
  $icon.Dispose()
}`, encodedPath)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil || ctx.Err() != nil {
		return ""
	}
	b64 := strings.TrimSpace(string(out))
	if b64 == "" {
		return ""
	}
	return "data:image/png;base64," + b64
}
