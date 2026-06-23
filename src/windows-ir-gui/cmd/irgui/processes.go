package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

type processListResult struct {
	items  []ProcessInfo
	err    error
	source string
}

func registerProcessAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/processes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		processes, err := listProcesses()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"items":     processes,
			"timestamp": time.Now().Format(time.RFC3339),
			"count":     len(processes),
		})
	})

	mux.HandleFunc("/api/processes/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/processes/"), "/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || parts[1] != "terminate" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil || pid <= 0 {
			http.Error(w, "invalid pid", http.StatusBadRequest)
			return
		}
		var req KillProcessRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		result := terminateProcess(pid, req)
		if !result.OK {
			w.WriteHeader(http.StatusBadRequest)
		}
		writeJSON(w, result)
	})
}

func listProcesses() ([]ProcessInfo, error) {
	fastCtx, fastCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fastCancel()
	richCtx, richCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer richCancel()

	fastCh := make(chan processListResult, 1)
	richCh := make(chan processListResult, 1)
	go func() {
		items, err := runProcessListScript(fastCtx, processFastScript())
		fastCh <- processListResult{items: items, err: err, source: "fast"}
	}()
	go func() {
		items, err := runProcessListScript(richCtx, processRichScript())
		richCh <- processListResult{items: items, err: err, source: "rich"}
	}()

	var fast processListResult
	select {
	case fast = <-fastCh:
	case <-time.After(5500 * time.Millisecond):
		fast = processListResult{err: fmt.Errorf("fast process enumeration timed out"), source: "fast"}
	}

	if fast.err == nil && len(fast.items) > 0 {
		select {
		case rich := <-richCh:
			if rich.err == nil && len(rich.items) > 0 {
				return finalizeProcesses(mergeProcessLists(fast.items, rich.items)), nil
			}
		case <-time.After(1200 * time.Millisecond):
			richCancel()
		}
		return finalizeProcesses(fast.items), nil
	}

	select {
	case rich := <-richCh:
		if rich.err == nil && len(rich.items) > 0 {
			return finalizeProcesses(rich.items), nil
		}
	case <-time.After(8500 * time.Millisecond):
		richCancel()
	}

	if fallback, err := listProcessesByTasklist(); err == nil && len(fallback) > 0 {
		return finalizeProcesses(fallback), nil
	}
	if fast.err != nil {
		return nil, fast.err
	}
	return nil, fmt.Errorf("process enumeration returned no data")
}

func runProcessListScript(ctx context.Context, script string) ([]ProcessInfo, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("process enumeration timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("process enumeration failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var items []ProcessInfo
	if err := json.Unmarshal(out, &items); err != nil {
		var single ProcessInfo
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("parse process json failed: %v", err)
		}
		items = []ProcessInfo{single}
	}
	return items, nil
}

func finalizeProcesses(items []ProcessInfo) []ProcessInfo {
	for i := range items {
		classifyProcess(&items[i])
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := severityRank(items[i].Risk), severityRank(items[j].Risk)
		if ri != rj {
			return ri > rj
		}
		if items[i].MemoryMB != items[j].MemoryMB {
			return items[i].MemoryMB > items[j].MemoryMB
		}
		return items[i].PID < items[j].PID
	})
	return items
}

func mergeProcessLists(fast, rich []ProcessInfo) []ProcessInfo {
	merged := make(map[int]ProcessInfo, len(fast)+len(rich))
	for _, p := range fast {
		if p.PID > 0 {
			merged[p.PID] = p
		}
	}
	for _, r := range rich {
		if r.PID <= 0 {
			continue
		}
		p := merged[r.PID]
		if p.PID == 0 {
			merged[r.PID] = r
			continue
		}
		if r.PPID != 0 {
			p.PPID = r.PPID
		}
		p.Name = firstNonEmpty(r.Name, p.Name)
		p.Path = firstNonEmpty(r.Path, p.Path)
		p.CommandLine = firstNonEmpty(r.CommandLine, p.CommandLine)
		p.CreationDate = firstNonEmpty(r.CreationDate, p.CreationDate)
		if p.CPU == 0 {
			p.CPU = r.CPU
		}
		if p.MemoryMB == 0 {
			p.MemoryMB = r.MemoryMB
		}
		merged[r.PID] = p
	}
	out := make([]ProcessInfo, 0, len(merged))
	for _, p := range merged {
		out = append(out, p)
	}
	return out
}

func processFastScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$items=@(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
  $name=[string]$_.ProcessName
  if($name -and $name -notmatch '\.exe$'){ $name=$name + '.exe' }
  $path=''; try { $path=[string]$_.Path } catch {}
  $start=''; try { if($_.StartTime){ $start=$_.StartTime.ToString('o') } } catch {}
  $cpu=0; try { if($_.CPU){ $cpu=[double]([math]::Round($_.CPU,2)) } } catch {}
  $mem=0; try { $mem=[double]([math]::Round($_.WorkingSet64/1MB,1)) } catch {}
  [PSCustomObject]@{
    pid=[int]$_.Id
    ppid=0
    name=$name
    path=$path
    commandLine=''
    creationDate=$start
    cpu=$cpu
    memoryMB=$mem
  }
})
@($items) | ConvertTo-Json -Depth 4 -Compress`
}

func processRichScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$gpMap=@{}
try {
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $name=[string]$_.ProcessName
    if($name -and $name -notmatch '\.exe$'){ $name=$name + '.exe' }
    $path=''; try { $path=[string]$_.Path } catch {}
    $start=''; try { if($_.StartTime){ $start=$_.StartTime.ToString('o') } } catch {}
    $cpu=0; try { if($_.CPU){ $cpu=[double]([math]::Round($_.CPU,2)) } } catch {}
    $mem=0; try { $mem=[double]([math]::Round($_.WorkingSet64/1MB,1)) } catch {}
    $gpMap[[int]$_.Id]=[PSCustomObject]@{name=$name; path=$path; creationDate=$start; cpu=$cpu; memoryMB=$mem}
  }
} catch {}
$items=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  $procId=[int]$_.ProcessId
  $gp=$gpMap[$procId]
  $name=[string]$_.Name
  $path=[string]$_.ExecutablePath
  $start=''
  if($_.CreationDate){ $start=$_.CreationDate.ToString('o') }
  $cpu=0; $mem=0
  if($gp){
    if(-not $name){ $name=[string]$gp.name }
    if(-not $path){ $path=[string]$gp.path }
    if(-not $start){ $start=[string]$gp.creationDate }
    $cpu=[double]$gp.cpu
    $mem=[double]$gp.memoryMB
  }
  [PSCustomObject]@{
    pid=$procId
    ppid=[int]$_.ParentProcessId
    name=$name
    path=$path
    commandLine=[string]$_.CommandLine
    creationDate=$start
    cpu=$cpu
    memoryMB=$mem
  }
})
@($items) | ConvertTo-Json -Depth 4 -Compress`
}

func listProcessesByTasklist() ([]ProcessInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/nh")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("tasklist timed out")
	}
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(strings.NewReader(string(out)))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	items := make([]ProcessInfo, 0, len(records))
	for _, rec := range records {
		if len(rec) < 5 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(rec[1]))
		if pid <= 0 {
			continue
		}
		memText := strings.NewReplacer(",", "", "K", "", "k", "", " ", "").Replace(rec[4])
		memKB, _ := strconv.ParseFloat(memText, 64)
		items = append(items, ProcessInfo{
			PID:      pid,
			Name:     strings.TrimSpace(rec[0]),
			MemoryMB: memKB / 1024,
		})
	}
	return items, nil
}

func classifyProcess(p *ProcessInfo) {
	lowerName := strings.ToLower(p.Name)
	lowerPath := strings.ToLower(p.Path)
	decodedCommand := decodePowerShellEncodedCommand(p.CommandLine)
	if decodedCommand != "" {
		p.DecodedCommand = compact(decodedCommand, 1800)
	}
	isKnownAutomation := isKnownAutomationPowerShell(decodedCommand)
	reasons := []string{}
	risk := "low"

	if isProtectedProcess(p.PID, lowerName) {
		p.Protected = true
	}
	if isKnownAutomation {
		p.TrustHints = append(p.TrustHints, "PowerShell EncodedCommand 解码为本地自动化/命令安全层，需确认来源但不应直接定性为 C2")
		reasons = append(reasons, "EncodedCommand 解码内容匹配本地自动化/命令安全层特征")
	}
	if lowerPath == "" {
		reasons = append(reasons, "缺少可执行路径")
	}
	if regexp.MustCompile(`(?i)\\(temp|appdata\\local\\temp|users\\public|downloads)\\`).MatchString(p.Path) {
		reasons = append(reasons, "可执行文件位于临时目录/用户下载目录")
		risk = maxRisk(risk, "high")
	}
	if strings.Contains(lowerPath, `\programdata\`) && regexp.MustCompile(`(?i)\.(exe|dll|ps1|vbs|js|bat|cmd)$`).MatchString(lowerPath) {
		reasons = append(reasons, "ProgramData 下存在可执行或脚本路径")
		risk = maxRisk(risk, "medium")
	}
	if isSpoofedSystemProcess(lowerName, lowerPath) {
		reasons = append(reasons, "疑似系统进程名伪装但路径不在 System32/SysWOW64")
		risk = maxRisk(risk, "high")
	}
	if !isKnownAutomation && regexp.MustCompile(`(?i)(-enc|-encodedcommand|downloadstring|invoke-expression|\biex\b|frombase64string|/dev/tcp|reverse|meterpreter)`).MatchString(p.CommandLine) {
		reasons = append(reasons, "命令行包含编码执行/下载执行/反连特征")
		risk = maxRisk(risk, "high")
	}
	if regexp.MustCompile(`(?i)\b(mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|wmic)\b.*(http|https|temp|appdata|users\\public)`).MatchString(p.CommandLine) {
		reasons = append(reasons, "命令行包含 LOLBin 可疑调用链")
		risk = maxRisk(risk, "high")
	}
	if p.CPU >= 60 {
		reasons = append(reasons, "CPU 占用异常偏高")
		risk = maxRisk(risk, "medium")
	}
	if p.MemoryMB >= 2048 {
		reasons = append(reasons, "内存占用异常偏高")
		risk = maxRisk(risk, "medium")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "未命中内置可疑规则")
	}
	p.Risk = risk
	if p.Protected {
		p.Risk = "info"
		reasons = append(reasons, "系统/工具保护进程")
	}
	p.Reasons = reasons
}

func decodePowerShellEncodedCommand(commandLine string) string {
	encoded := extractPowerShellEncodedCommand(commandLine)
	if encoded == "" {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return ""
	}
	if len(raw) >= 2 && raw[1] == 0 {
		u16 := make([]uint16, 0, len(raw)/2)
		for i := 0; i+1 < len(raw); i += 2 {
			u16 = append(u16, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
		return strings.TrimSpace(string(utf16.Decode(u16)))
	}
	return strings.TrimSpace(string(raw))
}

func extractPowerShellEncodedCommand(commandLine string) string {
	match := regexp.MustCompile(`(?i)(?:^|\s)(?:-|/)(?:encodedcommand|enc|ec|e)\s+([A-Za-z0-9+/=]+)`).FindStringSubmatch(commandLine)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func isKnownAutomationPowerShell(decoded string) bool {
	text := strings.ToLower(decoded)
	if text == "" {
		return false
	}
	knownTerms := []string{
		"rust command-safety layer",
		"long-lived powershell ast parser",
		"newline-delimited json requests over stdin",
		"invoke-parserequest",
		"write-response",
	}
	matches := 0
	for _, term := range knownTerms {
		if strings.Contains(text, term) {
			matches++
		}
	}
	return matches >= 2
}

func isProtectedProcess(pid int, lowerName string) bool {
	if pid <= 4 || pid == os.Getpid() {
		return true
	}
	protected := map[string]bool{
		"system": true, "registry": true, "smss.exe": true, "csrss.exe": true,
		"wininit.exe": true, "winlogon.exe": true, "services.exe": true,
		"lsass.exe": true, "fontdrvhost.exe": true, "dwm.exe": true,
	}
	return protected[lowerName]
}

func isSpoofedSystemProcess(lowerName, lowerPath string) bool {
	systemNames := map[string]bool{
		"svchost.exe": true, "lsass.exe": true, "services.exe": true, "winlogon.exe": true,
		"csrss.exe": true, "spoolsv.exe": true, "conhost.exe": true, "rundll32.exe": true,
	}
	if !systemNames[lowerName] || lowerPath == "" {
		return false
	}
	return !(strings.Contains(lowerPath, `\windows\system32\`) || strings.Contains(lowerPath, `\windows\syswow64\`))
}

func maxRisk(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func terminateProcess(pid int, req KillProcessRequest) ProcessActionResult {
	result := ProcessActionResult{PID: pid, Timestamp: time.Now().Format(time.RFC3339)}
	name := strings.ToLower(getProcessNameByPID(pid))
	if isProtectedProcess(pid, name) || pid == os.Getpid() {
		result.OK = false
		result.Error = "refusing to terminate protected process"
		return result
	}
	args := []string{"/PID", strconv.Itoa(pid)}
	if req.Tree {
		args = append(args, "/T")
	}
	if req.Force {
		args = append(args, "/F")
	}
	result.Command = "taskkill " + strings.Join(args, " ")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "taskkill", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	result.Output = strings.TrimSpace(out.String())
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "taskkill timed out"
		return result
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.OK = true
	return result
}

func getProcessNameByPID(pid int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := fmt.Sprintf(`$p=Get-CimInstance Win32_Process -Filter "ProcessId=%d" -ErrorAction SilentlyContinue; if($p){$p.Name}`, pid)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
