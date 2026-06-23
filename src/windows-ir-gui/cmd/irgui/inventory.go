package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type AccountInfo struct {
	Name                  string   `json:"name"`
	Enabled               bool     `json:"enabled"`
	SID                   string   `json:"sid"`
	LastLogon             string   `json:"lastLogon"`
	PasswordLastSet       string   `json:"passwordLastSet"`
	Description           string   `json:"description"`
	PasswordRequired      bool     `json:"passwordRequired"`
	UserMayChangePassword bool     `json:"userMayChangePassword"`
	Admin                 bool     `json:"admin"`
	Hidden                bool     `json:"hidden"`
	Risk                  string   `json:"risk"`
	Reasons               []string `json:"reasons"`
}

type EventInfo struct {
	Time        string   `json:"time"`
	Log         string   `json:"log"`
	ID          int      `json:"id"`
	Provider    string   `json:"provider"`
	Level       string   `json:"level"`
	Message     string   `json:"message"`
	User        string   `json:"user"`
	IP          string   `json:"ip"`
	Port        string   `json:"port"`
	LogonType   string   `json:"logonType"`
	CommandLine string   `json:"commandLine,omitempty"`
	ServiceName string   `json:"serviceName,omitempty"`
	ImagePath   string   `json:"imagePath,omitempty"`
	Risk        string   `json:"risk"`
	Reasons     []string `json:"reasons"`
}

// RDPSessionInfo 描述一条实时 RDP/终端会话（来自 quser/qwinsta），非日志事件。
type RDPSessionInfo struct {
	UserName    string `json:"userName"`
	SessionName string `json:"sessionName"`
	ID          string `json:"id"`
	State       string `json:"state"`
	IdleTime    string `json:"idleTime"`
	LogonTime   string `json:"logonTime"`
}

type HotfixInfo struct {
	HotFixID    string `json:"hotFixId"`
	Description string `json:"description"`
	InstalledOn string `json:"installedOn"`
	InstalledBy string `json:"installedBy"`
}

type IPAddressInfo struct {
	InterfaceAlias string `json:"interfaceAlias"`
	IPAddress      string `json:"ipAddress"`
	PrefixLength   int    `json:"prefixLength"`
}

type HostInventory struct {
	Hostname           string          `json:"hostname"`
	CurrentUser        string          `json:"currentUser"`
	UserSID            string          `json:"userSid"`
	IsAdmin            bool            `json:"isAdmin"`
	WindowsProductName string          `json:"windowsProductName"`
	DisplayVersion     string          `json:"displayVersion"`
	WindowsVersion     string          `json:"windowsVersion"`
	BuildNumber        string          `json:"buildNumber"`
	UBR                string          `json:"ubr"`
	Architecture       string          `json:"architecture"`
	Domain             string          `json:"domain"`
	Manufacturer       string          `json:"manufacturer"`
	Model              string          `json:"model"`
	InstallDate        string          `json:"installDate"`
	LastBootTime       string          `json:"lastBootTime"`
	TimeZone           string          `json:"timeZone"`
	PowerShellVersion  string          `json:"powerShellVersion"`
	Hotfixes           []HotfixInfo    `json:"hotfixes"`
	IPAddresses        []IPAddressInfo `json:"ipAddresses"`
	Risk               string          `json:"risk"`
	Reasons            []string        `json:"reasons"`
	Timestamp          string          `json:"timestamp"`
}

type NetworkConnectionInfo struct {
	LocalAddress  string   `json:"localAddress"`
	LocalPort     int      `json:"localPort"`
	RemoteAddress string   `json:"remoteAddress"`
	RemotePort    int      `json:"remotePort"`
	State         string   `json:"state"`
	PID           int      `json:"pid"`
	Process       string   `json:"process"`
	Path          string   `json:"path"`
	CommandLine   string   `json:"commandLine"`
	External      bool     `json:"external"`
	Risk          string   `json:"risk"`
	Reasons       []string `json:"reasons"`
}

type NetworkModuleInfo struct {
	ProcessCount    int      `json:"processCount"`
	PID             int      `json:"pid"`
	Process         string   `json:"process"`
	ProcessPath     string   `json:"processPath"`
	DLLPath         string   `json:"dllPath"`
	SignatureStatus string   `json:"signatureStatus"`
	Signer          string   `json:"signer"`
	Risk            string   `json:"risk"`
	Reasons         []string `json:"reasons"`
}

type DNSCacheInfo struct {
	Entry      string   `json:"entry"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Data       string   `json:"data"`
	TimeToLive int      `json:"timeToLive"`
	Risk       string   `json:"risk"`
	Reasons    []string `json:"reasons"`
}

type DNSServerInfo struct {
	InterfaceAlias  string   `json:"interfaceAlias"`
	ServerAddresses []string `json:"serverAddresses"`
	Risk            string   `json:"risk"`
	Reasons         []string `json:"reasons"`
}

type RouteInfo struct {
	DestinationPrefix string   `json:"destinationPrefix"`
	NextHop           string   `json:"nextHop"`
	InterfaceAlias    string   `json:"interfaceAlias"`
	RouteMetric       int      `json:"routeMetric"`
	Protocol          string   `json:"protocol"`
	State             string   `json:"state"`
	Risk              string   `json:"risk"`
	Reasons           []string `json:"reasons"`
}

type ProxyInfo struct {
	Scope   string   `json:"scope"`
	Enabled bool     `json:"enabled"`
	Server  string   `json:"server"`
	Bypass  string   `json:"bypass"`
	Raw     string   `json:"raw"`
	Risk    string   `json:"risk"`
	Reasons []string `json:"reasons"`
}

type NetworkInventory struct {
	Connections         []NetworkConnectionInfo `json:"connections"`
	ExternalConnections []NetworkConnectionInfo `json:"externalConnections"`
	Listeners           []NetworkConnectionInfo `json:"listeners"`
	Modules             []NetworkModuleInfo     `json:"modules"`
	DNSCache            []DNSCacheInfo          `json:"dnsCache"`
	DNSServers          []DNSServerInfo         `json:"dnsServers"`
	Routes              []RouteInfo             `json:"routes"`
	Proxies             []ProxyInfo             `json:"proxies"`
	Timestamp           string                  `json:"timestamp"`
}

type AutorunInfo struct {
	Location        string   `json:"location"`
	Name            string   `json:"name"`
	Command         string   `json:"command"`
	Path            string   `json:"path"`
	Description     string   `json:"description"`
	CompanyName     string   `json:"companyName"`
	SignatureStatus string   `json:"signatureStatus"`
	Signer          string   `json:"signer"`
	Enabled         bool     `json:"enabled"`
	Source          string   `json:"source"`
	Risk            string   `json:"risk"`
	Reasons         []string `json:"reasons"`
}

type StartupFileInfo struct {
	FullName      string   `json:"fullName"`
	Length        int64    `json:"length"`
	CreationTime  string   `json:"creationTime"`
	LastWriteTime string   `json:"lastWriteTime"`
	Risk          string   `json:"risk"`
	Reasons       []string `json:"reasons"`
}

type ScheduledTaskInfo struct {
	TaskName    string   `json:"taskName"`
	TaskPath    string   `json:"taskPath"`
	State       string   `json:"state"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	Execute     string   `json:"execute"`
	Arguments   string   `json:"arguments"`
	LastRunTime string   `json:"lastRunTime"`
	NextRunTime string   `json:"nextRunTime"`
	Enabled     bool     `json:"enabled"`
	Risk        string   `json:"risk"`
	Reasons     []string `json:"reasons"`
}

type ServiceInfo struct {
	Name                      string   `json:"name"`
	DisplayName               string   `json:"displayName"`
	State                     string   `json:"state"`
	StartMode                 string   `json:"startMode"`
	PathName                  string   `json:"pathName"`
	ExecutablePath            string   `json:"executablePath"`
	ServiceDLL                string   `json:"serviceDll"`
	FailureCommand            string   `json:"failureCommand"`
	ServiceType               string   `json:"serviceType"`
	ProcessID                 int      `json:"processId"`
	StartName                 string   `json:"startName"`
	SignatureStatus           string   `json:"signatureStatus"`
	Signer                    string   `json:"signer"`
	CompanyName               string   `json:"companyName"`
	FileDescription           string   `json:"fileDescription"`
	FileCreationTime          string   `json:"fileCreationTime"`
	FileLastWriteTime         string   `json:"fileLastWriteTime"`
	ServiceDLLSignatureStatus string   `json:"serviceDllSignatureStatus"`
	ServiceDLLSigner          string   `json:"serviceDllSigner"`
	ServiceDLLCompanyName     string   `json:"serviceDllCompanyName"`
	ServiceDLLCreationTime    string   `json:"serviceDllCreationTime"`
	ServiceDLLLastWriteTime   string   `json:"serviceDllLastWriteTime"`
	Risk                      string   `json:"risk"`
	Reasons                   []string `json:"reasons"`
}

type WMIInfo struct {
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	Query   string   `json:"query"`
	Command string   `json:"command"`
	Risk    string   `json:"risk"`
	Reasons []string `json:"reasons"`
}

type PersistenceInventory struct {
	Autoruns     []AutorunInfo       `json:"autoruns"`
	StartupFiles []StartupFileInfo   `json:"startupFiles"`
	Tasks        []ScheduledTaskInfo `json:"tasks"`
	Services     []ServiceInfo       `json:"services"`
	WMI          []WMIInfo           `json:"wmi"`
	Timestamp    string              `json:"timestamp"`
}

// DeleteTaskRequest 删除计划任务请求：需要 TaskName + TaskPath 精确定位。
type DeleteTaskRequest struct {
	TaskName string `json:"taskName"`
	TaskPath string `json:"taskPath"`
	Reason   string `json:"reason"`
}

// DeleteServiceRequest 删除系统服务请求：用服务短名（Name，非 DisplayName）。
type DeleteServiceRequest struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// DeleteAutorunRequest 删除注册表自启值请求。
// Hive+KeyPath+ValueName 精确定位；Winlogon\Shell/Userinit 等高危项默认拒绝。
type DeleteAutorunRequest struct {
	Hive      string `json:"hive"`      // HKLM 或 HKCU
	KeyPath   string `json:"keyPath"`   // 去掉前缀的键路径，如 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	ValueName string `json:"valueName"` // 要删除的值名
	Reason    string `json:"reason"`
}

// DeleteWmiRequest 删除 WMI 永久订阅请求。
// Kind: EventFilter / Consumer / Binding；删除前后端会先导出对象属性取证。
type DeleteWmiRequest struct {
	Kind   string `json:"kind"` // EventFilter / Consumer / Binding
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// DeleteStartupFileRequest 删除启动文件夹文件请求。删除前自动备份到 TEMP\ir-deleted-backup。
type DeleteStartupFileRequest struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// PersistenceActionResult 删除/处置计划任务或服务的统一返回结构。
type PersistenceActionResult struct {
	OK        bool   `json:"ok"`
	Target    string `json:"target"`
	Command   string `json:"command"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp"`
}

// protectedServiceNames 是不允许通过本工具删除的关键系统服务短名白名单，
// 删除它们会导致系统无法启动或关键功能失效。
var protectedServiceNames = map[string]bool{
	"eventlog": true, "plugplay": true, "rpcss": true, "rpcepmapper": true,
	"winmgmt": true, "lsass": true, "samss": true, "netlogon": true,
	"schedule": true, "services": true, "lanmanserver": true, "lanmanworkstation": true,
	"msiserver": true, "trustedinstaller": true, "system": true, "auditfilter": true,
	"cryptsvc": true, "dhcp": true, "dnscache": true, "iphlpsvc": true,
	"ndu": true, "nsi": true, "tcpip": true, "tdx": true, "afd": true,
	"wdf01000": true, "acpi": true, "disk": true, "partmgr": true, "volmgr": true,
	"volsnap": true, "mountmgr": true, "pcw": true, "wdfloadingservice": true,
}

// isProtectedService 判断服务是否在系统关键服务保护名单内（大小写不敏感）。
func isProtectedService(name string) bool {
	return protectedServiceNames[strings.ToLower(strings.TrimSpace(name))]
}

func isProtectedScheduledTask(taskPath, taskName string) bool {
	p := strings.ToLower(strings.TrimSpace(taskPath))
	n := strings.ToLower(strings.TrimSpace(taskName))
	if strings.HasPrefix(p, `\microsoft\windows\`) || p == `\microsoft\windows` {
		return true
	}
	if strings.HasPrefix(n, `\microsoft\windows\`) {
		return true
	}
	return false
}

// protectedAutorunValues 是微软签名/系统关键的自启值名白名单，删除会破坏系统或正常软件。
var protectedAutorunValues = map[string]bool{
	// Winlogon 关键值（删了会破坏登录）
	"shell": true, "userinit": true, "taskman": true,
	// 系统级微软软件自启
	"securityhealth": true, "onedrive": true, "onedriveupdater": true,
	"windowsdefender": true, "msseces": true, "vmwaretray": true, "vmwareuser": true,
	"rthdvcpl": true, "skytel": true, "adobearm": true, "reader_sl": true,
	"icloudservices": true, "ituneshelper": true, "apnsdaemon": true,
	"loadappinit_dlls": true, // AppInit 加载开关，删了影响加载策略但不致命，保留保护避免误删
}

// isProtectedAutorunValue 判断注册表自启值是否受保护。
// Winlogon 的 Shell/Userinit 等高危值默认拒绝（除非 reason 含 force）。
func isProtectedAutorunValue(hive, keyPath, valueName string) bool {
	v := strings.ToLower(strings.TrimSpace(valueName))
	if protectedAutorunValues[v] {
		return true
	}
	kp := strings.ToLower(strings.TrimSpace(keyPath))
	// Winlogon 下除了明确的几个，其它都保护
	if strings.Contains(kp, `windows nt\currentversion\winlogon`) {
		return true
	}
	return false
}

// isProtectedStartupFile 判断启动文件夹文件是否为系统自带（不应删除）。
func isProtectedStartupFile(filename string) bool {
	f := strings.ToLower(strings.TrimSpace(filename))
	// 系统/软件自带的启动项常见名
	systemStartup := []string{
		"desktop.ini", "readme.txt", "autorun.inf",
	}
	for _, s := range systemStartup {
		if f == s {
			return true
		}
	}
	return false
}

func registerInventoryAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/host", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		item, err := collectHostInventory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, item)
	})

	mux.HandleFunc("/api/accounts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := listAccounts()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"items":     items,
			"count":     len(items),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		days := atoiDefault(r.URL.Query().Get("days"), 0)
		limit := atoiDefault(r.URL.Query().Get("limit"), 160)
		if days < 0 {
			days = 0
		}
		if days > 3650 {
			days = 3650
		}
		if limit <= 0 || limit > 800 {
			limit = 160
		}
		items, err := listKeyEvents(days, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"items":     items,
			"count":     len(items),
			"days":      days,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/rdp-sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := listRDPSessions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"items":     items,
			"count":     len(items),
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/network", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := collectNetworkInventory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	})

	mux.HandleFunc("/api/persistence", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		items, err := collectPersistenceInventory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, items)
	})

	// 删除计划任务：Unregister-ScheduledTask -TaskName -TaskPath -Confirm:$false
	mux.HandleFunc("/api/persistence/tasks/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req DeleteTaskRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := deleteScheduledTask(req)
		writeJSON(w, result)
	})

	// 删除系统服务：sc.exe delete <name>
	mux.HandleFunc("/api/persistence/services/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req DeleteServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := deleteSystemService(req)
		writeJSON(w, result)
	})

	// 删除注册表自启值：Remove-ItemProperty（含保护名单 + Winlogon force 限制）
	mux.HandleFunc("/api/persistence/autorun/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req DeleteAutorunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := deleteAutorunValue(req)
		writeJSON(w, result)
	})

	// 删除 WMI 永久订阅：先导出对象再 Remove-WmiObject
	mux.HandleFunc("/api/persistence/wmi/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req DeleteWmiRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := deleteWmiSubscription(req)
		writeJSON(w, result)
	})

	// 删除启动文件夹文件：先备份到 TEMP\ir-deleted-backup 再 Remove-Item
	mux.HandleFunc("/api/persistence/startup-file/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req DeleteStartupFileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := deleteStartupFile(req)
		writeJSON(w, result)
	})
}

func collectHostInventory() (*HostInventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='SilentlyContinue'
$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$buildNumber=[string]$(if($cv.CurrentBuildNumber){$cv.CurrentBuildNumber}elseif($cv.CurrentBuild){$cv.CurrentBuild}else{$os.BuildNumber})
$productName=[string]$(if($os.Caption){$os.Caption}else{$cv.ProductName})
try {
  if(([int]$buildNumber -ge 22000) -and ($productName -match 'Windows 10')){
    switch -Regex ([string]$cv.EditionID) {
      'CoreCountrySpecific' { $productName='Microsoft Windows 11 家庭中文版'; break }
      'CoreSingleLanguage' { $productName='Microsoft Windows 11 家庭单语言版'; break }
      'Core' { $productName='Microsoft Windows 11 家庭版'; break }
      'Professional' { $productName='Microsoft Windows 11 专业版'; break }
      'Enterprise' { $productName='Microsoft Windows 11 企业版'; break }
      'Education' { $productName='Microsoft Windows 11 教育版'; break }
      default { $productName=($productName -replace 'Windows 10','Windows 11') }
    }
  }
} catch {}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
$hotfixes=Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object {
  [PSCustomObject]@{
    hotFixId=[string]$_.HotFixID
    description=[string]$_.Description
    installedOn=if($_.InstalledOn){ ([datetime]$_.InstalledOn).ToString('o') } else { '' }
    installedBy=[string]$_.InstalledBy
  }
}
$ips=Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -ne '127.0.0.1'} | ForEach-Object {
  [PSCustomObject]@{interfaceAlias=[string]$_.InterfaceAlias; ipAddress=[string]$_.IPAddress; prefixLength=[int]$_.PrefixLength}
}
[PSCustomObject]@{
  hostname=[string]$env:COMPUTERNAME
  currentUser=[string]$id.Name
  userSid=[string]$id.User.Value
  isAdmin=[bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  windowsProductName=[string]$productName
  displayVersion=[string]$(if($cv.DisplayVersion){$cv.DisplayVersion}else{$cv.ReleaseId})
  windowsVersion=[string]$os.Version
  buildNumber=[string]$buildNumber
  ubr=[string]$cv.UBR
  architecture=[string]$os.OSArchitecture
  domain=[string]$cs.Domain
  manufacturer=[string]$cs.Manufacturer
  model=[string]$cs.Model
  installDate=if($os.InstallDate){ ([datetime]$os.InstallDate).ToString('o') } else { '' }
  lastBootTime=if($os.LastBootUpTime){ ([datetime]$os.LastBootUpTime).ToString('o') } else { '' }
  timeZone=[string]$os.CurrentTimeZone
  powerShellVersion=[string]$PSVersionTable.PSVersion
  hotfixes=@($hotfixes)
  ipAddresses=@($ips)
} | ConvertTo-Json -Depth 5 -Compress`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("host inventory timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("host inventory failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var inv HostInventory
	if err := json.Unmarshal(out, &inv); err != nil {
		return nil, fmt.Errorf("parse host inventory failed: %v", err)
	}
	if inv.Hotfixes == nil {
		inv.Hotfixes = []HotfixInfo{}
	}
	if inv.IPAddresses == nil {
		inv.IPAddresses = []IPAddressInfo{}
	}
	inv.Timestamp = time.Now().Format(time.RFC3339)
	classifyHost(&inv)
	return &inv, nil
}

func classifyHost(h *HostInventory) {
	h.Risk = "low"
	h.Reasons = []string{"系统版本、Build、补丁和当前权限已采集"}
	product := strings.ToLower(h.WindowsProductName)
	if strings.Contains(product, "windows 7") || strings.Contains(product, "windows 8") || strings.Contains(product, "server 2008") || strings.Contains(product, "server 2012") {
		h.Risk = maxRisk(h.Risk, "high")
		h.Reasons = append(h.Reasons, "系统版本较旧，需确认补丁支持状态")
	}
	if !h.IsAdmin {
		h.Risk = maxRisk(h.Risk, "medium")
		h.Reasons = append(h.Reasons, "当前客户端未以管理员权限运行，部分应急采集可能不完整")
	}
	if len(h.Hotfixes) == 0 {
		h.Risk = maxRisk(h.Risk, "medium")
		h.Reasons = append(h.Reasons, "未读取到补丁列表，需复核 Windows Update/权限")
	}
}

func listAccounts() ([]AccountInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='SilentlyContinue'
$adminMap=@{}
try {
  Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
    $n=[string]$_.Name
    if($n){ $adminMap[$n.ToLower()]=$true; $adminMap[(($n -split '\\')[-1]).ToLower()]=$true }
  }
} catch {}
$hiddenMap=@{}
try {
  $hiddenKey='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
  $hiddenProps=Get-ItemProperty -Path $hiddenKey -ErrorAction SilentlyContinue
  if($hiddenProps){
    $hiddenProps.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      $hiddenMap[$_.Name.ToLowerInvariant()] = ([int]$_.Value -eq 0)
    }
  }
} catch {}
$items = Get-LocalUser | ForEach-Object {
  $accountName=[string]$_.Name
  $accountKey=$accountName.ToLowerInvariant()
  [PSCustomObject]@{
    name = $accountName
    enabled = [bool]$_.Enabled
    sid = [string]$_.SID
    lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { '' }
    passwordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') } else { '' }
    description = [string]$_.Description
    passwordRequired = [bool]$_.PasswordRequired
    userMayChangePassword = [bool]$_.UserMayChangePassword
    admin = [bool]$adminMap.ContainsKey($accountKey)
    hidden = [bool]($accountName.EndsWith('$') -or ($hiddenMap.ContainsKey($accountKey) -and $hiddenMap[$accountKey]))
  }
}
@($items) | ConvertTo-Json -Depth 4 -Compress`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("account enumeration timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("account enumeration failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" || strings.TrimSpace(string(out)) == "null" {
		return []AccountInfo{}, nil
	}
	var items []AccountInfo
	if err := json.Unmarshal(out, &items); err != nil {
		var single AccountInfo
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("parse account json failed: %v", err)
		}
		items = []AccountInfo{single}
	}
	for i := range items {
		classifyAccount(&items[i])
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri, rj := severityRank(items[i].Risk), severityRank(items[j].Risk)
		if ri != rj {
			return ri > rj
		}
		if items[i].Admin != items[j].Admin {
			return items[i].Admin
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}

func classifyAccount(a *AccountInfo) {
	reasons := []string{}
	risk := "low"
	lowerName := strings.ToLower(a.Name)
	if a.Hidden && strings.HasSuffix(a.Name, "$") {
		reasons = append(reasons, "账号名以 $ 结尾，疑似隐藏账号")
		risk = maxRisk(risk, "high")
	} else if a.Hidden {
		reasons = append(reasons, "账号被 SpecialAccounts\\UserList 标记为隐藏账号")
		risk = maxRisk(risk, "high")
	}
	if a.Admin && !strings.HasSuffix(a.SID, "-500") && lowerName != "administrator" {
		reasons = append(reasons, "管理员组成员，需确认授权")
		risk = maxRisk(risk, "medium")
	}
	if a.Enabled && !a.PasswordRequired {
		reasons = append(reasons, "启用账号未要求密码")
		risk = maxRisk(risk, "high")
	}
	if !a.Enabled {
		reasons = append(reasons, "账号已禁用")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "未命中内置账号风险规则")
	}
	a.Risk = risk
	a.Reasons = reasons
}

func listKeyEvents(days, limit int) ([]EventInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	loginMax := limit / 3
	if loginMax < 120 {
		loginMax = 120
	}
	failMax := loginMax
	categoryMax := limit / 5
	if categoryMax < 80 {
		categoryMax = 80
	}
	logMax := limit / 5
	if logMax < 80 {
		logMax = 80
	}
	rdpMax := limit / 4
	if rdpMax < 80 {
		rdpMax = 80
	}
	procMax := limit / 4
	if procMax < 80 {
		procMax = 80
	}
	finalMax := limit * 2
	if finalMax < limit {
		finalMax = limit
	}
	// 采集应急需要的事件：登录成功/失败、账户操作、日志服务关闭、审计日志清除、
	// RDP登录(TerminalServices)、服务创建(7045)、进程创建(4688)。
	// IP、用户名、登录类型、命令行等关键字段直接从事件 XML 的 EventData 节点结构化提取，
	// 不再依赖 Message 本地化文本正则，避免中文/乱码环境下 IP 显示为 "?" 的问题。
	script := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'
$days=%d
$useStart=$false
$start=$null
if($days -gt 0){ $useStart=$true; $start=(Get-Date).AddDays(-$days) }
$defs=@(
  @{Log='Security';Ids=@(4624,4648,4672,4778);Max=%d},
  @{Log='Security';Ids=@(4625,4771,4776,4779);Max=%d},
  @{Log='Security';Ids=@(4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4740);Max=%d},
  @{Log='Security';Ids=@(1100,1102);Max=%d},
  @{Log='System';Ids=@(6005,6006,6008,7045);Max=%d},
  @{Log='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';Ids=@(21,22,24,25);Max=%d},
  @{Log='Security';Ids=@(4688);Max=%d}
)
function Read-EventData($ev){
  $props=@{}
  try{
    $xml=[xml]$ev.ToXml()
    $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    foreach($d in $xml.SelectNodes('//e:Data',$ns)){
      $n=[string]$d.GetAttribute('Name')
      if($n){ $props[$n]=[string]$d.InnerText }
    }
  }catch{}
  return $props
}
function Clean($v){ $s=[string]$v; if($s -eq '-'){return ''}; return $s.Trim() }
function IsNoiseIP($v){ $s=[string]$v; return ($s -eq '' -or $s -eq '-' -or $s -eq '::1' -or $s -eq '127.0.0.1') }
# 噪声账户：SYSTEM / 本地服务 / 计算机账户(以 $ 结尾) 这些登录通常没有真实源 IP
function IsNoiseAccount($u){ $s=[string]$u; return ($s -eq 'SYSTEM' -or $s -eq 'UMFD-0' -or $s -eq 'DWM-1' -or $s -eq 'DWM-0' -or $s -eq '$' -or $s.EndsWith('$') -or $s -eq 'ANONYMOUS LOGON') }
# 真正有意义的远程登录类型：2 交互 / 3 网络 / 4 批处理 / 7 解锁 / 8 明文 / 9 新凭据 / 10 RDP / 11 缓存交互
$remoteTypes=@(2,3,4,7,8,9,10,11)
$out=@()
foreach($d in $defs){
  try {
    $filter=@{LogName=$d.Log}
    if($useStart){ $filter['StartTime']=$start }
    if($d.Ids){ $filter['Id']=$d.Ids }
    Get-WinEvent -FilterHashtable $filter -MaxEvents $d.Max -ErrorAction Stop | ForEach-Object {
      $msg=[string]$_.Message
      if($msg.Length -gt 900){ $msg=$msg.Substring(0,900) + '...' }
      $p=Read-EventData $_
      $eid=[int]$_.Id
      $user=Clean($p['TargetUserName']); if(-not $user){$user=Clean($p['SubjectUserName'])}; if(-not $user){$user=Clean($p['SamAccountName'])}
      $ip=Clean($p['IpAddress']); if(-not $ip){$ip=Clean($p['SourceNetworkAddress'])}; if(-not $ip){$ip=Clean($p['ClientAddress'])}
      $port=Clean($p['IpPort']); if(-not $port){$port=Clean($p['SourcePort'])}
      $ltype=Clean($p['LogonType'])
      # 进程创建(4688)：提取新进程名、命令行、父进程
      $cmdLine=''; $imgPath=''
      if($eid -eq 4688){
        $cmdLine=Clean($p['CommandLine']); $imgPath=Clean($p['NewProcessName'])
        if(-not $imgPath){$imgPath=Clean($p['ProcessName'])}
      }
      # 服务创建(7045)：提取服务名、可执行路径、启动类型
      $svcName=''; $svcPath=''
      if($eid -eq 7045){
        $svcName=Clean($p['ServiceName']); $svcPath=Clean($p['ImagePath']); if(-not $svcPath){$svcPath=Clean($p['ServiceFileName'])}
      }
      # 登录类事件(4624/4625/4648/4672)过滤掉本地噪声：SYSTEM/计算机账户 + 非远程登录类型
      if($eid -eq 4624 -or $eid -eq 4625 -or $eid -eq 4672 -or $eid -eq 4648){
        $lt=0; [int]::TryParse($ltype,[ref]$lt) | Out-Null
        if((IsNoiseAccount $user) -and ($remoteTypes -notcontains $lt)){ return }
      }
      $out += [PSCustomObject]@{
        time = $_.TimeCreated.ToString('o')
        log = [string]$d.Log
        id = $eid
        provider = [string]$_.ProviderName
        level = [string]$_.LevelDisplayName
        message = $msg
        user = $user
        ip = $ip
        port = $port
        logonType = $ltype
        commandLine = $cmdLine
        serviceName = $svcName
        imagePath = $svcPath
      }
    }
  } catch {}
}
@($out | Sort-Object time -Descending | Select-Object -First %d) | ConvertTo-Json -Depth 4 -Compress`, days, loginMax, failMax, categoryMax, logMax, logMax, rdpMax, procMax, finalMax)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("event enumeration timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("event enumeration failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if strings.TrimSpace(string(out)) == "" || strings.TrimSpace(string(out)) == "null" {
		return []EventInfo{}, nil
	}
	var items []EventInfo
	if err := json.Unmarshal(out, &items); err != nil {
		var single EventInfo
		if err2 := json.Unmarshal(out, &single); err2 != nil {
			return nil, fmt.Errorf("parse event json failed: %v", err)
		}
		items = []EventInfo{single}
	}
	for i := range items {
		classifyEvent(&items[i])
	}
	return items, nil
}

// listRDPSessions 采集当前实时 RDP/终端会话（来自 quser，回退 qwinsta）。
// 这是会话快照而非日志事件，用于"RDP连接"tab。
func listRDPSessions() ([]RDPSessionInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	// quser/qwinsta 输出是定宽表格，第一行是表头。用 PowerShell 把每行按空白切分，
	// 兼容 quser（含 IDLE TIME/LOGON TIME 列）和 qwinsta（不含）两种格式。
	script := `$ErrorActionPreference='SilentlyContinue'
$out=@()
$lines=@()
try { $lines=(quser) -as [string[]] } catch {}
if(-not $lines -or $lines.Count -lt 2){
  try { $lines=(qwinsta) -as [string[]] } catch {}
}
if($lines -and $lines.Count -ge 2){
  foreach($ln in $lines[1..($lines.Count-1)]){
    if(-not $ln.Trim()){ continue }
    $parts=$ln -split '\s+' | Where-Object { $_ -ne '' }
    if($parts.Count -lt 2){ continue }
    # quser 格式：USERNAME SESSIONNAME ID STATE IDLE TIME LOGON TIME
    # SESSIONNAME 列对磁盘/服务会话为空，导致列数变化，需启发式判断
    $obj=[PSCustomObject]@{ userName=''; sessionName=''; id=''; state=''; idleTime=''; logonTime='' }
    $hasSession=($parts[1] -match '^\d+$') -or ($parts[1] -match '^(rdp|console|services|>--)')
    if($hasSession){
      $obj.userName=[string]$parts[0]
      $obj.sessionName=[string]$parts[1]
      $obj.id=[string]$parts[2]
      $obj.state=if($parts.Count -ge 4){[string]$parts[3]}else{''}
      # 剩余列拼回 idleTime/logonTime
      if($parts.Count -ge 5){ $obj.logonTime=[string]($parts[($parts.Count-1)]) }
    } else {
      $obj.userName=[string]$parts[0]
      $obj.id=[string]$parts[1]
      $obj.state=if($parts.Count -ge 3){[string]$parts[2]}else{''}
      if($parts.Count -ge 4){ $obj.logonTime=[string]($parts[($parts.Count-1)]) }
    }
    $out += $obj
  }
}
if($out.Count -eq 0){ '' } else { $out | ConvertTo-Json -Depth 3 -Compress }
`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("rdp session enumeration timed out")
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == `""` || trimmed == "null" {
		return []RDPSessionInfo{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rdp session enumeration failed: %v: %s", err, trimmed)
	}
	var items []RDPSessionInfo
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		var single RDPSessionInfo
		if err2 := json.Unmarshal([]byte(out), &single); err2 != nil {
			return nil, fmt.Errorf("parse rdp session json failed: %v", err)
		}
		items = []RDPSessionInfo{single}
	}
	return items, nil
}

// deleteScheduledTask 删除计划任务。用 Unregister-ScheduledTask 同时带 TaskName 和 TaskPath
// 精确定位，避免误删同名任务；-Confirm:$false 跳过交互。
func deleteScheduledTask(req DeleteTaskRequest) PersistenceActionResult {
	result := PersistenceActionResult{Target: strings.TrimSpace(req.TaskName), Timestamp: time.Now().Format(time.RFC3339)}
	name := strings.TrimSpace(req.TaskName)
	if name == "" {
		result.Error = "缺少计划任务名称（taskName）"
		return result
	}
	taskPath := strings.TrimSpace(req.TaskPath)
	if isProtectedScheduledTask(taskPath, name) && !strings.Contains(strings.ToLower(req.Reason), "force") {
		result.Error = "拒绝删除 Microsoft Windows 系统计划任务：" + firstNonEmpty(taskPath, `\`) + name + "。如确认恶意，请先导出任务 XML 后手动处置。"
		return result
	}
	// 构造脚本：优先用 TaskPath 定位；缺省时回退到仅按名称匹配
	var script string
	if taskPath != "" {
		result.Command = fmt.Sprintf("Unregister-ScheduledTask -TaskName '%s' -TaskPath '%s' -Confirm:$false", name, taskPath)
		script = fmt.Sprintf(`$ErrorActionPreference='Stop'
try { Unregister-ScheduledTask -TaskName '%s' -TaskPath '%s' -Confirm:$false -ErrorAction Stop; 'OK' }
catch { Write-Output ('ERR:' + $_.Exception.Message) }`, psSingleQuoteEscape(name), psSingleQuoteEscape(taskPath))
	} else {
		result.Command = fmt.Sprintf("Unregister-ScheduledTask -TaskName '%s' -Confirm:$false", name)
		script = fmt.Sprintf(`$ErrorActionPreference='Stop'
try { Unregister-ScheduledTask -TaskName '%s' -Confirm:$false -ErrorAction Stop; 'OK' }
catch { Write-Output ('ERR:' + $_.Exception.Message) }`, psSingleQuoteEscape(name))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "删除计划任务超时"
		return result
	}
	output := strings.TrimSpace(string(out))
	result.Output = output
	if err != nil && output == "" {
		result.Error = err.Error()
		return result
	}
	if strings.HasPrefix(output, "ERR:") {
		result.Error = strings.TrimPrefix(output, "ERR:")
		return result
	}
	result.OK = true
	result.Message = "计划任务已删除：" + firstNonEmpty(taskPath, `\`) + name
	return result
}

// deleteSystemService 删除系统服务。用 sc.exe delete <name>（兼容旧系统），
// 命中保护名单的关键服务拒绝删除。
func deleteSystemService(req DeleteServiceRequest) PersistenceActionResult {
	result := PersistenceActionResult{Target: strings.TrimSpace(req.Name), Timestamp: time.Now().Format(time.RFC3339)}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		result.Error = "缺少服务名称（name）"
		return result
	}
	if !isSafeServiceName(name) {
		result.Error = "服务短名包含不安全字符，已拒绝执行：" + name
		return result
	}
	if isProtectedService(name) {
		result.Error = "拒绝删除受保护的关键系统服务：" + name
		return result
	}
	// 先尝试停止运行中的服务，再删除，避免"服务被标记为删除但仍在运行"
	stopScript := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'
try { Stop-Service -Name '%s' -Force -ErrorAction SilentlyContinue } catch {}
sc.exe delete %s`, psSingleQuoteEscape(name), svcTokenSafe(name))
	result.Command = fmt.Sprintf("sc.exe delete %s", name)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+stopScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "删除系统服务超时"
		return result
	}
	output := strings.TrimSpace(string(out))
	result.Output = output
	if err != nil && output == "" {
		result.Error = err.Error()
		return result
	}
	// sc.exe delete 成功标志：含 "SUCCESS" 或 "[SC] DeleteService SUCCESS"；标记删除中也算 OK
	lower := strings.ToLower(output)
	if strings.Contains(lower, "success") || strings.Contains(lower, "标记为删除") || strings.Contains(lower, "marked for deletion") {
		result.OK = true
		result.Message = "系统服务已删除或已标记删除：" + name
		return result
	}
	if strings.Contains(lower, "指定的服务未安装") || strings.Contains(lower, "not exist") || strings.Contains(lower, "does not exist") {
		result.Error = "服务不存在或已删除：" + name
		return result
	}
	if strings.Contains(lower, "拒绝访问") || strings.Contains(lower, "access is denied") {
		result.Error = "权限不足（拒绝访问），请以管理员重新运行客户端"
		return result
	}
	result.Error = output
	return result
}

// deleteAutorunValue 删除注册表自启值。
// 用 Remove-ItemProperty；命中保护名单（Winlogon\Shell/Userinit 等）默认拒绝，
// 仅当 reason 含 "force" 才允许（破坏系统登录的高危操作需二次确认）。
func deleteAutorunValue(req DeleteAutorunRequest) PersistenceActionResult {
	target := strings.TrimSpace(req.ValueName) + " @ " + strings.TrimSpace(req.Hive) + `\` + strings.TrimSpace(req.KeyPath)
	result := PersistenceActionResult{Target: target, Timestamp: time.Now().Format(time.RFC3339)}
	hive := strings.ToUpper(strings.TrimSpace(req.Hive))
	keyPath := strings.TrimSpace(req.KeyPath)
	valueName := strings.TrimSpace(req.ValueName)
	if valueName == "" || keyPath == "" {
		result.Error = "缺少 valueName 或 keyPath"
		return result
	}
	if hive != "HKLM" && hive != "HKCU" {
		result.Error = "hive 必须是 HKLM 或 HKCU"
		return result
	}
	// 安全校验：拒删系统关键值；Winlogon 仅 force 放行
	if isProtectedAutorunValue(hive, keyPath, valueName) && !strings.Contains(strings.ToLower(req.Reason), "force") {
		result.Error = "拒绝删除受保护的系统自启值：" + valueName + "（位于 " + keyPath + "）。如确认为恶意且已备份，请强制确认后重试。"
		return result
	}
	// 构造 PS 路径：HKLM:\... / HKCU:\...
	psPath := hive + `:\` + keyPath
	result.Command = fmt.Sprintf("Remove-ItemProperty -Path '%s' -Name '%s' -Confirm:$false", psPath, valueName)
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
try {
  $p='%s'
  if(-not (Test-Path $p)){ Write-Output 'ERR:注册表键不存在'; exit }
  $cur=(Get-ItemProperty $p -Name '%s' -ErrorAction Stop).'%s'
  Write-Output ('BACKUP:'+$cur)
  Remove-ItemProperty -Path $p -Name '%s' -Confirm:$false -ErrorAction Stop
  Write-Output 'OK'
} catch { Write-Output ('ERR:'+($_.Exception.Message)) }`,
		psSingleQuoteEscape(psPath), psSingleQuoteEscape(valueName), psSingleQuoteEscape(valueName), psSingleQuoteEscape(valueName))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "删除注册表值超时"
		return result
	}
	output := strings.TrimSpace(string(out))
	result.Output = output
	if err != nil && output == "" {
		result.Error = err.Error()
		return result
	}
	lower := strings.ToLower(output)
	if strings.HasPrefix(output, "ERR:") {
		result.Error = strings.TrimPrefix(output, "ERR:")
		return result
	}
	if strings.Contains(lower, "拒绝访问") || strings.Contains(lower, "access is denied") {
		result.Error = "权限不足（拒绝访问），请以管理员重新运行客户端"
		return result
	}
	result.OK = true
	result.Message = "注册表自启值已删除：" + target
	return result
}

// deleteWmiSubscription 删除 WMI 永久订阅。
// Kind: EventFilter / Consumer / Binding；删除前先导出对象属性取证。
func deleteWmiSubscription(req DeleteWmiRequest) PersistenceActionResult {
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	name := strings.TrimSpace(req.Name)
	target := kind + ":" + name
	result := PersistenceActionResult{Target: target, Timestamp: time.Now().Format(time.RFC3339)}
	if name == "" || kind == "" {
		result.Error = "缺少 kind 或 name"
		return result
	}
	// 按 kind 映射到 WMI 类名
	var wmiClass string
	switch kind {
	case "eventfilter", "filter":
		wmiClass = "__EventFilter"
	case "consumer":
		wmiClass = "__EventConsumer"
	case "binding":
		wmiClass = "__FilterToConsumerBinding"
	default:
		result.Error = "kind 必须是 EventFilter / Consumer / Binding"
		return result
	}
	result.Command = fmt.Sprintf("Get-WmiObject %s -Filter \"Name='%s'\" | Remove-WmiObject", wmiClass, name)
	// 删除前先导出对象属性（取证留痕），再删除
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
try {
  $obj = Get-WmiObject %s -Filter "Name='%s'" -ErrorAction Stop
  if(-not $obj){ Write-Output 'ERR:WMI 对象不存在'; exit }
  Write-Output ('BACKUP:'+($obj | Select-Object * -ExcludeProperty PS* | Out-String))
  $obj | Remove-WmiObject -ErrorAction Stop
  Write-Output 'OK'
} catch { Write-Output ('ERR:'+($_.Exception.Message)) }`, wmiClass, psSingleQuoteEscape(name))
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "删除 WMI 订阅超时"
		return result
	}
	output := strings.TrimSpace(string(out))
	result.Output = output
	if err != nil && output == "" {
		result.Error = err.Error()
		return result
	}
	if strings.HasPrefix(output, "ERR:") {
		result.Error = strings.TrimPrefix(output, "ERR:")
		return result
	}
	result.OK = true
	result.Message = "WMI 永久订阅已删除（已先导出对象属性）：" + target
	return result
}

// deleteStartupFile 删除启动文件夹文件。删除前自动备份到 TEMP\ir-deleted-backup。
func deleteStartupFile(req DeleteStartupFileRequest) PersistenceActionResult {
	path := strings.TrimSpace(req.Path)
	result := PersistenceActionResult{Target: path, Timestamp: time.Now().Format(time.RFC3339)}
	if path == "" {
		result.Error = "缺少 path"
		return result
	}
	// 安全校验：拒删系统自带文件
	base := filepath.Base(path)
	if isProtectedStartupFile(base) {
		result.Error = "拒绝删除系统自带的启动文件夹文件：" + base
		return result
	}
	// 路径必须落在已知的 Startup 目录下，防止任意文件删除
	lower := strings.ToLower(path)
	if !strings.Contains(lower, `start menu\programs\startup`) {
		result.Error = "路径不在启动文件夹内，已拒绝：" + path
		return result
	}
	result.Command = fmt.Sprintf("备份到 $env:TEMP\\ir-deleted-backup 后 Remove-Item -LiteralPath '%s'", path)
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'
try {
  $src='%s'
  if(-not (Test-Path -LiteralPath $src)){ Write-Output 'ERR:文件不存在'; exit }
  $backupDir=Join-Path $env:TEMP 'ir-deleted-backup'
  if(-not (Test-Path $backupDir)){ New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
  $dst=Join-Path $backupDir ([System.IO.Path]::GetFileName($src)+'.'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
  Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
  Write-Output ('BACKUP:'+$dst)
  Remove-Item -LiteralPath $src -Force -ErrorAction Stop
  Write-Output 'OK'
} catch { Write-Output ('ERR:'+($_.Exception.Message)) }`, strings.ReplaceAll(path, "'", "''"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "删除启动文件超时"
		return result
	}
	output := strings.TrimSpace(string(out))
	result.Output = output
	if err != nil && output == "" {
		result.Error = err.Error()
		return result
	}
	if strings.HasPrefix(output, "ERR:") {
		result.Error = strings.TrimPrefix(output, "ERR:")
		return result
	}
	result.OK = true
	result.Message = "启动文件已删除（已备份到 TEMP\\ir-deleted-backup）：" + path
	return result
}

// psSingleQuoteEscape 转义 PowerShell 单引号字符串里的单引号（' -> ''）。
func psSingleQuoteEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// svcTokenSafe 校验服务短名只含安全字符，防注入；非法字符回退为原值（sc.exe 会自行报错）。
func svcTokenSafe(name string) string {
	if !isSafeServiceName(name) {
		return ""
	}
	return name
}

func isSafeServiceName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '$' {
			continue
		}
		return false
	}
	return true
}

func classifyEvent(e *EventInfo) {
	reasons := []string{}
	risk := "low"
	switch e.ID {
	case 1100:
		reasons = append(reasons, "事件日志服务关闭")
		risk = "high"
	case 1102:
		reasons = append(reasons, "安全日志被清理")
		risk = "critical"
	case 7045:
		reasons = append(reasons, "新服务安装事件")
		risk = "high"
	case 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4740:
		reasons = append(reasons, "账号创建/启用/禁用/删除/组成员变更事件")
		risk = "high"
	case 4625, 4771, 4776:
		reasons = append(reasons, "登录失败/凭据验证事件")
		risk = "medium"
	case 4672:
		reasons = append(reasons, "特权登录事件")
		risk = "medium"
	case 4104:
		if strings.Contains(strings.ToLower(e.Message), "encodedcommand") || strings.Contains(strings.ToLower(e.Message), "downloadstring") || strings.Contains(strings.ToLower(e.Message), "invoke-expression") {
			reasons = append(reasons, "PowerShell 脚本块包含下载/编码/执行特征")
			risk = "high"
		} else {
			reasons = append(reasons, "PowerShell 脚本块日志")
		}
	case 4103:
		reasons = append(reasons, "PowerShell 模块日志")
	case 400:
		reasons = append(reasons, "PowerShell 引擎启动")
	case 403:
		reasons = append(reasons, "PowerShell 引擎停止")
	case 600:
		reasons = append(reasons, "PowerShell Provider 加载")
	case 800:
		reasons = append(reasons, "PowerShell 管道执行")
	case 4624:
		reasons = append(reasons, "登录成功事件")
	case 4648:
		reasons = append(reasons, "显式凭据登录事件")
	case 4778:
		reasons = append(reasons, "RDP 会话重连")
	case 4779:
		reasons = append(reasons, "RDP 会话断开")
	case 6006:
		reasons = append(reasons, "事件日志服务停止")
		risk = maxRisk(risk, "high")
	case 6005:
		reasons = append(reasons, "事件日志服务启动")
	case 6008:
		reasons = append(reasons, "系统异常关机")
		risk = maxRisk(risk, "medium")
	case 21:
		reasons = append(reasons, "RDP 会话登录")
		risk = maxRisk(risk, "medium")
	case 22:
		reasons = append(reasons, "RDP 会话重连")
		risk = maxRisk(risk, "medium")
	case 24:
		reasons = append(reasons, "RDP 会话已断开")
	case 25:
		reasons = append(reasons, "RDP 会话重新连接成功")
		risk = maxRisk(risk, "medium")
	case 4688:
		reasons = append(reasons, "进程创建")
		ml := strings.ToLower(e.CommandLine + " " + e.ImagePath)
		if strings.Contains(ml, "encodedcommand") || strings.Contains(ml, "downloadstring") || strings.Contains(ml, "invoke-expression") || strings.Contains(ml, "iex") || strings.Contains(ml, "certutil") || strings.Contains(ml, "bitsadmin") {
			reasons = append(reasons, "命令行命中下载/编码/执行特征")
			risk = maxRisk(risk, "high")
		}
	case 7036:
		reasons = append(reasons, "服务状态变化")
	case 7040:
		reasons = append(reasons, "服务启动类型变更")
	default:
		if e.ID > 0 {
			reasons = append(reasons, "关键日志事件 "+strconv.Itoa(e.ID))
		}
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "普通日志事件")
	}
	e.Risk = risk
	e.Reasons = reasons
}

func collectNetworkInventory() (*NetworkInventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	inv := &NetworkInventory{Timestamp: time.Now().Format(time.RFC3339)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	successes := 0
	errs := []string{}

	record := func(label string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, label+": "+err.Error())
			return
		}
		successes++
	}

	wg.Add(6)
	go func() {
		defer wg.Done()
		var result struct {
			Items []NetworkConnectionInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "connections", networkConnectionsScript(), &result)
		if err == nil {
			mu.Lock()
			inv.Connections = result.Items
			mu.Unlock()
		}
		record("connections", err)
	}()
	go func() {
		defer wg.Done()
		var result struct {
			Items []DNSCacheInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "dns-cache", networkDNSCacheScript(), &result)
		if err == nil {
			mu.Lock()
			inv.DNSCache = result.Items
			mu.Unlock()
		}
		record("dns-cache", err)
	}()
	go func() {
		defer wg.Done()
		var result struct {
			Items []DNSServerInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "dns-servers", networkDNSServersScript(), &result)
		if err == nil {
			mu.Lock()
			inv.DNSServers = result.Items
			mu.Unlock()
		}
		record("dns-servers", err)
	}()
	go func() {
		defer wg.Done()
		var result struct {
			Items []RouteInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "routes", networkRoutesScript(), &result)
		if err == nil {
			mu.Lock()
			inv.Routes = result.Items
			mu.Unlock()
		}
		record("routes", err)
	}()
	go func() {
		defer wg.Done()
		var result struct {
			Items []ProxyInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "proxies", networkProxiesScript(), &result)
		if err == nil {
			mu.Lock()
			inv.Proxies = result.Items
			mu.Unlock()
		}
		record("proxies", err)
	}()
	go func() {
		defer wg.Done()
		var result struct {
			Items []NetworkModuleInfo `json:"items"`
		}
		err := runNetworkInventoryPS(ctx, "modules", networkModulesScript(), &result)
		if err == nil {
			mu.Lock()
			inv.Modules = result.Items
			mu.Unlock()
		}
		record("modules", err)
	}()
	wg.Wait()

	if successes == 0 {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("network inventory timed out")
		}
		return nil, fmt.Errorf("network inventory failed: %s", strings.Join(errs, "; "))
	}

	inv.Timestamp = time.Now().Format(time.RFC3339)
	if inv.Connections == nil {
		inv.Connections = []NetworkConnectionInfo{}
	}
	inv.ExternalConnections = []NetworkConnectionInfo{}
	inv.Listeners = []NetworkConnectionInfo{}
	if inv.Modules == nil {
		inv.Modules = []NetworkModuleInfo{}
	}
	if inv.DNSCache == nil {
		inv.DNSCache = []DNSCacheInfo{}
	}
	if inv.DNSServers == nil {
		inv.DNSServers = []DNSServerInfo{}
	}
	if inv.Routes == nil {
		inv.Routes = []RouteInfo{}
	}
	if inv.Proxies == nil {
		inv.Proxies = []ProxyInfo{}
	}
	for i := range inv.Connections {
		classifyConnection(&inv.Connections[i])
		if inv.Connections[i].External {
			inv.ExternalConnections = append(inv.ExternalConnections, inv.Connections[i])
		}
		if strings.EqualFold(inv.Connections[i].State, "Listen") {
			inv.Listeners = append(inv.Listeners, inv.Connections[i])
		}
	}
	for i := range inv.DNSCache {
		classifyDNSCache(&inv.DNSCache[i])
	}
	sort.SliceStable(inv.DNSCache, func(i, j int) bool {
		ri, rj := severityRank(inv.DNSCache[i].Risk), severityRank(inv.DNSCache[j].Risk)
		if ri != rj {
			return ri > rj
		}
		ni := strings.ToLower(inv.DNSCache[i].Name + inv.DNSCache[i].Entry)
		nj := strings.ToLower(inv.DNSCache[j].Name + inv.DNSCache[j].Entry)
		return ni < nj
	})
	for i := range inv.Modules {
		classifyNetworkModule(&inv.Modules[i])
	}
	sort.SliceStable(inv.Modules, func(i, j int) bool {
		ri, rj := severityRank(inv.Modules[i].Risk), severityRank(inv.Modules[j].Risk)
		if ri != rj {
			return ri > rj
		}
		if inv.Modules[i].ProcessCount != inv.Modules[j].ProcessCount {
			return inv.Modules[i].ProcessCount > inv.Modules[j].ProcessCount
		}
		return strings.ToLower(inv.Modules[i].DLLPath) < strings.ToLower(inv.Modules[j].DLLPath)
	})
	for i := range inv.DNSServers {
		classifyDNSServer(&inv.DNSServers[i])
	}
	for i := range inv.Routes {
		classifyRoute(&inv.Routes[i])
	}
	for i := range inv.Proxies {
		classifyProxy(&inv.Proxies[i])
	}
	sort.SliceStable(inv.ExternalConnections, func(i, j int) bool {
		if inv.ExternalConnections[i].RemoteAddress != inv.ExternalConnections[j].RemoteAddress {
			return inv.ExternalConnections[i].RemoteAddress < inv.ExternalConnections[j].RemoteAddress
		}
		return inv.ExternalConnections[i].RemotePort < inv.ExternalConnections[j].RemotePort
	})
	return inv, nil
}

func runNetworkInventoryPS(ctx context.Context, label, script string, target any) error {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out", label)
	}
	if err != nil {
		return fmt.Errorf("%s failed: %v: %s", label, err, strings.TrimSpace(string(out)))
	}
	if err := json.Unmarshal(out, target); err != nil {
		return fmt.Errorf("parse %s failed: %v: %s", label, err, compact(string(out), 300))
	}
	return nil
}

func networkConnectionsScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$tcp=@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.State -in @('Established','Listen')} | Select-Object -First 1500)
$pids=@($tcp | ForEach-Object {[int]$_.OwningProcess} | Sort-Object -Unique)
$pidSet=@{}
foreach($procId in $pids){ $pidSet[$procId]=$true }
$procMap=@{}
try {
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $procId=[int]$_.Id
    if($pidSet.ContainsKey($procId)){
      $name=[string]$_.ProcessName
      $path=''
      if($name -and $name -notmatch '\.exe$'){ $name=$name + '.exe' }
      try { $path=[string]$_.Path } catch {}
      $procMap[$procId]=[PSCustomObject]@{name=$name; path=$path; commandLine=''}
    }
  }
} catch {}
foreach($procId in $pids){
  if(-not $procMap.ContainsKey($procId)){
    $procMap[$procId]=[PSCustomObject]@{name=''; path=''; commandLine=''}
  }
}
$items=@($tcp | ForEach-Object {
  $ownerPid=[int]$_.OwningProcess
  $pi=$procMap[$ownerPid]
  $name=''; $path=''; $cmdline=''
  if($pi){ $name=[string]$pi.name; $path=[string]$pi.path; $cmdline=[string]$pi.commandLine }
  if(-not $name -and $ownerPid -eq 0){ $name='System Idle Process' }
  [PSCustomObject]@{
    localAddress=[string]$_.LocalAddress
    localPort=[int]$_.LocalPort
    remoteAddress=[string]$_.RemoteAddress
    remotePort=[int]$_.RemotePort
    state=[string]$_.State
    pid=$ownerPid
    process=$name
    path=$path
    commandLine=$cmdline
  }
})
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 6 -Compress`
}

func networkDNSCacheScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$items=@(Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{entry=[string]$_.Entry; name=[string]$_.Name; type=[string]$_.Type; data=[string]$_.Data; timeToLive=[int]$_.TimeToLive}
})
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 5 -Compress`
}

func networkDNSServersScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$items=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{interfaceAlias=[string]$_.InterfaceAlias; serverAddresses=@($_.ServerAddresses)}
})
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 5 -Compress`
}

func networkRoutesScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$items=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix,RouteMetric | Select-Object -First 250 | ForEach-Object {
  [PSCustomObject]@{destinationPrefix=[string]$_.DestinationPrefix; nextHop=[string]$_.NextHop; interfaceAlias=[string]$_.InterfaceAlias; routeMetric=[int]$_.RouteMetric; protocol=[string]$_.Protocol; state=[string]$_.State}
})
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 5 -Compress`
}

func networkProxiesScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$proxy=$null
try { $proxy=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' } catch {}
$winhttp=(netsh winhttp show proxy 2>&1 | Out-String)
$items=@()
if($proxy){
  $items += [PSCustomObject]@{scope='HKCU Internet Settings'; enabled=([int]$proxy.ProxyEnable -eq 1); server=[string]$proxy.ProxyServer; bypass=[string]$proxy.ProxyOverride; raw=''}
}
$items += [PSCustomObject]@{scope='WinHTTP'; enabled=($winhttp -notmatch 'Direct access|直接访问|无代理'); server=''; bypass=''; raw=[string]$winhttp}
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 5 -Compress`
}

func networkModulesScript() string {
	return `$ErrorActionPreference='SilentlyContinue'
$tcp=@(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.State -in @('Established','Listen')} | Select-Object -First 1500)
$pids=@($tcp | ForEach-Object {[int]$_.OwningProcess} | Where-Object { $_ -gt 0 } | Sort-Object -Unique | Select-Object -First 220)
$moduleMap=@{}
foreach($procId in $pids){
  try {
    $p=Get-Process -Id $procId -ErrorAction SilentlyContinue
    if(-not $p){ continue }
    $procName=[string]$p.ProcessName
    if($procName -and $procName -notmatch '\.exe$'){ $procName=$procName + '.exe' }
    $procPath=''
    try { $procPath=[string]$p.Path } catch {}
    $mods=@()
    try { $mods=@($p.Modules) } catch { $mods=@() }
    foreach($m in $mods){
      $dll=[string]$m.FileName
      if([string]::IsNullOrWhiteSpace($dll)){ continue }
      if($dll -notmatch '(?i)\.(dll|ocx|cpl|sys)$'){ continue }
      $key=$dll.ToLowerInvariant()
      if(-not $moduleMap.ContainsKey($key)){
        $moduleMap[$key]=[PSCustomObject]@{dllPath=$dll; pid=$procId; process=$procName; processPath=$procPath; processIds=@{}}
      }
      $moduleMap[$key].processIds[[string]$procId]=$true
    }
  } catch {}
}
$items=@()
$signatureCache=@{}
$sigIndex=0
foreach($item in ($moduleMap.Values | Sort-Object dllPath | Select-Object -First 3000)){
  $status=''; $signer=''
  $dll=[string]$item.dllPath
  $lower=$dll.ToLowerInvariant()
  $shouldCheckSignature=($sigIndex -lt 350) -or ($lower -match '\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\')
  $sigIndex++
  if(-not [string]::IsNullOrWhiteSpace($dll)){
    $key=$dll.ToLowerInvariant()
    if($signatureCache.ContainsKey($key)){
      $sigInfo=$signatureCache[$key]
      $status=[string]$sigInfo.status
      $signer=[string]$sigInfo.signer
    } elseif($shouldCheckSignature) {
      try {
        if(Test-Path -LiteralPath $dll){
          $sig=Get-AuthenticodeSignature -LiteralPath $dll -ErrorAction SilentlyContinue
          if($sig){
            $status=[string]$sig.Status
            if($sig.SignerCertificate){ $signer=[string]$sig.SignerCertificate.Subject }
          }
        } else { $status='NotFound' }
      } catch {}
      $signatureCache[$key]=[PSCustomObject]@{status=$status; signer=$signer}
    }
  }
  $items += [PSCustomObject]@{
    processCount=[int]$item.processIds.Count
    pid=[int]$item.pid
    process=[string]$item.process
    processPath=[string]$item.processPath
    dllPath=[string]$item.dllPath
    signatureStatus=[string]$status
    signer=[string]$signer
  }
}
[PSCustomObject]@{items=@($items)} | ConvertTo-Json -Depth 6 -Compress`
}

func classifyNetworkModule(m *NetworkModuleInfo) {
	m.Risk = "low"
	m.Reasons = []string{"网络进程加载 DLL"}
	path := strings.ToLower(strings.ReplaceAll(m.DLLPath, "/", `\`))
	if strings.Contains(path, `\temp\`) || strings.Contains(path, `\appdata\`) || strings.Contains(path, `\downloads\`) || strings.Contains(path, `\users\public\`) {
		m.Risk = maxRisk(m.Risk, "medium")
		m.Reasons = append(m.Reasons, "DLL 位于用户/临时/下载目录")
	}
	if serviceSignatureInvalid(m.SignatureStatus) {
		m.Risk = maxRisk(m.Risk, "medium")
		m.Reasons = append(m.Reasons, "DLL 签名无效或未知")
	}
	if strings.Contains(path, `\windows\system32\`) && serviceSignatureInvalid(m.SignatureStatus) {
		m.Risk = maxRisk(m.Risk, "high")
		m.Reasons = append(m.Reasons, "System32 DLL 签名异常，需排除 DLL 劫持/替换")
	}
}

func classifyConnection(c *NetworkConnectionInfo) {
	reasons := []string{}
	risk := "low"
	c.External = strings.EqualFold(c.State, "Established") && isExternalIP(c.RemoteAddress)
	if c.External {
		reasons = append(reasons, "外部 ESTABLISHED 连接")
		risk = "medium"
		if strings.TrimSpace(c.Path) == "" {
			reasons = append(reasons, "外联进程未读取到 EXE 路径，需提升权限或在进程页复核")
		}
	}
	if strings.EqualFold(c.State, "Listen") && (c.LocalAddress == "0.0.0.0" || c.LocalAddress == "::" || c.LocalAddress == "[::]") {
		reasons = append(reasons, "全网卡监听端口")
		risk = maxRisk(risk, "low")
	}
	lowerPath := strings.ToLower(c.Path)
	if strings.Contains(lowerPath, `\temp\`) || strings.Contains(lowerPath, `\appdata\`) || strings.Contains(lowerPath, `\users\public\`) || strings.Contains(lowerPath, `\downloads\`) {
		reasons = append(reasons, "进程 EXE 位于用户/临时/下载目录")
		risk = maxRisk(risk, "high")
	}
	if isSpoofedSystemProcess(strings.ToLower(c.Process), lowerPath) {
		reasons = append(reasons, "疑似系统进程名伪装但路径不在 System32/SysWOW64")
		risk = maxRisk(risk, "high")
	}
	if regexpSuspiciousCommand(c.CommandLine) {
		reasons = append(reasons, "进程命令行包含下载/编码/脚本执行特征")
		risk = maxRisk(risk, "high")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "未命中网络风险规则")
	}
	c.Risk = risk
	c.Reasons = reasons
}

func classifyDNSCache(d *DNSCacheInfo) {
	text := strings.ToLower(d.Entry + " " + d.Name + " " + d.Data)
	d.Risk = "low"
	d.Reasons = []string{"DNS 缓存记录"}
	if strings.Contains(text, "dnslog") || strings.Contains(text, "interactsh") || strings.Contains(text, "oast") || strings.Contains(text, "ngrok") || strings.Contains(text, "duckdns") || strings.Contains(text, "no-ip") || strings.Contains(text, "pastebin") || strings.Contains(text, "raw.githubusercontent") {
		d.Risk = "medium"
		d.Reasons = []string{"命中可疑动态域名/OOB/DNSLog 特征"}
	}
}

func classifyDNSServer(d *DNSServerInfo) {
	d.Risk = "low"
	d.Reasons = []string{"DNS 服务器配置"}
	for _, ip := range d.ServerAddresses {
		if isCommonDNSResolverIP(ip) {
			provider := commonDNSResolvers[strings.TrimSpace(strings.Trim(ip, "[]"))]
			if provider == "" {
				provider = "常用 DNS"
			}
			d.Reasons = append(d.Reasons, "常用公共/运营商 DNS："+ip+"（"+provider+"）")
			continue
		}
		if isExternalIP(ip) {
			d.Risk = maxRisk(d.Risk, "medium")
			d.Reasons = append(d.Reasons, "使用未在常用 DNS 白名单中的外部 DNS 服务器："+ip)
		}
	}
}

func classifyRoute(r *RouteInfo) {
	r.Risk = "low"
	r.Reasons = []string{"路由表项"}
	if r.DestinationPrefix != "0.0.0.0/0" && (r.Protocol == "NetMgmt" || strings.Contains(strings.ToLower(r.Protocol), "netmgmt")) {
		r.Risk = "medium"
		r.Reasons = append(r.Reasons, "疑似手工/持久路由")
	}
	if isExternalIP(r.NextHop) && r.DestinationPrefix != "0.0.0.0/0" {
		r.Risk = maxRisk(r.Risk, "medium")
		r.Reasons = append(r.Reasons, "非默认路由指向外部下一跳")
	}
}

func classifyProxy(p *ProxyInfo) {
	p.Risk = "low"
	p.Reasons = []string{"代理配置"}
	if p.Enabled || strings.TrimSpace(p.Server) != "" {
		p.Risk = "medium"
		p.Reasons = append(p.Reasons, "代理已启用或存在代理服务器")
	}
}

func collectPersistenceInventory() (*PersistenceInventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	script := `$ErrorActionPreference='SilentlyContinue'
$fileMetaCache=@{}
function Expand-PathValue([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return '' }
  try { return [Environment]::ExpandEnvironmentVariables($p.Trim('"')) } catch { return $p.Trim('"') }
}
function Extract-Executable([string]$cmd){
  if([string]::IsNullOrWhiteSpace($cmd)){ return '' }
  $v=[Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if($v.StartsWith('"')){
    $m=[regex]::Match($v, '^"([^"]+)"')
    if($m.Success){ return $m.Groups[1].Value }
  }
  $m=[regex]::Match($v, '^(.*?\.(exe|dll|sys|ps1|vbs|js|bat|cmd|lnk))\b', 'IgnoreCase')
  if($m.Success){ return $m.Groups[1].Value.Trim('"') }
  $parts=$v -split '\s+',2
  return $parts[0].Trim('"')
}
function Get-FileMeta([string]$p){
  $expanded=Expand-PathValue $p
  if([string]::IsNullOrWhiteSpace($expanded)){
    return [PSCustomObject]@{path=''; signatureStatus=''; signer=''; companyName=''; fileDescription=''}
  }
  $key=$expanded.ToLowerInvariant()
  if($fileMetaCache.ContainsKey($key)){ return $fileMetaCache[$key] }
  $status='NotFound'; $signer=''; $company=''; $desc=''
  try {
    if(Test-Path -LiteralPath $expanded){
      $item=Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue
      if($item){
        try { $company=[string]$item.VersionInfo.CompanyName; $desc=[string]$item.VersionInfo.FileDescription } catch {}
      }
      try {
        $sig=Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction SilentlyContinue
        if($sig){
          $status=[string]$sig.Status
          if($sig.SignerCertificate){ $signer=[string]$sig.SignerCertificate.Subject }
        }
      } catch {}
    }
  } catch {}
  $meta=[PSCustomObject]@{path=$expanded; signatureStatus=$status; signer=$signer; companyName=$company; fileDescription=$desc}
  $fileMetaCache[$key]=$meta
  return $meta
}
function Get-SourceLabel([string]$location){
  $l=[string]$location
  $l=$l.ToLowerInvariant()
  if($l -match 'wow6432node'){ return 'wow64' }
  if($l -match '^hklm'){ return 'hklm' }
  if($l -match '^hkcu'){ return 'hkcu' }
  return $location
}
$keys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
$autoruns=@()
foreach($k in $keys){
  if(Test-Path $k){
    $props=Get-ItemProperty $k
    foreach($p in $props.PSObject.Properties){
      if($p.Name -notmatch '^PS'){
        $cmd=[string]$p.Value
        $exe=Extract-Executable $cmd
        $meta=Get-FileMeta $exe
        $autoruns += [PSCustomObject]@{
          location=$k
          name=[string]$p.Name
          command=$cmd
          path=[string]$meta.path
          description=[string]$meta.fileDescription
          companyName=[string]$meta.companyName
          signatureStatus=[string]$meta.signatureStatus
          signer=[string]$meta.signer
          enabled=$true
          source=(Get-SourceLabel $k)
        }
      }
    }
  }
}
# === 应急响应专家补充：额外高危自启位置 ===
# AppInit_DLLs（经典 DLL 注入点）
foreach($ad in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')){
  if(Test-Path $ad){
    $ap=Get-ItemProperty $ad -ErrorAction SilentlyContinue
    foreach($vn in @('AppInit_DLLs','LoadAppInit_DLLs')){
      $v=$ap.$vn
      if($null -ne $v -and "$v" -ne '' -and "$v" -ne '0'){
        $cmd=[string]$v
        $exe=if($vn -eq 'LoadAppInit_DLLs'){''}else{Extract-Executable $cmd}
        $meta=Get-FileMeta $exe
        $autoruns += [PSCustomObject]@{ location=$ad; name=$vn; command=$cmd; path=[string]$meta.path; description=[string]$meta.fileDescription; companyName=[string]$meta.companyName; signatureStatus=[string]$meta.signatureStatus; signer=[string]$meta.signer; enabled=$true; source='appinit-dlls' }
      }
    }
  }
}
# Explorer Shell Folders / User Shell Folders（常被滥用）
foreach($sf in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')){
  if(Test-Path $sf){
    $sp=Get-ItemProperty $sf -ErrorAction SilentlyContinue
    foreach($p in $sp.PSObject.Properties){
      if($p.Name -notmatch '^PS' -and "$($p.Value)" -ne ''){
        $cmd=[string]$p.Value
        $exe=Extract-Executable $cmd
        $meta=Get-FileMeta $exe
        if($meta.path -or $cmd -match '\.(exe|dll|ps1|vbs|js|bat|cmd)'){
          $autoruns += [PSCustomObject]@{ location=$sf; name=[string]$p.Name; command=$cmd; path=[string]$meta.path; description=[string]$meta.fileDescription; companyName=[string]$meta.companyName; signatureStatus=[string]$meta.signatureStatus; signer=[string]$meta.signer; enabled=$true; source='shell-folders' }
        }
      }
    }
  }
}
# Active Setup Installed Components 的 StubPath
$asu='HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'
if(Test-Path $asu){
  Get-ChildItem $asu -ErrorAction SilentlyContinue | ForEach-Object {
    $sub=$_.PSPath
    if(Test-Path $sub){
      $ap=Get-ItemProperty $sub -ErrorAction SilentlyContinue
      $stub=[string]$ap.StubPath
      if($stub -ne ''){
        $exe=Extract-Executable $stub
        $meta=Get-FileMeta $exe
        $autoruns += [PSCustomObject]@{ location=$sub; name='StubPath'; command=$stub; path=[string]$meta.path; description=[string]$meta.fileDescription; companyName=[string]$meta.companyName; signatureStatus=[string]$meta.signatureStatus; signer=[string]$meta.signer; enabled=$true; source='active-setup' }
      }
    }
  }
}
$startupPaths=@("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
$startupFiles=Get-ChildItem $startupPaths -Force -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{fullName=[string]$_.FullName; length=[int64]$_.Length; creationTime=$_.CreationTime.ToString('o'); lastWriteTime=$_.LastWriteTime.ToString('o')}
}
$tasks=Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
  $a=($_.Actions | Select-Object -First 1)
  $info=$null
  try { $info=Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue } catch {}
  [PSCustomObject]@{
    taskName=[string]$_.TaskName
    taskPath=[string]$_.TaskPath
    state=[string]$_.State
    author=[string]$_.Author
    description=[string]$_.Description
    execute=[string]$a.Execute
    arguments=[string]$a.Arguments
    lastRunTime=if($info -and $info.LastRunTime){$info.LastRunTime.ToString('o')}else{''}
    nextRunTime=if($info -and $info.NextRunTime){$info.NextRunTime.ToString('o')}else{''}
    enabled=([string]$_.State -ne 'Disabled')
  }
}
$serviceMetaCache=@{}
function Expand-ServicePathValue([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ return '' }
  try { return [Environment]::ExpandEnvironmentVariables($p.Trim('"')) } catch { return $p.Trim('"') }
}
function Extract-ServiceExecutable([string]$cmd){
  if([string]::IsNullOrWhiteSpace($cmd)){ return '' }
  $v=[Environment]::ExpandEnvironmentVariables($cmd.Trim())
  if($v.StartsWith('"')){
    $m=[regex]::Match($v, '^"([^"]+)"')
    if($m.Success){ return $m.Groups[1].Value }
  }
  $m=[regex]::Match($v, '^(.*?\.(exe|dll|sys))\b', 'IgnoreCase')
  if($m.Success){ return $m.Groups[1].Value.Trim('"') }
  $parts=$v -split '\s+',2
  return $parts[0].Trim('"')
}
function Get-ServiceFileMeta([string]$p){
  $expanded=Expand-ServicePathValue $p
  if([string]::IsNullOrWhiteSpace($expanded)){
    return [PSCustomObject]@{path=''; signatureStatus=''; signer=''; companyName=''; fileDescription=''; creationTime=''; lastWriteTime=''}
  }
  $key=$expanded.ToLowerInvariant()
  if($serviceMetaCache.ContainsKey($key)){ return $serviceMetaCache[$key] }
  $status='NotFound'; $signer=''; $company=''; $desc=''; $created=''; $modified=''
  try {
    if(Test-Path -LiteralPath $expanded){
      $item=Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue
      if($item){
        $created=$item.CreationTime.ToString('o')
        $modified=$item.LastWriteTime.ToString('o')
        try { $company=[string]$item.VersionInfo.CompanyName; $desc=[string]$item.VersionInfo.FileDescription } catch {}
      }
      try {
        $sig=Get-AuthenticodeSignature -LiteralPath $expanded -ErrorAction SilentlyContinue
        if($sig){
          $status=[string]$sig.Status
          if($sig.SignerCertificate){ $signer=[string]$sig.SignerCertificate.Subject }
        }
      } catch {}
    }
  } catch {}
  $meta=[PSCustomObject]@{path=$expanded; signatureStatus=$status; signer=$signer; companyName=$company; fileDescription=$desc; creationTime=$created; lastWriteTime=$modified}
  $serviceMetaCache[$key]=$meta
  return $meta
}
$services=Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Sort-Object StartMode,Name | Select-Object -First 500 | ForEach-Object {
  $name=[string]$_.Name
  $exe=Extract-ServiceExecutable ([string]$_.PathName)
  $serviceDll=''
  $failureCommand=''
  try {
    $param=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name\Parameters" -ErrorAction SilentlyContinue
    if($param -and $param.ServiceDll){ $serviceDll=Expand-ServicePathValue ([string]$param.ServiceDll) }
  } catch {}
  try {
    $svcKey=Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue
    if($svcKey -and $svcKey.FailureCommand){ $failureCommand=[string]$svcKey.FailureCommand }
  } catch {}
  $exeMeta=Get-ServiceFileMeta $exe
  $dllMeta=Get-ServiceFileMeta $serviceDll
  [PSCustomObject]@{
    name=$name; displayName=[string]$_.DisplayName; state=[string]$_.State; startMode=[string]$_.StartMode; pathName=[string]$_.PathName; executablePath=[string]$exeMeta.path; serviceDll=[string]$serviceDll; failureCommand=[string]$failureCommand; serviceType=[string]$_.ServiceType; processId=[int]$_.ProcessId; startName=[string]$_.StartName;
    signatureStatus=[string]$exeMeta.signatureStatus; signer=[string]$exeMeta.signer; companyName=[string]$exeMeta.companyName; fileDescription=[string]$exeMeta.fileDescription; fileCreationTime=[string]$exeMeta.creationTime; fileLastWriteTime=[string]$exeMeta.lastWriteTime;
    serviceDllSignatureStatus=[string]$dllMeta.signatureStatus; serviceDllSigner=[string]$dllMeta.signer; serviceDllCompanyName=[string]$dllMeta.companyName; serviceDllCreationTime=[string]$dllMeta.creationTime; serviceDllLastWriteTime=[string]$dllMeta.lastWriteTime
  }
}
$wmi=@()
try { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $wmi += [PSCustomObject]@{kind='EventFilter'; name=[string]$_.Name; query=[string]$_.Query; command=''} } } catch {}
try { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $wmi += [PSCustomObject]@{kind='CommandLineEventConsumer'; name=[string]$_.Name; query=''; command=[string]$_.CommandLineTemplate} } } catch {}
try { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $wmi += [PSCustomObject]@{kind='ActiveScriptEventConsumer'; name=[string]$_.Name; query=''; command=[string]$_.ScriptText} } } catch {}
[PSCustomObject]@{autoruns=@($autoruns); startupFiles=@($startupFiles); tasks=@($tasks); services=@($services); wmi=@($wmi)} | ConvertTo-Json -Depth 6 -Compress`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("persistence inventory timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("persistence inventory failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var inv PersistenceInventory
	if err := json.Unmarshal(out, &inv); err != nil {
		return nil, fmt.Errorf("parse persistence inventory failed: %v", err)
	}
	inv.Timestamp = time.Now().Format(time.RFC3339)
	if inv.Autoruns == nil {
		inv.Autoruns = []AutorunInfo{}
	}
	if inv.StartupFiles == nil {
		inv.StartupFiles = []StartupFileInfo{}
	}
	if inv.Tasks == nil {
		inv.Tasks = []ScheduledTaskInfo{}
	}
	if inv.Services == nil {
		inv.Services = []ServiceInfo{}
	}
	if inv.WMI == nil {
		inv.WMI = []WMIInfo{}
	}
	for i := range inv.Autoruns {
		classifyAutorun(&inv.Autoruns[i])
	}
	for i := range inv.StartupFiles {
		classifyStartupFile(&inv.StartupFiles[i])
	}
	for i := range inv.Tasks {
		classifyScheduledTask(&inv.Tasks[i])
	}
	for i := range inv.Services {
		classifyService(&inv.Services[i])
	}
	for i := range inv.WMI {
		classifyWMI(&inv.WMI[i])
	}
	sort.SliceStable(inv.Autoruns, func(i, j int) bool { return severityRank(inv.Autoruns[i].Risk) > severityRank(inv.Autoruns[j].Risk) })
	sort.SliceStable(inv.Tasks, func(i, j int) bool { return severityRank(inv.Tasks[i].Risk) > severityRank(inv.Tasks[j].Risk) })
	sort.SliceStable(inv.Services, func(i, j int) bool { return severityRank(inv.Services[i].Risk) > severityRank(inv.Services[j].Risk) })
	return &inv, nil
}

func classifyAutorun(a *AutorunInfo) {
	if strings.TrimSpace(a.Path) == "" {
		a.Path = extractExecutablePath(a.Command)
	}
	a.Risk = "low"
	a.Reasons = []string{"注册表启动项"}
	lower := strings.ToLower(a.Command)
	if strings.Contains(lower, `\appdata\local\programs\`) || strings.Contains(lower, `\appdata\roaming\`) {
		a.Risk = maxRisk(a.Risk, "medium")
		a.Reasons = append(a.Reasons, "用户目录自启动项，需结合业务白名单确认")
	}
	if strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\users\public\`) || strings.Contains(lower, `\downloads\`) || strings.Contains(lower, `\$recycle.bin\`) {
		a.Risk = maxRisk(a.Risk, "high")
		a.Reasons = append(a.Reasons, "启动命令指向临时/下载/公共可写目录")
	}
	if regexpSuspiciousCommand(a.Command) {
		a.Risk = maxRisk(a.Risk, "high")
		a.Reasons = append(a.Reasons, "启动命令包含脚本/下载/编码执行链")
	}
}

func classifyStartupFile(f *StartupFileInfo) {
	f.Risk = "low"
	f.Reasons = []string{"启动文件夹文件"}
	lower := strings.ToLower(f.FullName)
	if strings.HasSuffix(lower, ".ps1") || strings.HasSuffix(lower, ".vbs") || strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".bat") || strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".lnk") {
		f.Risk = "medium"
		f.Reasons = append(f.Reasons, "启动文件夹中存在脚本或快捷方式")
	}
}

func classifyScheduledTask(t *ScheduledTaskInfo) {
	t.Risk = "low"
	t.Reasons = []string{"计划任务"}
	cmd := t.Execute + " " + t.Arguments
	if isMicrosoftWindowsScheduledTask(t) {
		t.Reasons = append(t.Reasons, "Microsoft Windows 系统计划任务基线，默认按低风险处理")
	}
	if taskCommandHasHighRiskIndicators(cmd) {
		t.Risk = "high"
		t.Reasons = append(t.Reasons, "计划任务执行链包含下载/编码/用户目录/脚本宿主高危特征")
	}
}

func isMicrosoftWindowsScheduledTask(t *ScheduledTaskInfo) bool {
	taskPath := strings.ToLower(strings.ReplaceAll(t.TaskPath, "/", `\`))
	author := strings.ToLower(t.Author)
	execute := strings.ToLower(strings.ReplaceAll(t.Execute, "/", `\`))
	return strings.HasPrefix(taskPath, `\microsoft\windows\`) &&
		strings.Contains(author, "microsoft") &&
		(strings.Contains(execute, `%windir%\system32\`) || strings.Contains(execute, `\windows\system32\`))
}

func taskCommandHasHighRiskIndicators(cmd string) bool {
	lower := strings.ToLower(cmd)
	highTerms := []string{
		"-enc", "encodedcommand", "downloadstring", "invoke-expression", " frombase64string",
		"http://", "https://", `\temp\`, `\appdata\`, `\users\public\`, `\downloads\`, `\$recycle.bin\`,
		"powershell", "pwsh", "mshta", "wscript", "cscript", "certutil", "bitsadmin",
	}
	for _, term := range highTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	if strings.Contains(lower, "rundll32") || strings.Contains(lower, "regsvr32") {
		return strings.Contains(lower, "http") || strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\appdata\`) || strings.Contains(lower, `\users\public\`) || strings.Contains(lower, `\downloads\`)
	}
	return false
}

func classifyService(s *ServiceInfo) {
	s.Risk = "low"
	s.Reasons = []string{"服务项"}
	exePath := s.ExecutablePath
	if strings.TrimSpace(exePath) == "" {
		exePath = extractExecutablePath(s.PathName)
	}
	serviceDLL := strings.TrimSpace(s.ServiceDLL)
	exeLower := normalizeWindowsPath(exePath)
	dllLower := normalizeWindowsPath(serviceDLL)
	isWindowsService := isWindowsSystemServiceName(s.Name)
	exeTrustedPath := isTrustedWindowsServicePath(exePath)
	dllTrustedPath := serviceDLL == "" || isTrustedWindowsServicePath(serviceDLL)
	isSvchostService := strings.Contains(strings.ToLower(s.PathName), "svchost.exe") || strings.HasSuffix(exeLower, `\svchost.exe`)

	if serviceDLL != "" {
		s.Reasons = append(s.Reasons, "已解析 svchost/服务 DLL："+serviceDLL)
	}
	if isWindowsService && exeTrustedPath && dllTrustedPath && serviceSignedByMicrosoft(s.SignatureStatus, s.Signer) && (serviceDLL == "" || serviceSignedByMicrosoft(s.ServiceDLLSignatureStatus, s.ServiceDLLSigner)) {
		s.Reasons = append(s.Reasons, "Windows 系统服务基线，路径和微软签名匹配")
	} else if isWindowsService {
		s.Reasons = append(s.Reasons, "Windows 系统服务名，已结合路径、签名和 ServiceDll 复核")
	}

	combined := strings.ToLower(strings.Join([]string{s.PathName, exePath, serviceDLL, s.FailureCommand}, " "))
	if strings.Contains(combined, `\temp\`) || strings.Contains(combined, `\appdata\`) || strings.Contains(combined, `\users\public\`) || strings.Contains(combined, `\downloads\`) || strings.Contains(combined, `\$recycle.bin\`) {
		s.Risk = "high"
		s.Reasons = append(s.Reasons, "服务主程序/ServiceDll/失败恢复命令位于用户可写或临时目录")
	}
	if regexpSuspiciousCommand(s.PathName) || regexpSuspiciousCommand(s.FailureCommand) {
		s.Risk = "high"
		s.Reasons = append(s.Reasons, "服务命令或失败恢复命令包含脚本、下载、编码执行特征")
	}
	if hasUnquotedServiceExecutablePath(s.PathName) {
		s.Risk = maxRisk(s.Risk, "medium")
		s.Reasons = append(s.Reasons, "服务可执行文件路径包含空格且未加引号")
	}

	if isWindowsService {
		if exePath != "" && !exeTrustedPath {
			s.Risk = maxRisk(s.Risk, "high")
			s.Reasons = append(s.Reasons, "服务名属于 Windows 系统服务，但主程序路径不在可信系统目录，疑似伪装")
		}
		if serviceDLL != "" && !dllTrustedPath {
			s.Risk = maxRisk(s.Risk, "high")
			s.Reasons = append(s.Reasons, "Windows 系统服务的 ServiceDll 不在可信系统目录，疑似 DLL 注入/替换")
		}
		if exePath != "" && serviceSignatureInvalid(s.SignatureStatus) {
			s.Risk = maxRisk(s.Risk, "high")
			s.Reasons = append(s.Reasons, "Windows 系统服务主程序签名无效或未签名")
		} else if exePath != "" && !serviceSignedByMicrosoft(s.SignatureStatus, s.Signer) {
			s.Risk = maxRisk(s.Risk, "medium")
			s.Reasons = append(s.Reasons, "Windows 系统服务主程序未确认微软签名，需人工复核")
		}
		if serviceDLL != "" && serviceSignatureInvalid(s.ServiceDLLSignatureStatus) {
			s.Risk = maxRisk(s.Risk, "high")
			s.Reasons = append(s.Reasons, "Windows 系统服务 ServiceDll 签名无效或未签名，疑似 DLL 注入/替换")
		} else if serviceDLL != "" && !serviceSignedByMicrosoft(s.ServiceDLLSignatureStatus, s.ServiceDLLSigner) {
			s.Risk = maxRisk(s.Risk, "medium")
			s.Reasons = append(s.Reasons, "Windows 系统服务 ServiceDll 未确认微软签名，需人工复核")
		}
	}

	if !isWindowsService && isSvchostService {
		s.Risk = maxRisk(s.Risk, "medium")
		s.Reasons = append(s.Reasons, "非 Windows 基线服务使用 svchost 宿主，需重点核对 ServiceDll 来源")
		if serviceDLL != "" && (!dllTrustedPath || serviceSignatureInvalid(s.ServiceDLLSignatureStatus)) {
			s.Risk = maxRisk(s.Risk, "high")
			s.Reasons = append(s.Reasons, "非基线 svchost 服务的 ServiceDll 路径或签名异常")
		}
	}

	if !isWindowsService && isWindowsDirectoryPath(exeLower) && serviceSignatureInvalid(s.SignatureStatus) {
		s.Risk = maxRisk(s.Risk, "medium")
		s.Reasons = append(s.Reasons, "非系统服务位于 Windows/System32 目录且签名异常，System32 路径不能直接视为安全")
	}
	if serviceDLL != "" && isWindowsDirectoryPath(dllLower) && serviceSignatureInvalid(s.ServiceDLLSignatureStatus) {
		s.Risk = maxRisk(s.Risk, "medium")
		s.Reasons = append(s.Reasons, "ServiceDll 位于 Windows/System32 目录但签名异常，需排查 DLL 替换/注入")
	}
	if strings.HasSuffix(exeLower, ".sys") && serviceSignatureInvalid(s.SignatureStatus) {
		s.Risk = maxRisk(s.Risk, "high")
		s.Reasons = append(s.Reasons, "驱动服务文件签名异常，需排查 Rootkit/内核驱动木马")
	}
	if (isWindowsDirectoryPath(exeLower) || isWindowsDirectoryPath(dllLower)) && (isRecentServiceFileTime(s.FileCreationTime, 7) || isRecentServiceFileTime(s.FileLastWriteTime, 7) || isRecentServiceFileTime(s.ServiceDLLCreationTime, 7) || isRecentServiceFileTime(s.ServiceDLLLastWriteTime, 7)) {
		if serviceSignatureInvalid(s.SignatureStatus) || serviceSignatureInvalid(s.ServiceDLLSignatureStatus) || (!isWindowsService && !serviceSignedByMicrosoft(s.SignatureStatus, s.Signer)) {
			s.Risk = maxRisk(s.Risk, "medium")
			s.Reasons = append(s.Reasons, "Windows/System32 内服务文件近期创建或修改且签名/来源未确认，需结合补丁和安装记录复核")
		}
	}
}

func normalizeWindowsPath(pathName string) string {
	p := strings.ToLower(strings.Trim(pathName, `" `))
	return strings.ReplaceAll(p, "/", `\`)
}

func serviceSignatureInvalid(status string) bool {
	st := strings.ToLower(strings.TrimSpace(status))
	return st != "" && st != "valid"
}

func serviceSignedByMicrosoft(status, signer string) bool {
	st := strings.ToLower(strings.TrimSpace(status))
	if st != "" && st != "valid" {
		return false
	}
	return strings.Contains(strings.ToLower(signer), "microsoft")
}

func isWindowsDirectoryPath(pathName string) bool {
	p := normalizeWindowsPath(pathName)
	return strings.Contains(p, `\windows\system32\`) || strings.Contains(p, `\windows\syswow64\`) || strings.Contains(p, `\windows\servicing\`) || strings.Contains(p, `\windows\winsxs\`)
}

func isRecentServiceFileTime(value string, days int) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return false
	}
	return time.Since(parsed) >= 0 && time.Since(parsed) <= time.Duration(days)*24*time.Hour
}

var windowsSystemServiceNames = map[string]bool{
	"aarsvc": true, "ajrouter": true, "alg": true, "appidsvc": true,
	"appinfo": true, "appmgmt": true, "appreadiness": true, "appvclient": true,
	"appxsvc": true, "assignedaccessmanagersvc": true, "audioendpointbuilder": true, "audiosrv": true,
	"autotimesvc": true, "axinstsv": true, "bcastdvruserservice": true, "bdesvc": true,
	"bfe": true, "bits": true, "bluetoothuserservice": true, "brokerinfrastructure": true,
	"browser": true, "btagservice": true, "bthavctpsvc": true, "bthserv": true,
	"camsvc": true, "captureservice": true, "cbdhsvc": true, "cdpsvc": true,
	"cdpusersvc": true, "certpropsvc": true, "clipsvc": true, "cloudbackuprestoresvc": true,
	"comsysapp": true, "consentuxusersvc": true, "coremessagingregistrar": true, "credentialenrollmentmanagerusersvc": true,
	"cryptsvc": true, "cscservice": true, "dcomlaunch": true, "dcpsvc": true,
	"defragsvc": true, "deviceassociationbroker": true, "deviceassociationbrokersvc": true, "deviceassociationservice": true,
	"deviceinstall": true, "devicepickersvc": true, "devicepickerusersvc": true, "devicesflowusersvc": true,
	"devquerybroker": true, "dhcp": true, "diagnosticshub.standardcollector.service": true, "diagsvc": true,
	"diagtrack": true, "dialogblockingservice": true, "dispbrokerdesktopsvc": true, "displayenhancementservice": true,
	"dmenrollmentsvc": true, "dmwappushservice": true, "dnscache": true, "dosvc": true,
	"dot3svc": true, "dps": true, "dsmsvc": true, "dssvc": true,
	"dusmsvc": true, "eaphost": true, "edgeupdate": true, "edgeupdatem": true,
	"efs": true, "embeddedmode": true, "entappsvc": true, "eventlog": true,
	"eventsystem": true, "fax": true, "fdphost": true, "fdrespub": true,
	"fhsvc": true, "fontcache": true, "frameserver": true, "gameinputsvc": true,
	"gpsvc": true, "graphicsperfsvc": true, "hidserv": true, "hvhost": true,
	"icssvc": true, "ikeext": true, "installservice": true, "inventorysvc": true,
	"iphlpsvc": true, "ipxlatcfgsvc": true, "keyiso": true, "kpssvc": true,
	"ktmrm": true, "lanmanserver": true, "lanmanworkstation": true, "lfsvc": true,
	"licensemanager": true, "lltdsvc": true, "lmhosts": true, "lpxsvc": true,
	"lsm": true, "lxpsvc": true, "mapsbroker": true, "mcpmanagementservice": true,
	"mdcoresvc": true, "messagingservice": true, "microsoftedgeelevationservice": true, "mixedrealityopenxrsvc": true,
	"mpssvc": true, "msdtc": true, "msiscsi": true, "msiserver": true,
	"mskeyboardfilter": true, "naturalauthentication": true, "ncasvc": true, "ncbservice": true,
	"ncdautosetup": true, "netlogon": true, "netman": true, "netprofm": true,
	"netsetupsvc": true, "nettcpportsharing": true, "ngcctnrsvc": true, "ngcsvc": true,
	"nlasvc": true, "npsmsvc": true, "nsi": true, "onesyncsvc": true,
	"p2pimsvc": true, "p2psvc": true, "p9rdrservice": true, "p9rdrsvc": true,
	"pcasvc": true, "peerdistsvc": true, "penservice": true, "perceptionsimulation": true,
	"perfhost": true, "phonesvc": true, "pimindexmaintenancesvc": true, "pla": true,
	"plugplay": true, "pnrpautoreg": true, "pnrpsvc": true, "policyagent": true,
	"power": true, "printnotify": true, "printworkflowusersvc": true, "profsvc": true,
	"pushtoinstall": true, "qwave": true, "rasauto": true, "rasman": true,
	"remoteaccess": true, "remoteregistry": true, "retaildemo": true, "rmsvc": true,
	"rpceptmapper": true, "rpclocator": true, "rpcss": true, "rsopprov": true,
	"sacsvr": true, "samss": true, "scardsvr": true, "scdeviceenum": true,
	"schedule": true, "scpolicysvc": true, "sdrsvc": true, "seclogon": true,
	"securityhealthservice": true, "semgrsvc": true, "sens": true, "sense": true,
	"sensordataservice": true, "sensorservice": true, "sensrsvc": true, "sessionenv": true,
	"sgrmbroker": true, "sharedaccess": true, "sharedrealitysvc": true, "shellhwdetection": true,
	"shpamsvc": true, "smphost": true, "smsrouter": true, "snmptrap": true,
	"spectrum": true, "spooler": true, "sppsvc": true, "ssdpsrv": true,
	"ssh-agent": true, "sshd": true, "sstpsvc": true, "staterepository": true,
	"stisvc": true, "storsvc": true, "svsvc": true, "swprv": true,
	"sysmain": true, "systemeventsbroker": true, "tabletinputservice": true, "tapisrv": true,
	"termservice": true, "textinputmanagementservice": true, "themes": true, "tieringengineservice": true,
	"tiledatamodelsvc": true, "timebrokersvc": true, "tokenbroker": true, "trkwks": true,
	"troubleshootingsvc": true, "trustedinstaller": true, "tzautoupdate": true, "ualsvc": true,
	"udkusersvc": true, "uevagentservice": true, "ui0detect": true, "umrdpservice": true,
	"unistoresvc": true, "upnphost": true, "userdatasvc": true, "usermanager": true,
	"usosvc": true, "vacsvc": true, "vaultsvc": true, "vds": true,
	"vmicguestinterface": true, "vmicheartbeat": true, "vmickvpexchange": true, "vmicrdv": true,
	"vmicshutdown": true, "vmictimesync": true, "vmicvmsession": true, "vmicvss": true,
	"vss": true, "w32time": true, "w3logsvc": true, "w3svc": true,
	"waasmedicsvc": true, "walletservice": true, "warpjitsvc": true, "was": true,
	"wbengine": true, "wbiosrvc": true, "wcmsvc": true, "wcncsvc": true,
	"wdiservicehost": true, "wdisystemhost": true, "wdnissvc": true, "webclient": true,
	"webthreatdefsvc": true, "webthreatdefusersvc": true, "wecsvc": true, "wephostsvc": true,
	"wercplsupport": true, "wersvc": true, "wfdsconmgrsvc": true, "wiarpc": true,
	"windefend": true, "winhttpautoproxysvc": true, "winmgmt": true, "winrm": true,
	"wisvc": true, "wlansvc": true, "wlidsvc": true, "wlpasvc": true,
	"wmansvc": true, "wmiapsrv": true, "wmpnetworksvc": true, "workfolderssvc": true,
	"wpcmonsvc": true, "wpdbusenum": true, "wpnservice": true, "wpnuserservice": true,
	"wscsvc": true, "wsearch": true, "wuauserv": true, "wudfsvc": true,
	"wwansvc": true, "xblauthmanager": true, "xblgamesave": true, "xboxgipsvc": true,
	"xboxnetapisvc": true,
}

var windowsPerUserServiceNames = map[string]bool{
	"aarsvc":                             true,
	"bcastdvruserservice":                true,
	"bluetoothuserservice":               true,
	"captureservice":                     true,
	"cbdhsvc":                            true,
	"cdpusersvc":                         true,
	"cloudbackuprestoresvc":              true,
	"consentuxusersvc":                   true,
	"credentialenrollmentmanagerusersvc": true,
	"deviceassociationbrokersvc":         true,
	"devicepickersvc":                    true,
	"devicepickerusersvc":                true,
	"devicesflowusersvc":                 true,
	"messagingservice":                   true,
	"npsmsvc":                            true,
	"onesyncsvc":                         true,
	"p9rdrservice":                       true,
	"penservice":                         true,
	"pimindexmaintenancesvc":             true,
	"printworkflowusersvc":               true,
	"udkusersvc":                         true,
	"unistoresvc":                        true,
	"userdatasvc":                        true,
	"webthreatdefusersvc":                true,
	"wpnuserservice":                     true,
}

func isWindowsSystemServiceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if windowsSystemServiceNames[n] {
		return true
	}
	if idx := strings.LastIndex(n, "_"); idx > 0 {
		base := n[:idx]
		return windowsPerUserServiceNames[base] || windowsSystemServiceNames[base]
	}
	return false
}

func isTrustedWindowsServicePath(pathName string) bool {
	exe := strings.ToLower(extractExecutablePath(pathName))
	if exe == "" {
		return true
	}
	exe = strings.ReplaceAll(exe, "/", `\`)
	trustedParts := []string{
		`\windows\system32\`,
		`\windows\syswow64\`,
		`\windows\servicing\`,
		`\windows\winsxs\`,
		`\windows\microsoft.net\`,
		`\program files\windows defender\`,
		`\program files\windows defender advanced threat protection\`,
		`\programdata\microsoft\windows defender\`,
		`\program files\microsoft\edgeupdate\`,
		`\program files (x86)\microsoft\edgeupdate\`,
		`\program files\windowsapps\microsoft.`,
		`\program files\windowsapps\microsoftwindows.`,
	}
	for _, part := range trustedParts {
		if strings.Contains(exe, part) {
			return true
		}
	}
	return false
}
func hasUnquotedServiceExecutablePath(pathName string) bool {
	trimmed := strings.TrimSpace(pathName)
	if trimmed == "" || strings.HasPrefix(trimmed, `"`) {
		return false
	}
	exePath := extractExecutablePath(trimmed)
	if exePath == "" || !strings.Contains(strings.ToLower(exePath), ".exe") {
		return false
	}
	return strings.Contains(exePath, " ")
}
func classifyWMI(w *WMIInfo) {
	w.Risk = "medium"
	w.Reasons = []string{"WMI 永久事件订阅对象，需确认业务基线"}
	if regexpSuspiciousCommand(w.Command) {
		w.Risk = "high"
		w.Reasons = append(w.Reasons, "WMI Consumer 包含脚本/下载/编码执行特征")
	}
}

func regexpSuspiciousCommand(s string) bool {
	lower := strings.ToLower(s)
	terms := []string{"-enc", "encodedcommand", "downloadstring", "invoke-expression", " iex ", "frombase64string", "mshta", "regsvr32", "certutil", "bitsadmin", "rundll32", "wscript", "cscript", "powershell"}
	for _, t := range terms {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func extractExecutablePath(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if strings.HasPrefix(command, `"`) {
		rest := strings.TrimPrefix(command, `"`)
		if i := strings.Index(rest, `"`); i >= 0 {
			return rest[:i]
		}
	}
	lower := strings.ToLower(command)
	for _, ext := range []string{".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd"} {
		if i := strings.Index(lower, ext); i >= 0 {
			return strings.Trim(command[:i+len(ext)], `"`)
		}
	}
	return strings.Fields(command)[0]
}
