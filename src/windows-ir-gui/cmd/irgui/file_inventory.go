package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

type FileEvidenceInfo struct {
	Path          string     `json:"path"`
	Name          string     `json:"name"`
	Length        int64      `json:"length"`
	CreationTime  string     `json:"creationTime"`
	LastWriteTime string     `json:"lastWriteTime"`
	Risk          string     `json:"risk"`
	Reasons       StringList `json:"reasons"`
}

type ADSEvidenceInfo struct {
	Path          string     `json:"path"`
	Stream        string     `json:"stream"`
	Length        int64      `json:"length"`
	LastWriteTime string     `json:"lastWriteTime"`
	Risk          string     `json:"risk"`
	Reasons       StringList `json:"reasons"`
}

type WebLogEvidenceInfo struct {
	Path          string     `json:"path"`
	Line          string     `json:"line"`
	LastWriteTime string     `json:"lastWriteTime"`
	Risk          string     `json:"risk"`
	Reasons       StringList `json:"reasons"`
}

type FileInventory struct {
	TempFiles         []FileEvidenceInfo   `json:"tempFiles"`
	DownloadFiles     []FileEvidenceInfo   `json:"downloadFiles"`
	RecentExecutables []FileEvidenceInfo   `json:"recentExecutables"`
	PrefetchFiles     []FileEvidenceInfo   `json:"prefetchFiles"`
	ADS               []ADSEvidenceInfo    `json:"ads"`
	WebLogs           []WebLogEvidenceInfo `json:"webLogs"`
	Timestamp         string               `json:"timestamp"`
}

type StringList []string

func (s *StringList) UnmarshalJSON(b []byte) error {
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one == "" {
			*s = nil
		} else {
			*s = []string{one}
		}
		return nil
	}
	*s = nil
	return nil
}

func registerFilesAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		days := atoiDefault(r.URL.Query().Get("days"), 7)
		if days <= 0 || days > 90 {
			days = 7
		}
		item, err := collectFileInventory(days)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, item)
	})
}

func collectFileInventory(days int) (*FileInventory, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	script := fileInventoryScript(days)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	var inv FileInventory
	if err := json.Unmarshal(out, &inv); err != nil {
		return nil, err
	}
	inv.Timestamp = time.Now().Format(time.RFC3339)
	return &inv, nil
}

func fileInventoryScript(days int) string {
	return `
$days=` + strconv.Itoa(days) + `
function New-Reasons([string]$Path,[string]$Name) {
  $r=@()
  $lower=(($Path+' '+$Name).ToLower())
  if($lower -match '\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\') { $r+='用户/临时/下载目录文件' }
  if($lower -match '\.(exe|dll|ps1|vbs|js|bat|cmd)$') { $r+='脚本或可执行文件' }
  if($lower -match '(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)') { $r+='名称包含常见脚本宿主或 LOLBin' }
  if($r.Count -eq 0) { $r+='文件取证样本' }
  return @($r)
}
function New-Risk([string]$Path,[string]$Name) {
  $lower=(($Path+' '+$Name).ToLower())
  if($lower -match '\.(ps1|vbs|js|bat|cmd)$') { return 'medium' }
  if($lower -match '\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\') {
    if($lower -match '\.(exe|dll)$') { return 'medium' }
  }
  return 'low'
}
function To-FileObj($f) {
  [PSCustomObject]@{
    path=[string]$f.FullName
    name=[string]$f.Name
    length=[int64]$f.Length
    creationTime=if($f.CreationTime){$f.CreationTime.ToString('o')}else{''}
    lastWriteTime=if($f.LastWriteTime){$f.LastWriteTime.ToString('o')}else{''}
    risk=New-Risk $f.FullName $f.Name
    reasons=New-Reasons $f.FullName $f.Name
  }
}
$tempRoots=@($env:TEMP, "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp") | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$downloadRoot=Join-Path $env:USERPROFILE 'Downloads'
$startupUser=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
$startupAll=Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
$execRoots=@($env:TEMP, "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp", $downloadRoot, $startupUser, $startupAll, $env:PUBLIC) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
$tempFiles=@($tempRoots | ForEach-Object { Get-ChildItem $_ -Force -File -ErrorAction SilentlyContinue } | Sort-Object LastWriteTime -Descending | Select-Object -First 120 | ForEach-Object { To-FileObj $_ })
$downloadFiles=@()
if(Test-Path $downloadRoot){ $downloadFiles=@(Get-ChildItem $downloadRoot -Force -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 120 | ForEach-Object { To-FileObj $_ }) }
$recentExecutables=@($execRoots | ForEach-Object { Get-ChildItem $_ -Force -File -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$days) -and $_.Extension -match '(?i)\.(exe|dll|ps1|vbs|js|bat|cmd)$'} } | Sort-Object LastWriteTime -Descending | Select-Object -First 180 | ForEach-Object { To-FileObj $_ })
$prefetchFiles=@()
if(Test-Path "$env:WINDIR\Prefetch"){ $prefetchFiles=@(Get-ChildItem "$env:WINDIR\Prefetch" -Force -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 160 | ForEach-Object { To-FileObj $_ }) }
$ads=@()
foreach($root in @($tempRoots + @($downloadRoot))) {
  if(-not (Test-Path $root)) { continue }
  Get-ChildItem $root -Force -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 200 | ForEach-Object {
    $file=$_
    Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -and $_.Stream -ne ':$DATA' -and $_.Stream -ne '$DATA' } | ForEach-Object {
      $ads += [PSCustomObject]@{
        path=[string]$file.FullName
        stream=[string]$_.Stream
        length=[int64]$_.Length
        lastWriteTime=if($file.LastWriteTime){$file.LastWriteTime.ToString('o')}else{''}
        risk='medium'
        reasons=@('发现备用数据流 ADS')
      }
    }
  }
}
$webLogs=@()
$roots=@("$env:SystemDrive\inetpub\logs\LogFiles", "$env:SystemRoot\System32\LogFiles")
foreach($root in $roots){
  if(Test-Path $root){
    Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20 | ForEach-Object {
      $file=$_
      Get-Content $file.FullName -Tail 300 -ErrorAction SilentlyContinue | Where-Object { $_ -match '(?i)\b(POST|GET)\b|cmd=|exec=|shell=|upload|\.php|\.jsp|\.aspx|base64|powershell|whoami' } | Select-Object -First 30 | ForEach-Object {
        $line=[string]$_
        $risk=if($line -match '(?i)cmd=|exec=|shell=|base64|powershell|whoami|upload'){ 'high' } else { 'low' }
        $webLogs += [PSCustomObject]@{path=[string]$file.FullName; line=$line; lastWriteTime=if($file.LastWriteTime){$file.LastWriteTime.ToString('o')}else{''}; risk=$risk; reasons=@('Web 日志关键请求')}
      }
    }
  }
}
[PSCustomObject]@{
  tempFiles=@($tempFiles)
  downloadFiles=@($downloadFiles)
  recentExecutables=@($recentExecutables)
  prefetchFiles=@($prefetchFiles)
  ads=@($ads | Select-Object -First 120)
  webLogs=@($webLogs | Select-Object -First 160)
  timestamp=(Get-Date).ToString('o')
} | ConvertTo-Json -Depth 6 -Compress
`
}
