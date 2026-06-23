package main

import (
	"fmt"
	"strings"
)

func windowsTasks(opt ScanOptions) []Task {
	days := opt.LookbackDays
	fileDays := days
	if fileDays <= 0 {
		fileDays = 7
	}
	maxEvents := opt.MaxEvents
	timeout := opt.TimeoutSec
	tasks := []Task{
		{ID: "basic", Title: "基础信息与当前权限", Category: "资产与环境", Skill: "emergency-response", Timeout: timeout, Notes: "记录当前时间戳、主机名、权限和补丁基线。", Command: `
$ErrorActionPreference='Continue'
"=== Time ==="; Get-Date -Format o
"=== Host ==="; hostname
"=== Current User ==="; whoami; whoami /groups; whoami /priv
"=== Computer Info ==="; Get-ComputerInfo | Select-Object CsName,WindowsProductName,WindowsVersion,OsArchitecture,OsBuildNumber,CsDomain,CsUserName,TimeZone | Format-List
"=== IP Config ==="; ipconfig /all
"=== SystemInfo ==="; systeminfo
`},
		{ID: "users", Title: "账户、会话与管理员组", Category: "账户审计", Skill: "emergency-response", Timeout: timeout, Notes: "排查隐藏账户、管理员组异常成员、当前会话。", Command: `
$ErrorActionPreference='Continue'
"=== query user ==="; query user 2>&1
"=== query session ==="; query session 2>&1
"=== net user ==="; net user
"=== administrators ==="; net localgroup administrators
"=== local users ==="; Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,PasswordRequired,UserMayChangePassword,SID | Format-Table -AutoSize
"=== local groups ==="; Get-LocalGroup | Format-Table -AutoSize
"=== WMIC user full ==="; wmic useraccount list full
`},
		{ID: "processes", Title: "进程、命令行与启动时间", Category: "进程排查", Skill: "emergency-response", Timeout: timeout, Notes: "关注临时目录、AppData、EncodedCommand、脚本宿主和异常父子链。", Command: `
$ErrorActionPreference='Continue'
"=== Top CPU ==="; Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Id,ProcessName,CPU,Path | Format-Table -AutoSize
"=== Top Memory ==="; Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 Id,ProcessName,@{N='WorkingSetMB';E={[math]::Round($_.WorkingSet64/1MB,2)}},Path | Format-Table -AutoSize
"=== Win32_Process CSV ==="; Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate | ConvertTo-Csv -NoTypeInformation
"=== tasklist svc ==="; tasklist /svc
"=== tasklist verbose ==="; tasklist /v
`},
		{ID: "network", Title: "网络连接、监听端口与代理", Category: "网络连接", Skill: "emergency-response", Timeout: timeout, Notes: "重点关注 ESTABLISHED 外联、异常监听端口和代理配置。", Command: `
$ErrorActionPreference='Continue'
"=== netstat ==="; netstat -ano
"=== TCP connections with process ==="; Get-NetTCPConnection -ErrorAction SilentlyContinue | Sort-Object State,LocalPort | ForEach-Object { $p=$null; try{$p=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}catch{}; [PSCustomObject]@{Local=$_.LocalAddress+':'+$_.LocalPort;Remote=$_.RemoteAddress+':'+$_.RemotePort;State=$_.State;PID=$_.OwningProcess;Process=$p} } | Format-Table -AutoSize
"=== NetTCP Owning Process Detail ==="; Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {$_.State -in @('Established','Listen')} | ForEach-Object { $proc=Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -ErrorAction SilentlyContinue; [PSCustomObject]@{State=$_.State;LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;PID=$_.OwningProcess;Process=$proc.Name;Path=$proc.ExecutablePath;CommandLine=$proc.CommandLine} } | Format-List
"=== Route Print ==="; route print
"=== NetRoute IPv4 ==="; Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object DestinationPrefix,RouteMetric | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,Protocol,State | Format-Table -AutoSize
"=== Persistent Routes Registry ==="; REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" 2>&1
"=== DNS Cache ipconfig ==="; ipconfig /displaydns
"=== DNS Client Cache ==="; Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry,Name,Type,Data,TimeToLive | Format-Table -AutoSize
"=== DNS Client Server Addresses ==="; Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,ServerAddresses | Format-List
"=== ARP Cache ==="; arp -a
"=== Proxy HKCU ==="; REG QUERY "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 2>&1
"=== WinHTTP Proxy ==="; netsh winhttp show proxy
`},
		{ID: "autoruns", Title: "注册表启动项与启动文件夹", Category: "持久化", Skill: "emergency-response", Timeout: timeout, Notes: "检查 Run/RunOnce/Winlogon/Startup 中的异常路径和脚本宿主。", Command: `
$ErrorActionPreference='Continue'
$keys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
foreach($k in $keys){"=== $k ==="; if(Test-Path $k){Get-ItemProperty $k | Format-List *} else {"missing"}}
"=== Startup folders ==="; Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,CreationTime,LastWriteTime | Format-Table -AutoSize
"=== WMIC startup ==="; wmic startup get Caption,Command,Location,User
`},
		{ID: "tasks", Title: "计划任务", Category: "持久化", Skill: "emergency-response", Timeout: timeout, Notes: "关注 PowerShell/cmd/mshta/rundll32/certutil/bitsadmin 与临时路径。", Command: `
$ErrorActionPreference='Continue'
"=== schtasks LIST verbose ==="; schtasks /query /fo LIST /v
"=== ScheduledTasks PowerShell view ==="; Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $i=$_; $a=($i.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' || '; [PSCustomObject]@{TaskName=$i.TaskName;TaskPath=$i.TaskPath;State=$i.State;Author=$i.Author;Action=$a} } | Format-List
`},
		{ID: "services", Title: "服务与驱动", Category: "持久化", Skill: "emergency-response", Timeout: timeout, Notes: "关注新建服务、未加引号路径、非标准目录服务。", Command: `
$ErrorActionPreference='Continue'
"=== Services ==="; Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId,StartName | Sort-Object StartMode,Name | Format-List
"=== Drivers ==="; Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName | Sort-Object StartMode,Name | Format-List
`},
		{ID: "wmi", Title: "WMI 永久事件订阅", Category: "持久化", Skill: "corporate", Timeout: timeout, Notes: "排查 __EventFilter / __EventConsumer / Binding。", Command: `
$ErrorActionPreference='Continue'
"=== WMI EventFilter ==="; Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Format-List *
"=== WMI EventConsumer ==="; Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Format-List *
"=== WMI Binding ==="; Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Format-List *
`},
		{ID: "files", Title: "临时目录、下载目录、Prefetch 与 ADS", Category: "文件系统", Skill: "emergency-response", Timeout: timeout, Notes: "关注近期落地样本、备用数据流和预取执行痕迹。", Command: fmt.Sprintf(`
$ErrorActionPreference='Continue'
$days=%d
"=== Recent Temp ==="; Get-ChildItem $env:TEMP,$env:WINDIR\Temp -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 120 FullName,Length,CreationTime,LastWriteTime | Format-Table -AutoSize
"=== Downloads ==="; Get-ChildItem "$env:USERPROFILE\Downloads" -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 120 FullName,Length,CreationTime,LastWriteTime | Format-Table -AutoSize
"=== Recent Modified Executables ==="; Get-ChildItem C:\ -Include *.exe,*.dll,*.ps1,*.vbs,*.js,*.bat,*.cmd -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$days)} | Select-Object -First 200 FullName,Length,CreationTime,LastWriteTime | Format-Table -AutoSize
"=== Prefetch Recent ==="; Get-ChildItem $env:WINDIR\Prefetch -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 120 Name,Length,LastWriteTime | Format-Table -AutoSize
"=== ADS in Temp and Downloads ==="; cmd /c "dir /r %%TEMP%%"; cmd /c "dir /r %%USERPROFILE%%\Downloads"
`, fileDays)},
		{ID: "security-events", Title: "安全日志关键事件", Category: "日志分析", Skill: "corporate", Timeout: timeout, Notes: "4624/4625/4672/4720/4722/4726/4778/4779/1102 登录/账号变更/日志清除事件。", Command: securityEventsCommand(days, maxEvents)},
		{ID: "system-events", Title: "系统服务日志事件", Category: "日志分析", Skill: "corporate", Timeout: timeout, Notes: "7045 新服务创建,以及服务启停、异常崩溃事件。", Command: systemEventsCommand(days, maxEvents)},
		{ID: "powershell-events", Title: "PowerShell 脚本日志", Category: "日志分析", Skill: "corporate", Timeout: timeout, Notes: "4103/4104 脚本块日志,含 EncodedCommand 解码、可疑下载执行特征。", Command: powershellEventsCommand(days, maxEvents)},
		{ID: "web-logs", Title: "IIS/HTTP 访问日志抽样", Category: "日志分析", Skill: "corporate", Timeout: timeout, Notes: "报告完整日志内置 GET/POST/自定义筛选。", Command: `
$ErrorActionPreference='Continue'
$roots=@("$env:SystemDrive\inetpub\logs\LogFiles", "$env:SystemRoot\System32\LogFiles")
foreach($root in $roots){
  "=== WebLogRoot $root ==="
  if(Test-Path $root){
    Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20 | ForEach-Object { "--- FILE: $($_.FullName) LastWrite=$($_.LastWriteTime) ---"; Get-Content $_.FullName -Tail 300 -ErrorAction SilentlyContinue }
  } else { "missing" }
}
`},
		{ID: "defender", Title: "Defender 与防火墙状态", Category: "防护状态", Skill: "corporate", Timeout: timeout, Notes: "检查实时防护、排除项、防火墙配置。", Command: `
$ErrorActionPreference='Continue'
"=== Defender Status ==="; Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *
"=== Defender Preferences ==="; Get-MpPreference -ErrorAction SilentlyContinue | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension,MAPSReporting,SubmitSamplesConsent | Format-List
"=== Firewall Profiles ==="; Get-NetFirewallProfile -ErrorAction SilentlyContinue | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction -AutoSize
"=== Hosts File ==="; Get-Content "$env:WINDIR\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
`},
		// === 应急响应专家补充：Defender 历史查杀记录（现有任务只看实时状态，不看历史）===
		{ID: "defender-history", Title: "Defender 历史查杀与威胁记录", Category: "防护状态", Skill: "corporate", Timeout: timeout, Notes: "Get-MpThreatDetection/Get-MpThreat 近期检测、隔离、允许的威胁，还原被拦截时间线。", Command: fmt.Sprintf(`
$ErrorActionPreference='Continue'
"=== Threat Detections (近期检测) ==="
$dets = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 200
if($dets){ $dets | Select-Object ThreatID,@{n='Process';e={$_.ProcessName}},@{n='File';e={$_.Resources -join '; '}},@{n='Time';e={$_.InitialDetectionTime}},ActionSuccess, @{n='Action';e={ switch($_.RemediationAction){0{'Unknown'}1{'Clean'}2{'Quarantine'}3{'Remove'}6{'Allow'}9{'NoAction'}default{'#'+[string]$_.RemediationAction}} }} | Format-Table -AutoSize }
else { "no threat detections" }
"=== Threats (隔离/允许列表) ==="
$thr = Get-MpThreat -ErrorAction SilentlyContinue
if($thr){ $thr | Select-Object ThreatID,SeverityID, @{n='Action';e={ switch($_.RemediationAction){0{'Unknown'}1{'Clean'}2{'Quarantine'}3{'Remove'}6{'Allow'}9{'NoAction'}default{'#'+[string]$_.RemediationAction}} }}, @{n='Time';e={$_.InitialDetectionTime}} | Format-Table -AutoSize }
else { "no threats recorded" }
"=== Threat Catalog (威胁名称摘要) ==="
$cat = Get-MpThreatCatalog -ErrorAction | Sort-Object SeverityID -Descending | Select-Object -First 80
if($cat){ $cat | Select-Object ThreatName,SeverityID,CategoryID | Format-Table -AutoSize }
`)},
		// === 应急响应专家补充：Sysmon 日志（现代 IR 核心数据源，原工具完全未采集）===
		{ID: "sysmon", Title: "Sysmon 进程与注入日志", Category: "日志分析", Skill: "corporate", Timeout: timeout, Notes: "Sysmon EventID 1/3/7/8/9/10/11 进程创建/网络/镜像加载/远程线程/RawAccess，注入与凭据转储特征。", Command: fmt.Sprintf(`
$ErrorActionPreference='SilentlyContinue'
%s
$logName='Microsoft-Windows-Sysmon/Operational'
$provider='Microsoft-Windows-Sysmon'
if(-not (Get-WinEvent -List $logName -ErrorAction SilentlyContinue)){ "=== Sysmon NOT installed (日志通道不存在) ==="; return }
$ids=@(1,3,7,8,9,10,11,13,22)
$filter=@{ProviderName=$provider; Id=$ids}
if($useStart){ $filter['StartTime']=$start; "=== Sysmon events since $start ===" } else { "=== Sysmon events (all) ===" }
Get-WinEvent -FilterHashtable $filter -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id, @{n='ShortMsg';e={ ($_.Message -split [Environment]::NewLine)[0] }}, @{n='FullMsg';e={ ($_.Message).Substring(0,[Math]::Min(500,$_.Message.Length)) }}, Properties | Format-List
`, eventStartPrelude(days), maxEvents)},
		// === 应急响应专家补充：横向移动痕迹（SMB/PsExec/共享，原工具完全缺失）===
		{ID: "lateral", Title: "横向移动与共享痕迹", Category: "横向定损", Skill: "corporate", Timeout: timeout, Notes: "SMB 共享/会话/PsExec 痕迹/映射驱动器，判断是否被横向渗透。", Command: `
$ErrorActionPreference='Continue'
"=== SMB Shares (共享) ==="; Get-SmbShare -ErrorAction SilentlyContinue | Format-Table Name,Path,Description,ConcurrentUserLimit -AutoSize
"=== Default Shares (net share) ==="; net share 2>$null
"=== Open Files (当前被打开的共享文件) ==="; Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object -First 100 ClientUserName,ClientComputerName,Path,SessionID | Format-Table -AutoSize
"=== SMB Sessions (入站会话) ==="; Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientUserName,ClientComputerName,Dialect,SessionID | Format-Table -AutoSize
"=== SMB Connections (出站连接) ==="; Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName,ShareName,UserName,Dialect | Format-Table -AutoSize
"=== SMB Mappings (映射驱动器) ==="; Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath,RemotePath,Status | Format-Table -AutoSize
"=== Net Session (旧式会话枚举) ==="; net session 2>$null
"=== Net Use (映射) ==="; net use 2>$null
"=== PsExec 痕迹 (PSEXESVC 服务) ==="; Get-Service -Name PSEXESVC -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
"=== Remote Desktop Users 组成员 ==="; try { net localgroup "Remote Desktop Users" 2>$null } catch {}
"=== Distributed COM Users 组成员 ==="; try { net localgroup "Distributed COM Users" 2>$null } catch {}
`},
		// === 应急响应专家补充：磁盘驱动签名全盘扫描（原仅 Win32_SystemDriver dump，无签名校验）===
		{ID: "drivers", Title: "驱动签名与 Rootkit 检测", Category: "驱动检测", Skill: "corporate", Timeout: timeout, Notes: "全盘扫描 drivers 目录 .sys 签名，未签名/非微软签名/撤销的驱动是内核 Rootkit 强信号。", Command: `
$ErrorActionPreference='SilentlyContinue'
$dirs = @("$env:WINDIR\System32\drivers")
"=== Driver Files 签名扫描 ==="
$all = Get-ChildItem -Path $dirs -Filter *.sys -File -ErrorAction SilentlyContinue
"总驱动文件数: $($all.Count)"
$unsigned = @(); $nonMs = @(); $revoked = @()
foreach($f in $all){
  $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
  if(-not $sig){ continue }
  if($sig.Status -eq 'NotSigned'){ $unsigned += $f.Name }
  elseif($sig.SignerCertificate){ $subj = $sig.SignerCertificate.Subject; if($subj -notmatch 'Microsoft'){ $nonMs += ($f.Name + ' | ' + ($subj -replace ',.*$','')) } }
  if($sig.Status -eq 'HashMismatch' -or $sig.Status -eq 'NotTrusted'){ $revoked += $f.Name }
}
"--- 未签名驱动 ($($unsigned.Count)) ---"; $unsigned | Select-Object -First 50
"--- 非微软签名驱动 ($($nonMs.Count)) ---"; $nonMs | Select-Object -First 50
"--- 签名异常/撤销 ($($revoked.Count)) ---"; $revoked | Select-Object -First 50
"=== 当前加载的内核驱动 ==="; driverquery /v /fo csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue | Select-Object -First 200 'Display Name','Link Date','Path' | Format-Table -AutoSize
`},
	}
	switch strings.ToLower(opt.Profile) {
	case "emergency-response":
		return filterTasks(tasks, map[string]bool{"emergency-response": true})
	case "corporate":
		return filterTasks(tasks, map[string]bool{"corporate": true})
	default:
		return tasks
	}
}

func eventStartPrelude(days int) string {
	if days > 0 {
		return fmt.Sprintf("$days=%d\n$useStart=$true\n$start=(Get-Date).AddDays(-$days)", days)
	}
	return "$days=0\n$useStart=$false\n$start=$null"
}

func securityEventsCommand(days, maxEvents int) string {
	return fmt.Sprintf(`
$ErrorActionPreference='Continue'
%s
$ids=@(4624,4625,4634,4647,4648,4672,4720,4722,4726,4778,4779,1102)
$filter=@{LogName='Security'; Id=$ids}
if($useStart){ $filter['StartTime']=$start; "=== Security key events since $start ===" } else { "=== Security key events all logs ===" }
Get-WinEvent -FilterHashtable $filter -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | Format-List
`, eventStartPrelude(days), maxEvents)
}

func systemEventsCommand(days, maxEvents int) string {
	return fmt.Sprintf(`
$ErrorActionPreference='Continue'
%s
$ids=@(7045,7036,7040,7000,7001,7009,7022,7023,7024,7031,7034)
$filter=@{LogName='System'; Id=$ids}
if($useStart){ $filter['StartTime']=$start; "=== System service events since $start ===" } else { "=== System service events all logs ===" }
Get-WinEvent -FilterHashtable $filter -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,LevelDisplayName,Message | Format-List
`, eventStartPrelude(days), maxEvents)
}

func powershellEventsCommand(days, maxEvents int) string {
	return fmt.Sprintf(`
$ErrorActionPreference='Continue'
%s
$ids=@(400,403,600,800,4103,4104)
$filterClassic=@{LogName='Windows PowerShell'}
$filterOperational=@{LogName='Microsoft-Windows-PowerShell/Operational'; Id=$ids}
if($useStart){ $filterClassic['StartTime']=$start; $filterOperational['StartTime']=$start; "=== PowerShell events since $start ===" } else { "=== PowerShell events all logs ===" }
"=== Windows PowerShell ==="; Get-WinEvent -FilterHashtable $filterClassic -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List
"=== PowerShell Operational ==="; Get-WinEvent -FilterHashtable $filterOperational -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,ProviderName,Message | Format-List
`, eventStartPrelude(days), maxEvents/2, maxEvents/2)
}

func filterTasks(tasks []Task, skills map[string]bool) []Task {
	out := make([]Task, 0, len(tasks))
	for _, t := range tasks {
		if skills[t.Skill] {
			out = append(out, t)
		}
	}
	return out
}
