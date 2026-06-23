package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

func analyzeResults(results []TaskResult) []Finding {
	var fs []Finding
	add := func(sev, cat, title, ev, taskID, rec, rule string, tags ...string) {
		fs = append(fs, Finding{
			ID:             "F-" + fmt.Sprintf("%03d", len(fs)+1),
			Severity:       sev,
			Category:       cat,
			Title:          title,
			Evidence:       compact(ev, 900),
			SourceTaskID:   taskID,
			Recommendation: rec,
			RuleID:         rule,
			Tags:           tags,
			CreatedAt:      time.Now(),
		})
	}

	suspiciousExec := regexp.MustCompile(`(?i)(\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\Users\\Public\\|\\Downloads\\|\\ProgramData\\[^\r\n]{0,120}\.(exe|dll|ps1|vbs|js|bat|cmd))`)
	lolbin := regexp.MustCompile(`(?i)(powershell(\.exe)?\s+.*(-enc|-encodedcommand|downloadstring|frombase64string|iex|invoke-expression)|\b(mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin|wmic)\b.*(http|https|\\AppData\\|\\Temp\\|\\Users\\Public))`)
	unquotedSvc := regexp.MustCompile(`(?im)^PathName\s*:\s*([A-Z]:\\[^"\r\n]*\s+[^"\r\n]*\.exe)(\s|$)`)
	ipv4 := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	listenAny := regexp.MustCompile(`(?mi)(0\.0\.0\.0|\[::\]|::):(?:\d+).*\b(LISTENING|Listen)\b`)
	suspiciousDNS := regexp.MustCompile(`(?i)(ngrok|frp|dnslog|burp|interactsh|oast|duckdns|no-ip|dynu|serveo|pastebin|raw\.githubusercontent|telegram|tor2web|onion)`)

	for _, r := range results {
		text := r.Stdout + "\n" + r.Stderr
		low := strings.ToLower(text)
		if r.Status == "timeout" || r.Status == "error" {
			add("low", "采集完整性", "采集任务异常或超时："+r.Title, firstNonEmpty(r.Error, r.Stderr), r.TaskID, "复核 raw 输出；必要时以管理员权限重跑该任务。", "collector.task_error", "collector")
		}
		if suspiciousExec.MatchString(text) && (r.Category == "进程排查" || r.Category == "持久化" || r.Category == "文件系统") {
			add("high", r.Category, "发现临时目录/用户目录中的可执行或脚本痕迹", findLine(text, suspiciousExec), r.TaskID, "核实文件签名、哈希、创建时间和父进程；处置前先复制样本并保全证据。", "win.suspicious_path", "file", "persistence")
		}
		if lolbin.MatchString(text) {
			add("high", r.Category, "发现疑似 LOLBin/脚本下载执行行为", findLine(text, lolbin), r.TaskID, "关联时间线与网络日志，检查是否为攻击链执行；重点核实 PowerShell 4104、计划任务和服务。", "win.lolbin_exec", "execution")
		}
		if r.TaskID == "services" && unquotedSvc.MatchString(text) {
			add("medium", "持久化", "发现疑似未加引号服务路径", findLine(text, unquotedSvc), r.TaskID, "确认服务路径是否可被低权限写入；修复为带引号完整路径并调整 ACL。", "win.unquoted_service_path", "service")
		}
		if strings.Contains(low, "the audit log was cleared") || regexp.MustCompile(`(?m)^Id\s*:\s*1102\b`).MatchString(text) {
			add("critical", "日志分析", "发现安全日志被清理事件（1102）", findAround(text, "1102", 500), r.TaskID, "立即保全其他日志源（EDR/SIEM/域控/网关），追踪清理者账号与登录来源。", "win.eventlog_cleared", "log")
		}
		if regexp.MustCompile(`(?m)^Id\s*:\s*7045\b`).MatchString(text) || strings.Contains(low, "a service was installed") {
			add("high", "持久化", "发现新服务安装事件（7045）", findAround(text, "7045", 700), r.TaskID, "核实服务名、路径、安装账号和同时间段登录事件；必要时隔离样本。", "win.service_install", "service")
		}
		if regexp.MustCompile(`(?m)^Id\s*:\s*(4720|4722|4726)\b`).MatchString(text) {
			add("high", "账户审计", "发现账号创建/启用/删除事件", findAroundRegex(text, regexp.MustCompile(`(?m)^Id\s*:\s*(4720|4722|4726)\b`), 700), r.TaskID, "确认账号变更是否授权；检查管理员组、远程登录和同源 IP。", "win.account_change", "account")
		}
		failedCount := strings.Count(text, "Id              : 4625") + strings.Count(text, "Id: 4625") + strings.Count(text, "Event ID: 4625")
		if failedCount >= 50 {
			add("high", "账户审计", "失败登录事件数量异常", fmt.Sprintf("采样中 4625 事件约 %d 条", failedCount), r.TaskID, "按源 IP/账号聚合 4625；联动边界封禁与账号保护策略。", "win.bruteforce_many", "login")
		} else if failedCount >= 10 {
			add("medium", "账户审计", "存在多次失败登录事件", fmt.Sprintf("采样中 4625 事件约 %d 条", failedCount), r.TaskID, "继续按时间窗口、源 IP、账号聚合，确认是否为暴力破解或误配。", "win.bruteforce_some", "login")
		}
		if regexp.MustCompile(`(?m)^Id\s*:\s*4672\b`).MatchString(text) {
			add("medium", "账户审计", "发现特权登录事件（4672）", findAround(text, "4672", 500), r.TaskID, "与 4624 登录类型、源 IP、账号变更和服务创建事件关联。", "win.privileged_logon", "login")
		}
		if r.TaskID == "wmi" && regexp.MustCompile(`(?i)(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding)`).MatchString(text) && !onlyHeaders(text) {
			add("high", "持久化", "发现 WMI 永久事件订阅痕迹", compact(text, 800), r.TaskID, "确认 Filter/Consumer/Binding 是否为业务基线；可疑项先导出再处置。", "win.wmi_persistence", "wmi")
		}
		if r.TaskID == "network" {
			seen := map[string]bool{}
			for _, line := range strings.Split(text, "\n") {
				if !regexp.MustCompile(`(?i)\bESTABLISHED\b`).MatchString(line) {
					continue
				}
				for _, ip := range ipv4.FindAllString(line, -1) {
					if isExternalIP(ip) && !seen[ip] {
						seen[ip] = true
						add("medium", "网络连接", "发现外部 ESTABLISHED 连接", enrichedNetworkEvidence(text, strings.TrimSpace(line), ip), r.TaskID, "结合 PID、进程路径、业务白名单和威胁情报判断；确认非业务后先网关/主机防火墙阻断，再进入进程清除页结束关联进程树。", "win.external_established", "network", "external")
						if len(seen) >= 12 {
							break
						}
					}
				}
				if len(seen) >= 12 {
					break
				}
			}
			if listenAny.MatchString(text) {
				add("low", "网络连接", "存在 0.0.0.0/:: 监听端口", findLine(text, listenAny), r.TaskID, "核对是否为业务端口；对非业务监听继续追 PID、路径和启动项。", "win.listen_any", "network")
			}
			dnsSeen := map[string]bool{}
			for _, line := range strings.Split(text, "\n") {
				if !regexp.MustCompile(`(?i)(DNS Servers|ServerAddresses|DNS 服务器)`).MatchString(line) {
					continue
				}
				for _, ip := range ipv4.FindAllString(line, -1) {
					if isExternalIP(ip) && !isCommonDNSResolverIP(ip) && !dnsSeen[ip] {
						dnsSeen[ip] = true
						add("medium", "网络连接", "发现未在常用白名单中的外部 DNS 服务器配置", strings.TrimSpace(line), r.TaskID, "核实是否为授权 DNS；若非授权，记录网卡、DNS 服务器与修改时间，恢复企业 DNS 并排查代理/恶意配置。", "win.dns_external_server", "network", "dns")
					}
				}
			}
			if suspiciousDNS.MatchString(text) {
				add("medium", "网络连接", "DNS 缓存存在可疑域名痕迹", findLine(text, suspiciousDNS), r.TaskID, "导出 DNS 缓存并关联同时间段进程、网络连接和 Web/PowerShell 日志；必要时在 DNS/网关侧封禁域名。", "win.dns_suspicious_cache", "network", "dns")
			}
			proxyConfigured := regexp.MustCompile(`(?i)(ProxyEnable\s+REG_DWORD\s+0x1|ProxyServer\s+REG_|代理服务器)`).MatchString(text)
			if !proxyConfigured {
				for _, line := range strings.Split(text, "\n") {
					lowLine := strings.ToLower(line)
					if strings.Contains(lowLine, "proxy server") && strings.Contains(line, ":") && !strings.Contains(lowLine, "direct access") {
						proxyConfigured = true
						break
					}
				}
			}
			if proxyConfigured {
				add("medium", "网络连接", "发现代理配置启用或存在代理服务器", findAroundRegex(text, regexp.MustCompile(`(?i)(ProxyEnable|ProxyServer|Proxy Server\(s\))`), 600), r.TaskID, "核实代理是否为企业基线；未知代理可能用于流量劫持或隐藏外联，建议保全配置后恢复基线并追踪修改来源。", "win.proxy_configured", "network", "proxy")
			}
			persistentRoute := regexp.MustCompile(`(?i)PersistentRoutes.*REG_`).MatchString(text)
			if !persistentRoute {
				idx := strings.Index(strings.ToLower(text), "persistent routes:")
				if idx >= 0 {
					end := idx + 700
					if end > len(text) {
						end = len(text)
					}
					block := text[idx:end]
					persistentRoute = !strings.Contains(strings.ToLower(block), "none") && ipv4.MatchString(block)
				}
			}
			if persistentRoute {
				add("medium", "网络连接", "发现持久路由配置", findAroundRegex(text, regexp.MustCompile(`(?i)(Persistent Routes|PersistentRoutes)`), 700), r.TaskID, "确认是否为授权网络策略；未知持久路由可能用于流量绕行或内网横向，建议导出后按变更记录核验。", "win.route_persistent", "network", "route")
			}
		}
		if r.TaskID == "defender" {
			if regexp.MustCompile(`(?i)(RealTimeProtectionEnabled\s*:\s*False|DisableRealtimeMonitoring\s*:\s*True)`).MatchString(text) {
				add("high", "防护状态", "Defender 实时防护疑似关闭", findAroundRegex(text, regexp.MustCompile(`(?i)(RealTimeProtectionEnabled|DisableRealtimeMonitoring)`), 500), r.TaskID, "确认是否为运维策略；若非授权，追踪策略变更来源并恢复防护。", "win.defender_disabled", "defender")
			}
			if regexp.MustCompile(`(?i)Exclusion(Path|Process|Extension)\s*:\s*\S`).MatchString(text) {
				add("medium", "防护状态", "Defender 存在排除项", findAroundRegex(text, regexp.MustCompile(`(?i)Exclusion(Path|Process|Extension)`), 500), r.TaskID, "核实排除项是否为授权基线；重点关注 Temp/AppData/脚本解释器。", "win.defender_exclusion", "defender")
			}
		}
		if r.TaskID == "web-logs" && regexp.MustCompile(`(?i)(\bPOST\b.*(cmd=|exec=|shell=|upload|\.php)|\bGET\b.*(\.jsp|\.jspx|\.asp|\.aspx|\.php).*(cmd|eval|base64|whoami|powershell))`).MatchString(text) {
			add("high", "日志分析", "Web 日志存在疑似 WebShell/命令执行请求", findAroundRegex(text, regexp.MustCompile(`(?i)(cmd=|exec=|shell=|whoami|powershell|base64|upload)`), 700), r.TaskID, "关联文件落地时间和应用日志；导出完整访问日志并按源 IP/URI 聚合。", "web.suspicious_request", "web")
		}
		// === 应急响应专家补充规则 ===
		// Defender 历史查杀记录
		if r.TaskID == "defender-history" && (strings.Contains(low, "threat") || strings.Contains(low, "threatid")) && !strings.Contains(strings.ToLower(text), "no threat") && regexp.MustCompile(`(?im)^(threatid|threat)\s*:`).MatchString(text) {
			add("high", "防护状态", "Defender 历史检测到威胁（Get-MpThreatDetection）", findAroundRegex(text, regexp.MustCompile(`(?im)(threatid|remediationaction|initialdetectiontime)`), 800), r.TaskID, "还原威胁检测时间线，对应文件进程做哈希取证；已隔离项确认是否清理彻底，允许项重点核查是否为误放行。", "win.defender_threat_history", "defender")
		}
		// Sysmon：进程注入/远程线程/凭据转储访问
		if r.TaskID == "sysmon" {
			if regexp.MustCompile(`(?m)^Id\s*:\s*10\b`).MatchString(text) {
				add("high", "进程排查", "Sysmon 检测到远程线程创建（EventID 10，疑似进程注入）", findAroundRegex(text, regexp.MustCompile(`(?m)^Id\s*:\s*10\b`), 800), r.TaskID, "核实源进程与目标进程；CreateRemoteThread 是 mimikatz/反射注入的典型特征，优先处置源进程。", "win.sysmon_remotethread", "sysmon", "injection")
			}
			if regexp.MustCompile(`(?im)(rawaccess|lsass)`).MatchString(text) && regexp.MustCompile(`(?m)^Id\s*:\s*(9|10)\b`).MatchString(text) {
				add("high", "凭据转储", "Sysmon 检测到 RawAccess/访问 lsass（疑似凭据转储）", findAroundRegex(text, regexp.MustCompile(`(?im)(lsass|rawaccess)`), 800), r.TaskID, "核实访问 lsass.exe 的进程；mimikatz/procdump 痕迹，立即隔离该主机并重置相关账号。", "win.sysmon_rawaccess", "sysmon", "credential")
			}
			if regexp.MustCompile(`(?m)^Id\s*:\s*3\b`).MatchString(text) && strings.Contains(low, "destination") {
				add("medium", "网络连接", "Sysmon 记录进程网络连接（EventID 3）", findAroundRegex(text, regexp.MustCompile(`(?m)^Id\s*:\s*3\b`), 600), r.TaskID, "补充 Sysmon 视角的网络连接，与 netstat 交叉验证；关注非常用端口和外网 IP。", "win.sysmon_network", "sysmon", "network")
			}
		}
		// 横向移动：PsExec / 异常共享
		if r.TaskID == "lateral" {
			if strings.Contains(low, "psexesvc") && regexp.MustCompile(`(?im)psexesvc`).MatchString(text) {
				add("high", "横向定损", "发现 PsExec 服务痕迹（PSEXESVC）", findAroundRegex(text, regexp.MustCompile(`(?im)psexesvc`), 600), r.TaskID, "PsExec 是横向移动常用工具；核实使用账号、来源 IP 和执行命令，检查远程执行时间线。", "win.psexec_service", "lateral")
			}
			// 非默认共享（C$/ADMIN$/IPC$ 之外）。RE2 不支持 (?!)，改为正则匹配共享行 + 代码层排除默认共享名
			shareLine := regexp.MustCompile(`(?im)^\s*([A-Za-z0-9_\-$]+)\s+([A-Z]:\\[^\r\n]*)`)
			if shareLine.MatchString(text) && strings.Contains(low, "share") {
				defaultShares := map[string]bool{"c$": true, "admin$": true, "ipc$": true, "print$": true, "fax$": true}
				suspectLines := []string{}
				for _, m := range shareLine.FindAllStringSubmatch(text, -1) {
					name := strings.ToLower(strings.TrimSpace(m[1]))
					if !defaultShares[name] && name != "" {
						suspectLines = append(suspectLines, strings.TrimSpace(m[0]))
					}
				}
				if len(suspectLines) > 0 {
					add("medium", "横向定损", "发现非默认共享（可能被用于横向文件投递）", strings.Join(suspectLines, "\n"), r.TaskID, "核实共享是否业务必需；非默认共享常被用于横向投递载荷，检查共享路径下的近期新增文件。", "win.suspicious_share", "lateral")
				}
			}
		}
		// 未签名/非微软驱动
		if r.TaskID == "drivers" {
			if strings.Contains(low, "未签名") || regexp.MustCompile(`(?im)notsigned`).MatchString(text) {
				unsignedCount := strings.Count(text, "\n")
				add("high", "驱动检测", "发现未签名驱动（Rootkit 强信号）", findAround(text, "未签名", 800), r.TaskID, "未签名 .sys 是内核 Rootkit/驱动层后门的典型特征；优先复制样本做哈希取证，必要时禁用并隔离主机。", "win.unsigned_driver", "driver", "rootkit")
				_ = unsignedCount
			}
			if regexp.MustCompile(`(?im)(非微软签名|nonms|hashmismatch|nottrusted)`).MatchString(text) {
				add("medium", "驱动检测", "发现非微软签名或签名异常的驱动", findAroundRegex(text, regexp.MustCompile(`(?im)(非微软|hashmismatch|nottrusted)`), 800), r.TaskID, "核实驱动来源厂商是否可信；签名撤销/哈希不匹配可能是被篡改的合法驱动。", "win.suspicious_driver", "driver")
			}
		}
	}

	if len(fs) == 0 {
		fs = append(fs, Finding{ID: "F-000", Severity: "pass", Category: "总体", Title: "未命中内置高风险规则", Evidence: "采集任务完成，未发现内置规则直接命中的高危项。仍需结合业务基线复核外联、服务和账号变更。", Recommendation: "建议人工复核完整日志，并与 EDR/SIEM/网关日志交叉验证。", RuleID: "collector.no_hit", CreatedAt: time.Now()})
	}
	sort.SliceStable(fs, func(i, j int) bool { return severityRank(fs[i].Severity) > severityRank(fs[j].Severity) })
	return fs
}

func enrichedNetworkEvidence(networkText, netstatLine, remoteIP string) string {
	evidence := strings.TrimSpace(netstatLine)
	pid := netstatPID(netstatLine)
	if pid == "" {
		return evidence
	}
	if block := netTCPDetailBlock(networkText, pid, remoteIP); block != "" {
		return evidence + "\n" + block
	}
	return evidence
}

func netstatPID(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	last := strings.TrimSpace(fields[len(fields)-1])
	if regexp.MustCompile(`^\d+$`).MatchString(last) {
		return last
	}
	return ""
}

func netTCPDetailBlock(text, pid, remoteIP string) string {
	sections := regexp.MustCompile(`\r?\n\s*\r?\n`).Split(text, -1)
	pidLine := regexp.MustCompile(`(?mi)^\s*PID\s*:\s*` + regexp.QuoteMeta(pid) + `\s*$`)
	for _, section := range sections {
		if !strings.Contains(section, remoteIP) || !pidLine.MatchString(section) {
			continue
		}
		return strings.TrimSpace(section)
	}
	return ""
}
