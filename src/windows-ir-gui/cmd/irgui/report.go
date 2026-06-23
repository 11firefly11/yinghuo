package main

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"
)

func writeReport(path string, s *Scan, results []TaskResult, findings []Finding) error {
	sum := summary(findings, results)
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Windows 应急响应报告</title>`)
	b.WriteString(reportCSS())
	b.WriteString(`</head><body>`)

	fmt.Fprintf(&b, `<header><div class="wrap hero"><div class="title"><h1>Windows 应急响应扫描报告</h1><p>Profile：%s · 输出目录：%s · 生成时间：%s</p></div><div class="toolbar"><a class="btn" href="#findings">可疑项</a><a class="btn" href="#tasks">完整输出</a><button class="btn primary" onclick="window.print()">打印/另存 PDF</button></div></div></header>`,
		esc(s.Options.Profile), esc(s.OutputDir), esc(time.Now().Format(time.RFC3339)))
	b.WriteString(`<main class="wrap">`)

	fmt.Fprintf(&b, `<section class="grid cards"><div class="card"><div class="muted">严重/高危</div><div class="metric">%d</div></div><div class="card"><div class="muted">中危</div><div class="metric">%d</div></div><div class="card"><div class="muted">采集任务</div><div class="metric">%d</div></div><div class="card"><div class="muted">失败/超时任务</div><div class="metric">%d</div></div><div class="card"><div class="muted">总耗时</div><div class="metric">%.0fs</div></div></section>`,
		countSeverity(findings, "critical")+countSeverity(findings, "high"), countSeverity(findings, "medium"), len(results), sum["failedTasks"].(int), anyFloat(sum["durationSec"]))

	b.WriteString(`<section class="section grid two"><div class="card"><h2>研判摘要</h2><p class="hint">本报告按两个 Skill 的核心原则生成：先取证后处置、并行采集、VBR 可复核、日志与证据链优先。内置规则只负责快速标红，最终结论仍建议结合业务基线、EDR/SIEM/网关日志交叉验证。</p><ul>`)
	for i, f := range findings {
		if i >= 8 {
			break
		}
		fmt.Fprintf(&b, `<li>%s <b>%s</b> <span class="muted">(%s / %s)</span></li>`, sevBadge(f.Severity), esc(f.Title), esc(f.Category), esc(f.SourceTaskID))
	}
	b.WriteString(`</ul></div><div class="card"><h2>优先动作建议</h2><ol>`)
	for _, advice := range priorityAdvice(findings) {
		fmt.Fprintf(&b, `<li>%s</li>`, esc(advice))
	}
	b.WriteString(`</ol></div></section>`)

	b.WriteString(`<section id="findings" class="section card"><h2>可疑点与不安全项</h2><div class="filters"><select id="sevFilter" onchange="filterFindings()"><option value="">全部等级</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="pass">通过</option></select><input id="findingSearch" class="input" placeholder="搜索标题/证据/建议" oninput="filterFindings()"></div><div id="findingList">`)
	for _, f := range findings {
		fmt.Fprintf(&b, `<div class="finding finding-row" data-sev="%s" data-search="%s"><div>%s<p class="muted">%s<br>%s</p></div><div><h3>%s</h3><p><b>建议：</b>%s</p><div class="evidence">%s</div></div></div>`,
			esc(f.Severity), esc(strings.ToLower(f.Title+" "+f.Evidence+" "+f.Recommendation+" "+f.RuleID)), sevBadge(f.Severity), esc(f.RuleID), esc(f.SourceTaskID), esc(f.Title), esc(f.Recommendation), esc(f.Evidence))
	}
	b.WriteString(`</div></section>`)

	b.WriteString(`<section class="section card"><h2>时间线（采集与发现）</h2><div class="timeline">`)
	for _, r := range results {
		fmt.Fprintf(&b, `<div class="timeline-item"><b>%s</b><br><span>开始采集：%s</span></div>`, esc(r.StartedAt.Format(time.RFC3339)), esc(r.Title))
	}
	for i, f := range findings {
		if i >= 60 {
			break
		}
		fmt.Fprintf(&b, `<div class="timeline-item"><b>%s</b><br><span>%s：%s</span></div>`, esc(f.CreatedAt.Format(time.RFC3339)), esc(sevText(f.Severity)), esc(f.Title))
	}
	b.WriteString(`</div></section>`)

	b.WriteString(`<section id="tasks" class="section"><h2>所有输出结果</h2><div class="grid task-grid">`)
	taskNotes := map[string]string{}
	for _, t := range s.Tasks {
		taskNotes[t.ID] = t.Notes
	}
	for _, r := range results {
		full := limitTextBytes(r.Stdout, maxReportEmbeddedLogBytes)
		if strings.TrimSpace(r.Stderr) != "" {
			full += "\n--- STDERR ---\n" + limitTextBytes(r.Stderr, maxReportEmbeddedLogBytes/4)
		}
		if strings.TrimSpace(full) == "" {
			full = "轻量模式未在 HTML 内嵌完整日志；请在客户端内点击完整响应或查看输出目录 raw 文件。"
		}
		fmt.Fprintf(&b, `<div class="card task-card"><div class="task-head"><div><h3>%s</h3><p class="muted">%s · %s · %s · %dms</p></div><button class="btn" onclick="openLog('%s','%s')">完整日志</button></div><p>%s</p><pre class="pre">%s</pre><pre id="logsrc-%s" class="log-source" hidden>%s</pre></div>`,
			esc(r.Title), esc(r.Category), esc(r.Skill), esc(r.Status), r.DurationMs, esc(r.TaskID), esc(r.Title), esc(taskNotes[r.TaskID]), esc(r.Preview), esc(r.TaskID), esc(full))
	}
	b.WriteString(`</div></section></main>`)
	b.WriteString(modalHTML())
	b.WriteString(reportJS())
	b.WriteString(`</body></html>`)
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func esc(s string) string { return html.EscapeString(s) }

func anyFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	default:
		return 0
	}
}

func summary(findings []Finding, results []TaskResult) map[string]any {
	failedTasks := 0
	var started time.Time
	var finished time.Time
	for _, r := range results {
		if r.Status != "ok" {
			failedTasks++
		}
		if started.IsZero() || (!r.StartedAt.IsZero() && r.StartedAt.Before(started)) {
			started = r.StartedAt
		}
		if finished.IsZero() || r.FinishedAt.After(finished) {
			finished = r.FinishedAt
		}
	}
	duration := 0.0
	if !started.IsZero() && !finished.IsZero() && finished.After(started) {
		duration = finished.Sub(started).Seconds()
	}
	return map[string]any{
		"failedTasks": failedTasks,
		"durationSec": duration,
		"findings":    len(findings),
	}
}

func countSeverity(findings []Finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func sevText(sev string) string {
	switch sev {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "pass":
		return "通过"
	default:
		return "信息"
	}
}

func sevBadge(sev string) string {
	return fmt.Sprintf(`<span class="badge sev-%s">%s</span>`, esc(sev), esc(sevText(sev)))
}

func priorityAdvice(findings []Finding) []string {
	var a []string
	if countSeverity(findings, "critical") > 0 {
		a = append(a, "优先保全并交叉验证日志清理、账号变更等破坏证据类事件。")
	}
	if countSeverity(findings, "high") > 0 {
		a = append(a, "对高危项对应的样本/账号/服务/计划任务先导出证据，再走 HITL 审批处置。")
	}
	a = append(a,
		"按源 IP、账号、PID、文件路径重建时间线，确认初始入口与影响面。",
		"对同密码、同服务、同管理员、互信资产做横向扩面排查。",
		"所有清除、隔离、重启、封禁动作均建议先记录可回滚方式并人工确认。",
	)
	return a
}

func reportCSS() string {
	return `<style>
:root{--bg:#f6f8fb;--card:#fff;--text:#0f172a;--muted:#64748b;--border:#e2e8f0;--primary:#4f46e5;--critical:#991b1b;--high:#dc2626;--medium:#d97706;--low:#0284c7;--info:#64748b;--pass:#059669;--shadow:0 12px 34px rgba(15,23,42,.08);--radius:18px}*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Microsoft YaHei,Arial,sans-serif;background:linear-gradient(135deg,#f8fafc,#eef2ff);color:var(--text)}header{position:sticky;top:0;z-index:4;background:rgba(255,255,255,.88);backdrop-filter:blur(16px);border-bottom:1px solid var(--border)}.wrap{max-width:1380px;margin:0 auto;padding:22px}.hero{display:flex;justify-content:space-between;gap:18px;align-items:center}.title h1{margin:0;font-size:28px}.title p{margin:8px 0 0;color:var(--muted)}.toolbar{display:flex;gap:10px;flex-wrap:wrap}.btn{border:1px solid var(--border);background:#fff;border-radius:12px;padding:9px 12px;cursor:pointer;color:#334155;text-decoration:none;display:inline-flex;align-items:center;gap:6px}.btn.primary{background:var(--primary);color:#fff;border-color:var(--primary)}.grid{display:grid;gap:16px}.cards{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-top:20px}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:18px}.metric{font-size:30px;font-weight:800}.muted{color:var(--muted)}.section{margin-top:22px}.section h2{margin:0 0 12px}.badge{display:inline-flex;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700}.sev-critical{background:#fee2e2;color:var(--critical)}.sev-high{background:#fee2e2;color:var(--high)}.sev-medium{background:#fef3c7;color:var(--medium)}.sev-low{background:#e0f2fe;color:var(--low)}.sev-info{background:#f1f5f9;color:var(--info)}.sev-pass{background:#d1fae5;color:var(--pass)}.finding{display:grid;grid-template-columns:110px 1fr;gap:12px;margin-bottom:12px}.finding h3{margin:0 0 8px;font-size:17px}.evidence{background:#f8fafc;border:1px dashed var(--border);border-radius:12px;padding:10px;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;color:#334155;max-height:180px;overflow:auto}.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.input,select{border:1px solid var(--border);border-radius:12px;padding:10px 12px;background:#fff;min-width:180px}.task-grid{grid-template-columns:repeat(auto-fit,minmax(360px,1fr))}.task-card{position:relative}.task-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.task-head h3{margin:0}.pre{white-space:pre-wrap;background:#0f172a;color:#dbeafe;border-radius:14px;padding:12px;max-height:230px;overflow:auto;font-family:Consolas,monospace;font-size:12px}.timeline{border-left:3px solid #c7d2fe;padding-left:16px}.timeline-item{margin:0 0 12px}.modal{position:fixed;inset:0;background:rgba(15,23,42,.62);display:none;z-index:20;padding:26px}.modal.open{display:block}.modal-box{height:100%;background:#fff;border-radius:20px;display:flex;flex-direction:column;overflow:hidden}.modal-head{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;gap:12px;align-items:center}.modal-tools{display:flex;gap:8px;flex-wrap:wrap;padding:12px 18px;border-bottom:1px solid var(--border);background:#f8fafc}.modal pre{margin:0;padding:18px;overflow:auto;flex:1;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px}.hint{border-left:4px solid var(--primary);background:#eef2ff;padding:12px;border-radius:12px;color:#312e81}.two{grid-template-columns:1.1fr .9fr}@media(max-width:860px){.hero,.two,.finding{display:block}.task-grid{grid-template-columns:1fr}.wrap{padding:14px}.modal{padding:6px}}
</style>`
}

func modalHTML() string {
	return `<div id="logModal" class="modal"><div class="modal-box"><div class="modal-head"><h2 id="modalTitle">完整日志</h2><button class="btn" onclick="closeLog()">关闭</button></div><div class="modal-tools"><button class="btn" onclick="filterPreset('POST')">筛选 POST 请求</button><button class="btn" onclick="filterPreset('GET')">筛选 GET 请求</button><button class="btn" onclick="filterPreset('4625')">4625失败登录</button><button class="btn" onclick="filterPreset('4624')">4624成功登录</button><button class="btn" onclick="filterPreset('error')">error/warn/fail</button><input id="customFilter" class="input" placeholder="自定义关键词或 /regex/i"><button class="btn primary" onclick="applyCustom()">筛选</button><button class="btn" onclick="resetLog()">还原完整日志</button><button class="btn" onclick="copyLog()">复制当前日志</button><button class="btn" onclick="downloadLog()">下载当前日志</button></div><pre id="modalLog"></pre></div></div>`
}

func reportJS() string {
	return `<script>
var modalRaw='';
function openLog(id,title){var el=document.getElementById('logsrc-'+id);modalRaw=el?el.textContent:'';document.getElementById('modalTitle').textContent='完整日志：'+title;document.getElementById('modalLog').textContent=modalRaw||'(empty)';document.getElementById('logModal').classList.add('open');}
function closeLog(){document.getElementById('logModal').classList.remove('open')}
function resetLog(){document.getElementById('modalLog').textContent=modalRaw}
function filterPreset(p){var re;if(p==='POST')re=/\bPOST\b|"POST\s/i;else if(p==='GET')re=/\bGET\b|"GET\s/i;else if(p==='4625')re=/4625|failed password|logon failure|登录失败/i;else if(p==='4624')re=/4624|accepted password|登录成功|logon/i;else re=/error|warn|warning|fail|失败|错误/i;var out=modalRaw.split(/\r?\n/).filter(function(l){return re.test(l)}).join('\n');document.getElementById('modalLog').textContent=out||'(无匹配)'}
function applyCustom(){var q=document.getElementById('customFilter').value.trim();if(!q){resetLog();return}var re=null;if(q.charAt(0)==='/'&&q.lastIndexOf('/')>0){var i=q.lastIndexOf('/');try{re=new RegExp(q.slice(1,i),q.slice(i+1)||'i')}catch(e){alert('正则无效：'+e.message);return}}var low=q.toLowerCase();var out=modalRaw.split(/\r?\n/).filter(function(l){return re?re.test(l):l.toLowerCase().indexOf(low)>=0}).join('\n');document.getElementById('modalLog').textContent=out||'(无匹配)'}
function copyLog(){var text=document.getElementById('modalLog').textContent||'';if(navigator.clipboard){navigator.clipboard.writeText(text)}else{var t=document.createElement('textarea');t.value=text;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}}
function downloadLog(){var blob=new Blob([document.getElementById('modalLog').textContent],{type:'text/plain;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=(document.getElementById('modalTitle').textContent||'log')+'.txt';a.click();URL.revokeObjectURL(a.href)}
function filterFindings(){var sev=document.getElementById('sevFilter').value;var q=(document.getElementById('findingSearch').value||'').toLowerCase();document.querySelectorAll('.finding-row').forEach(function(el){var ok=(!sev||el.getAttribute('data-sev')===sev)&&(!q||el.getAttribute('data-search').indexOf(q)>=0);el.style.display=ok?'grid':'none';});}
</script>`
}
