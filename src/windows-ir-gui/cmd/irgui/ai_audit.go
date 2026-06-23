package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const aiAuditSystemPrompt = `你是一个网络安全应急响应专家，需要对已有主机证据进行审计，识别可能的后门、木马、WebShell、Java 内存马、异常账号、C2 外联、恶意计划任务、恶意服务、WMI 永久订阅、注册表启动项、代理劫持、DNS/路由篡改、日志清理、横向移动、数据外传或防护绕过。

必须遵守：
1. 只基于输入证据判断，不要编造不存在的进程、IP、账号、路径、日志或威胁情报结论。
2. 每条结论必须引用证据字段或片段，例如 PID、进程名、路径、命令行、远端 IP、Event ID、账号、启动项位置、任务名、服务名、WMI 名称。
3. 严格区分“确认风险 / 高度可疑 / 需业务白名单确认 / 可能误报 / 信息不足”。没有执行命令、网络连接、落地文件、签名异常或日志链路时，不要直接定性为后门。
4. 常用公共 DNS（114DNS、8.8.8.8、1.1.1.1、223.5.5.5、119.29.29.29 等）默认只能写“需确认是否符合企业策略”，不能单独判定为异常 DNS。
5. Microsoft Windows 系统计划任务（路径为 \Microsoft\Windows\，作者为 Microsoft Corporation，执行位于 %windir%\system32）默认按低风险/可能误报处理，除非命令含下载执行、用户目录、编码脚本、未知二进制或证据显示被篡改。
6. AppData/用户目录下的常见应用自启动项只能判为“需业务白名单确认”；只有命中脚本宿主、下载执行、临时目录、无签名、近期异常落地或关联外联时才提升为高危。
7. PowerShell -EncodedCommand 需要结合解码内容、父进程、网络连接和持久化证据判断。若解码内容显示为本地自动化/命令安全层/采集工具（例如 Rust command-safety layer、stdin JSON request parser），不能直接定性为 C2 后门，只能列为“工具进程/需确认来源”。
8. WMI 仅有 EventFilter 名称或 Query，不代表恶意持久化；需要同时看到 Consumer、Binding、CommandLineTemplate/ScriptText 或异常创建日志，才可判高危。
9. 网络外联到 443/CDN/常见云厂商 IP 只能列 IOC 和待确认，不能在无威胁情报、无异常进程、无数据外传证据时直接判高危。
10. 输出必须完整，不要在表格中途截断。若证据不足，明确写“证据不足，建议补采”。

输出结构：
一、总体结论
二、确认风险
三、高度可疑/需复核
四、可能误报或白名单项
五、网络外联与 IOC
六、账号与日志异常
七、处置优先级和补采建议

处置建议必须遵守：先保全证据，再隔离/阻断/禁用/清除；不要建议直接删除证据。`

type AIAuditRequest struct {
	BaseURL   string          `json:"baseUrl"`
	APIKey    string          `json:"apiKey"`
	Model     string          `json:"model"`
	OutputDir string          `json:"outputDir"`
	Evidence  json.RawMessage `json:"evidence"`
}

type AIAuditResponse struct {
	OK           bool           `json:"ok"`
	Model        string         `json:"model"`
	Content      string         `json:"content"`
	FinishReason string         `json:"finishReason,omitempty"`
	ReportPath   string         `json:"reportPath,omitempty"`
	ReportURL    string         `json:"reportUrl,omitempty"`
	Usage        map[string]any `json:"usage,omitempty"`
	Timestamp    string         `json:"timestamp"`
	Error        string         `json:"error,omitempty"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Text         string `json:"text"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage map[string]any `json:"usage"`
	Error any            `json:"error"`
}

func registerAIAuditAPI(mux *http.ServeMux) {
	mux.HandleFunc("/api/ai-audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req AIAuditRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := runAIAudit(req)
		if !resp.OK {
			w.WriteHeader(http.StatusBadGateway)
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/api/ai-audit/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.Query().Get("path")
		if !isAllowedAIReport(path) {
			http.Error(w, "invalid report path", http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r, path)
	})
	mux.HandleFunc("/api/ai-audit/open-report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Path string `json:"path"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !isAllowedAIReport(body.Path) {
			http.Error(w, "invalid report path", http.StatusBadRequest)
			return
		}
		_ = openURL("file:///" + filepath.ToSlash(body.Path))
		writeJSON(w, map[string]any{"ok": true, "path": body.Path})
	})
}

func runAIAudit(req AIAuditRequest) AIAuditResponse {
	resp := AIAuditResponse{
		Model:     strings.TrimSpace(req.Model),
		Timestamp: time.Now().Format(time.RFC3339),
	}
	baseURL := strings.TrimSpace(req.BaseURL)
	apiKey := strings.TrimSpace(req.APIKey)
	model := strings.TrimSpace(req.Model)
	if baseURL == "" {
		resp.Error = "baseUrl is required"
		return resp
	}
	if apiKey == "" {
		resp.Error = "apiKey is required"
		return resp
	}
	if model == "" {
		resp.Error = "model is required"
		return resp
	}
	endpoint, err := chatCompletionsEndpoint(baseURL)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	evidence := summarizeAIEvidence(req.Evidence)
	if strings.TrimSpace(evidence) == "" {
		evidence = "当前没有收到结构化证据，请提示用户先执行排查或刷新模块。"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": aiAuditSystemPrompt},
			{"role": "user", "content": "以下是应急响应工具当前已采集和已发现的信息，请进行 AI 审计分析：\n\n" + evidence},
		},
		"temperature": 0.15,
		"max_tokens":  7000,
	}
	payload, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(strings.ToLower(apiKey), "bearer ") {
		httpReq.Header.Set("Authorization", apiKey)
	} else {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	defer httpResp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4*1024*1024))
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		resp.Error = fmt.Sprintf("AI API HTTP %d: %s", httpResp.StatusCode, compact(string(raw), 900))
		return resp
	}
	var parsed chatCompletionResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		resp.Error = "AI API response parse failed: " + err.Error()
		return resp
	}
	if len(parsed.Choices) == 0 {
		resp.Error = "AI API returned no choices"
		return resp
	}
	content := strings.TrimSpace(parsed.Choices[0].Message.Content)
	if content == "" {
		content = strings.TrimSpace(parsed.Choices[0].Text)
	}
	if content == "" {
		resp.Error = "AI API returned empty content"
		return resp
	}
	finishReason := strings.TrimSpace(parsed.Choices[0].FinishReason)
	if strings.EqualFold(finishReason, "length") {
		content += "\n\n> 系统提示：模型返回 finish_reason=length，本次报告可能仍被截断。建议减少证据量或使用更大上下文模型后重新生成。"
	}
	resp.OK = true
	resp.Content = content
	resp.FinishReason = finishReason
	resp.Usage = parsed.Usage
	if reportPath, err := writeAIAuditReport(req.OutputDir, model, content, evidence, resp.Timestamp); err == nil {
		resp.ReportPath = reportPath
		resp.ReportURL = "/api/ai-audit/report?path=" + url.QueryEscape(reportPath)
	} else {
		resp.Error = "AI analysis succeeded, but HTML report write failed: " + err.Error()
	}
	return resp
}

func writeAIAuditReport(outputDir, model, content, evidence, ts string) (string, error) {
	dir := strings.TrimSpace(outputDir)
	if dir == "" {
		dir = filepath.Join("runs", "ai-audit-"+time.Now().Format("20060102-150405"))
	}
	if !filepath.IsAbs(dir) {
		cwd, _ := os.Getwd()
		dir = filepath.Join(cwd, dir)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "ai-audit.html")
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI 应急审计结果</title>`)
	b.WriteString(`<style>body{margin:0;font-family:"Microsoft YaHei",Segoe UI,Arial,sans-serif;background:linear-gradient(135deg,#f8fafc,#eef2ff);color:#0f172a}.wrap{max-width:1180px;margin:0 auto;padding:26px}.hero{background:#fff;border:1px solid #e2e8f0;border-radius:24px;box-shadow:0 14px 38px rgba(15,23,42,.08);padding:24px;margin-bottom:18px}.hero h1{margin:0 0 10px;font-size:28px}.muted{color:#64748b}.grid{display:grid;grid-template-columns:1fr 340px;gap:18px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:20px;box-shadow:0 14px 38px rgba(15,23,42,.06);padding:20px}.pill{display:inline-flex;border-radius:999px;background:#eef2ff;color:#3730a3;padding:6px 12px;font-weight:800;margin-right:8px}.result{white-space:pre-wrap;line-height:1.75;font-size:15px}.result-card{min-height:520px}.evidence{white-space:pre-wrap;background:#101828;color:#dbeafe;border-radius:16px;padding:16px;max-height:520px;overflow:auto;font-family:Consolas,monospace;font-size:12px}.btn{border:1px solid #d8e0ec;border-radius:12px;background:#fff;color:#334155;text-decoration:none;padding:10px 14px;display:inline-flex;margin:8px 8px 0 0;cursor:pointer}.btn.primary{background:#0f172a;color:#fff;border-color:#0f172a}.note{border-left:4px solid #2563eb;background:#eff6ff;border-radius:12px;padding:12px;margin-top:12px;line-height:1.6}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px}@media(max-width:900px){.grid{grid-template-columns:1fr}}</style>`)
	b.WriteString(`<script>function copyText(sel){const el=document.querySelector(sel);if(!el)return;const text=el.innerText||el.textContent||'';navigator.clipboard&&navigator.clipboard.writeText(text);}</script>`)
	b.WriteString(`</head><body><div class="wrap">`)
	fmt.Fprintf(&b, `<section class="hero"><h1>AI 应急审计结果</h1><p class="muted">模型：%s · 生成时间：%s</p><span class="pill">网络安全应急分析</span><span class="pill">后门/持久化/外联/日志综合研判</span></section>`, html.EscapeString(model), html.EscapeString(ts))
	b.WriteString(`<div class="grid"><main class="card result-card"><div class="toolbar"><h2>AI 分析结论</h2><button class="btn primary" onclick="copyText('.result')">复制 AI 结论</button></div><div class="result">`)
	b.WriteString(html.EscapeString(content))
	b.WriteString(`</div></main><aside class="card"><h2>报告说明</h2><p class="muted">本 HTML 仅包含 AI 审计输出和提交给模型的证据摘要，不包含 APIKey，也不展示系统提示词。</p><div class="note"><b>审计降噪已启用</b><br>常用 DNS、微软系统计划任务、用户目录常见应用自启动、自动化 PowerShell 执行层、无 Consumer 的 WMI Filter 会优先标记为待确认/可能误报。</div><a class="btn" href="#" onclick="window.print();return false">打印/另存 PDF</a><button class="btn" onclick="copyText('.evidence')">复制证据摘要</button></aside></div>`)
	b.WriteString(`<section class="card" style="margin-top:18px"><div class="toolbar"><h2>提交模型的证据摘要</h2><button class="btn" onclick="copyText('.evidence')">复制证据</button></div><pre class="evidence">`)
	b.WriteString(html.EscapeString(truncateRunes(evidence, 50000)))
	b.WriteString(`</pre></section></div></body></html>`)
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func isAllowedAIReport(path string) bool {
	if strings.TrimSpace(path) == "" || !strings.HasSuffix(strings.ToLower(path), ".html") || !pathExists(path) {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	if base != "ai-audit.html" {
		return false
	}
	return true
}

func chatCompletionsEndpoint(base string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid baseUrl")
	}
	path := strings.TrimRight(u.Path, "/")
	switch {
	case strings.HasSuffix(path, "/chat/completions"):
		u.Path = path
	case strings.HasSuffix(path, "/v1"):
		u.Path = path + "/chat/completions"
	default:
		u.Path = path + "/v1/chat/completions"
	}
	return u.String(), nil
}

func summarizeAIEvidence(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return truncateRunes(string(raw), 120000)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return truncateRunes(string(raw), 120000)
	}
	return truncateRunes(string(b), 120000)
}

func truncateRunes(s string, max int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return string(r[:max]) + "\n\n...证据内容过长，已截断。"
}
