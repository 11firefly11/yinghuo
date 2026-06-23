package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxStoredTaskOutputBytes = 768 * 1024
const maxRawTaskOutputBytes = 4 * 1024 * 1024
const maxReportEmbeddedLogBytes = 96 * 1024

func runScan(mgr *scanManager, id string) {
	s, ok := mgr.get(id)
	if !ok {
		return
	}
	var wg sync.WaitGroup
	resultsCh := make(chan TaskResult, len(s.Tasks))
	for _, task := range s.Tasks {
		task := task
		wg.Add(1)
		go func() {
			defer wg.Done()
			resultsCh <- runTask(s.OutputDir, task)
		}()
	}
	wg.Wait()
	close(resultsCh)

	results := make([]TaskResult, 0, len(s.Tasks))
	for r := range resultsCh {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].TaskID < results[j].TaskID })
	findings := analyzeResults(results)
	reportPath := filepath.Join(s.OutputDir, "report.html")
	if err := writeReport(reportPath, s, results, findings); err != nil {
		mgr.update(id, func(sc *Scan) {
			sc.Status = "failed"
			sc.Error = err.Error()
			sc.Results = results
			sc.Findings = findings
			sc.FinishedAt = time.Now()
		})
		return
	}
	_ = writeJSONFile(filepath.Join(s.OutputDir, "result.json"), map[string]any{"scan": scanPublic(s), "results": slimTaskResults(results), "findings": findings})
	mgr.update(id, func(sc *Scan) {
		sc.Status = "completed"
		sc.Results = results
		sc.Findings = findings
		sc.ReportPath = reportPath
		sc.FinishedAt = time.Now()
	})
}

func runTask(outDir string, task Task) TaskResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(task.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", powershellUTF8Prefix()+task.Command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	finished := time.Now()

	exitCode := 0
	status := "ok"
	errText := ""
	if ctx.Err() == context.DeadlineExceeded {
		status = "timeout"
		exitCode = -1
		errText = "command timed out"
	} else if err != nil {
		status = "error"
		errText = err.Error()
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	output := stdout.String()
	errOut := stderr.String()
	if errText != "" {
		errOut = strings.TrimSpace(errOut + "\n" + errText)
	}
	rawPath := filepath.Join(outDir, "raw", sanitizeID(task.ID)+".txt")
	rawBody := limitTextBytes(output, maxRawTaskOutputBytes)
	rawErr := limitTextBytes(errOut, maxRawTaskOutputBytes/4)
	var b strings.Builder
	b.WriteString("# Task: " + task.Title + "\n")
	b.WriteString("# Category: " + task.Category + "\n")
	b.WriteString("# Skill: " + task.Skill + "\n")
	b.WriteString("# Started: " + started.Format(time.RFC3339) + "\n")
	b.WriteString("# Finished: " + finished.Format(time.RFC3339) + "\n")
	b.WriteString("# ExitCode: " + strconv.Itoa(exitCode) + "\n\n")
	b.WriteString(rawBody)
	if wasTruncated(output, rawBody) {
		b.WriteString("\n\n--- OUTPUT TRUNCATED FOR LIGHTWEIGHT MODE ---\n")
		b.WriteString("原始输出过大，已截断保存。请缩小日志时间范围或提高筛选条件后重新采集。\n")
	}
	if strings.TrimSpace(rawErr) != "" {
		b.WriteString("\n\n--- STDERR / ERRORS ---\n")
		b.WriteString(rawErr)
		if wasTruncated(errOut, rawErr) {
			b.WriteString("\n--- STDERR TRUNCATED ---\n")
		}
	}
	_ = os.WriteFile(rawPath, []byte(b.String()), 0644)

	storedOut := limitTextBytes(output, maxStoredTaskOutputBytes)
	storedErr := limitTextBytes(errOut, maxStoredTaskOutputBytes/4)

	return TaskResult{
		TaskID:     task.ID,
		Title:      task.Title,
		Category:   task.Category,
		Skill:      task.Skill,
		Status:     status,
		ExitCode:   exitCode,
		StartedAt:  started,
		FinishedAt: finished,
		DurationMs: finished.Sub(started).Milliseconds(),
		OutputFile: rawPath,
		Stdout:     storedOut,
		Stderr:     storedErr,
		Error:      errText,
		Preview:    previewText(storedOut, 1400),
	}
}

func slimTaskResults(results []TaskResult) []TaskResult {
	out := make([]TaskResult, len(results))
	for i, r := range results {
		r.Stdout = ""
		r.Stderr = ""
		out[i] = r
	}
	return out
}

func limitTextBytes(s string, max int) string {
	if max <= 0 || len([]byte(s)) <= max {
		return s
	}
	b := []byte(s)
	cut := max
	for cut > 0 && (b[cut]&0xC0) == 0x80 {
		cut--
	}
	return string(b[:cut]) + "\n\n...内容过长，轻量模式已截断。"
}

func wasTruncated(original, limited string) bool {
	return len([]byte(limited)) < len([]byte(original))
}
