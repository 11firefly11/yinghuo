package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var startupLogPath string

func initStartupLog() {
	paths := []string{filepath.Join(os.TempDir(), "IRToolLite", "firefly-ir-startup.log")}
	if exe, err := os.Executable(); err == nil && exe != "" {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "firefly-ir-startup.log"))
	}
	writers := []io.Writer{}
	created := []string{}
	for _, p := range paths {
		_ = os.MkdirAll(filepath.Dir(p), 0755)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}
		writers = append(writers, f)
		created = append(created, p)
	}
	if len(writers) > 0 {
		log.SetOutput(io.MultiWriter(writers...))
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	startupLogPath = strings.Join(created, " ; ")
	log.Printf("===== \u8424\u706b\u5e94\u6025\u54cd\u5e94\u5de5\u5177 started version=%s exe=%s os=%s =====", appVersion, executablePath(), windowsProductName())
}

func recoverStartupPanic() {
	if r := recover(); r != nil {
		msg := "\u7a0b\u5e8f\u542f\u52a8\u5f02\u5e38\uff1a" + anyToString(r)
		log.Print(msg)
		showStartupMessage("\u8424\u706b\u5e94\u6025\u54cd\u5e94\u5de5\u5177\u542f\u52a8\u5931\u8d25", msg+startupLogHint())
		os.Exit(1)
	}
}

func startupFatal(title, message string) {
	log.Printf("%s: %s", title, message)
	showStartupMessage(title, message+startupLogHint())
	os.Exit(1)
}

func fallbackToBrowser(url string, cause error) {
	log.Printf("enter browser compatibility mode url=%s cause=%v", url, cause)
	shortcut := writeURLShortcut(url)
	message := "Built-in WebView is unavailable on this system. Browser compatibility mode has been enabled.\n\nURL: " + url + "\n\nReason: " + cause.Error()
	if shortcut != "" {
		message += "\n\nShortcut created: " + shortcut
	}
	if err := openURL(url); err != nil {
		log.Printf("open browser failed: %v", err)
		message += "\n\nAuto open browser failed: " + err.Error() + "\nPlease copy the URL above and open it manually."
	} else {
		log.Printf("browser open requested")
	}
	go showStartupMessage("Firefly IR Compatibility Mode", message+startupLogHint())
	select {}
}

func writeURLShortcut(url string) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return ""
	}
	p := filepath.Join(filepath.Dir(exe), "\u6253\u5f00\u8424\u706b\u5e94\u6025\u54cd\u5e94\u5de5\u5177.url")
	content := "[InternetShortcut]\r\nURL=" + url + "\r\nIconFile=" + exe + "\r\nIconIndex=0\r\n"
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		log.Printf("write url shortcut failed: %v", err)
		return ""
	}
	return p
}

func startupLogHint() string {
	if startupLogPath == "" {
		return ""
	}
	return "\n\n\u542f\u52a8\u65e5\u5fd7\uff1a" + startupLogPath
}

func anyToString(v any) string { return fmt.Sprint(v) }

func executablePath() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return exe
}

func logStartupMilestone(name string) {
	log.Printf("startup milestone: %s at %s", name, time.Now().Format(time.RFC3339))
}
