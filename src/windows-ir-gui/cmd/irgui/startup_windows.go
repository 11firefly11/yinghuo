//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	mbOK              = 0x00000000
	mbIconInformation = 0x00000040
	keyRead           = 0x20019
)

var (
	startupUser32   = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = startupUser32.NewProc("MessageBoxW")
)

func showStartupMessage(title, message string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), mbOK|mbIconInformation)
}

func hasWebView2Runtime() bool {
	return hasWebView2Registry() || hasWebView2File()
}

func isWindowsServer() bool {
	name := strings.ToLower(windowsProductName())
	return strings.Contains(name, "server")
}

func windowsProductName() string {
	for _, root := range []syscall.Handle{syscall.HKEY_LOCAL_MACHINE} {
		if v := readRegistryString(root, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName"); v != "" {
			return v
		}
	}
	return "Windows"
}

func hasWebView2Registry() bool {
	paths := []string{
		`SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
		`SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`,
	}
	roots := []syscall.Handle{syscall.HKEY_LOCAL_MACHINE, syscall.HKEY_CURRENT_USER}
	for _, root := range roots {
		for _, p := range paths {
			var h syscall.Handle
			ptr, err := syscall.UTF16PtrFromString(p)
			if err != nil {
				continue
			}
			if syscall.RegOpenKeyEx(root, ptr, 0, keyRead, &h) == nil {
				_ = syscall.RegCloseKey(h)
				return true
			}
		}
	}
	return false
}

func hasWebView2File() bool {
	bases := []string{
		os.Getenv("ProgramFiles(x86)"),
		os.Getenv("ProgramFiles"),
		os.Getenv("LOCALAPPDATA"),
	}
	for _, base := range bases {
		if base == "" {
			continue
		}
		root := filepath.Join(base, "Microsoft", "EdgeWebView", "Application")
		matches, _ := filepath.Glob(filepath.Join(root, "*", "msedgewebview2.exe"))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

func readRegistryString(root syscall.Handle, path, name string) string {
	var h syscall.Handle
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	if syscall.RegOpenKeyEx(root, pathPtr, 0, keyRead, &h) != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var typ uint32
	var size uint32
	if syscall.RegQueryValueEx(h, namePtr, nil, &typ, nil, &size) != nil || size == 0 {
		return ""
	}
	buf := make([]uint16, size/2)
	if syscall.RegQueryValueEx(h, namePtr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size) != nil {
		return ""
	}
	return strings.TrimRight(syscall.UTF16ToString(buf), "\x00")
}
