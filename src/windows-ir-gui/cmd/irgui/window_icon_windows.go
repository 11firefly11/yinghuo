package main

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	wmSetIcon     = 0x0080
	iconSmall     = 0
	iconBig       = 1
	iconSmall2    = 2
	imageIcon     = 1
	lrDefaultSize = 0x00000040
	cxIcon        = 11
	cyIcon        = 12
	cxSmallIcon   = 49
	cySmallIcon   = 50
	gaRoot        = 2
)

var (
	user32                 = syscall.NewLazyDLL("user32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	shell32                = syscall.NewLazyDLL("shell32.dll")
	procLoadImageW         = user32.NewProc("LoadImageW")
	procSendMessageW       = user32.NewProc("SendMessageW")
	procGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	procSetClassLongPtrW   = user32.NewProc("SetClassLongPtrW")
	procGetAncestor        = user32.NewProc("GetAncestor")
	procEnumWindows        = user32.NewProc("EnumWindows")
	procGetWindowThreadPID = user32.NewProc("GetWindowThreadProcessId")
	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procExtractIconExW     = shell32.NewProc("ExtractIconExW")
)

func setAppWindowIcon(hwnd unsafe.Pointer) {
	big, small := loadAppIcons()
	if big == 0 && small == 0 {
		return
	}
	if hwnd != nil {
		window := uintptr(hwnd)
		applyIcons(window, big, small)
		if root := rootWindow(window); root != 0 && root != window {
			applyIcons(root, big, small)
		}
	}
	applyIconsToProcessWindows(big, small)
}

func loadAppIcons() (uintptr, uintptr) {
	if big, small := extractIconsFromExecutable(); big != 0 || small != 0 {
		return big, small
	}
	instance, _, _ := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return 0, 0
	}
	big := loadIconFromResource(instance, systemMetric(cxIcon), systemMetric(cyIcon))
	small := loadIconFromResource(instance, systemMetric(cxSmallIcon), systemMetric(cySmallIcon))
	return big, small
}

func extractIconsFromExecutable() (uintptr, uintptr) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return 0, 0
	}
	exePtr, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return 0, 0
	}
	var big uintptr
	var small uintptr
	count, _, _ := procExtractIconExW.Call(
		uintptr(unsafe.Pointer(exePtr)),
		0,
		uintptr(unsafe.Pointer(&big)),
		uintptr(unsafe.Pointer(&small)),
		1,
	)
	if count == 0 {
		return 0, 0
	}
	return big, small
}

func loadIconFromResource(instance uintptr, width, height int) uintptr {
	icon, _, _ := procLoadImageW.Call(
		instance,
		uintptr(1),
		imageIcon,
		uintptr(width),
		uintptr(height),
		lrDefaultSize,
	)
	return icon
}

func applyIcons(hwnd uintptr, big, small uintptr) {
	if big != 0 {
		sendWindowIcon(hwnd, iconBig, big)
		setClassIcon(hwnd, ^uintptr(13), big) // GCLP_HICON = -14
	}
	if small != 0 {
		sendWindowIcon(hwnd, iconSmall, small)
		sendWindowIcon(hwnd, iconSmall2, small)
		setClassIcon(hwnd, ^uintptr(33), small) // GCLP_HICONSM = -34
	}
}

func applyIconsToProcessWindows(big, small uintptr) {
	pid := uint32(os.Getpid())
	cb := syscall.NewCallback(func(hwnd uintptr, lparam uintptr) uintptr {
		var windowPID uint32
		procGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&windowPID)))
		if windowPID == pid {
			applyIcons(hwnd, big, small)
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
}

func rootWindow(hwnd uintptr) uintptr {
	root, _, _ := procGetAncestor.Call(hwnd, gaRoot)
	return root
}

func sendWindowIcon(hwnd uintptr, size int, icon uintptr) {
	procSendMessageW.Call(hwnd, wmSetIcon, uintptr(size), icon)
}

func setClassIcon(hwnd uintptr, index uintptr, icon uintptr) {
	procSetClassLongPtrW.Call(hwnd, index, icon)
}

func systemMetric(index int) int {
	v, _, _ := procGetSystemMetrics.Call(uintptr(index))
	if v == 0 {
		return 32
	}
	return int(v)
}
