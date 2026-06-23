//go:build !windows

package main

func hasWebView2Runtime() bool                 { return true }
func showStartupMessage(title, message string) {}
func isWindowsServer() bool                    { return false }
func windowsProductName() string               { return "" }
