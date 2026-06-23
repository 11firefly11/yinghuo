package main

import "testing"

func TestClassifyWindowsSystemServiceBaseline(t *testing.T) {
	s := ServiceInfo{Name: "BFE", PathName: `C:\Windows\System32\svchost.exe -k LocalServiceNoNetworkFirewall -p`, ExecutablePath: `C:\Windows\System32\svchost.exe`, SignatureStatus: "Valid", Signer: "CN=Microsoft Windows"}
	classifyService(&s)
	if s.Risk != "low" {
		t.Fatalf("risk = %q, want low, reasons=%v", s.Risk, s.Reasons)
	}
	if !isWindowsSystemServiceName("AarSvc_119e7a") {
		t.Fatal("per-user Windows service suffix was not recognized")
	}
}

func TestClassifyNonWindowsServiceUsesOldSuspicionRules(t *testing.T) {
	s := ServiceInfo{Name: "Wallpaper Engine Service", PathName: `"C:\Program Files (x86)\Steam\steamapps\common\wallpaper_engine\wallpaper32.exe"`, ExecutablePath: `C:\Program Files (x86)\Steam\steamapps\common\wallpaper_engine\wallpaper32.exe`, SignatureStatus: "Valid", Signer: "CN=Valve Corp"}
	classifyService(&s)
	if s.Risk != "low" {
		t.Fatalf("risk = %q, want low under old suspicion rules, reasons=%v", s.Risk, s.Reasons)
	}
}

func TestClassifyServiceInPublicDirectoryHighRisk(t *testing.T) {
	s := ServiceInfo{Name: "WinDefend", PathName: `C:\Users\Public\WinDefend.exe`, ExecutablePath: `C:\Users\Public\WinDefend.exe`, SignatureStatus: "NotSigned"}
	classifyService(&s)
	if s.Risk != "high" {
		t.Fatalf("risk = %q, want high, reasons=%v", s.Risk, s.Reasons)
	}
}

func TestClassifySystem32UnsignedServiceMediumRisk(t *testing.T) {
	s := ServiceInfo{Name: "UnknownSvc", PathName: `C:\Windows\System32\badsvc.exe`, ExecutablePath: `C:\Windows\System32\badsvc.exe`, SignatureStatus: "NotSigned"}
	classifyService(&s)
	if s.Risk != "medium" {
		t.Fatalf("risk = %q, want medium, reasons=%v", s.Risk, s.Reasons)
	}
}

func TestClassifyWindowsServiceDllInjectionHighRisk(t *testing.T) {
	s := ServiceInfo{Name: "WinDefend", PathName: `C:\Windows\System32\svchost.exe -k netsvcs`, ExecutablePath: `C:\Windows\System32\svchost.exe`, SignatureStatus: "Valid", Signer: "CN=Microsoft Windows", ServiceDLL: `C:\Windows\System32\evil.dll`, ServiceDLLSignatureStatus: "NotSigned"}
	classifyService(&s)
	if s.Risk != "high" {
		t.Fatalf("risk = %q, want high, reasons=%v", s.Risk, s.Reasons)
	}
}
