package main

import "time"

const appVersion = "1.0"

type ScanOptions struct {
	Profile      string `json:"profile"`
	OutputDir    string `json:"outputDir"`
	LookbackDays int    `json:"lookbackDays"`
	MaxEvents    int    `json:"maxEvents"`
	TimeoutSec   int    `json:"timeoutSec"`
}

type Task struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Command  string `json:"-"`
	Timeout  int    `json:"timeout"`
	Skill    string `json:"skill"`
	Notes    string `json:"notes"`
}

type TaskResult struct {
	TaskID     string    `json:"taskId"`
	Title      string    `json:"title"`
	Category   string    `json:"category"`
	Skill      string    `json:"skill"`
	Status     string    `json:"status"`
	ExitCode   int       `json:"exitCode"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	DurationMs int64     `json:"durationMs"`
	OutputFile string    `json:"outputFile"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Error      string    `json:"error,omitempty"`
	Preview    string    `json:"preview"`
}

type Finding struct {
	ID             string    `json:"id"`
	Severity       string    `json:"severity"`
	Category       string    `json:"category"`
	Title          string    `json:"title"`
	Evidence       string    `json:"evidence"`
	SourceTaskID   string    `json:"sourceTaskId"`
	Recommendation string    `json:"recommendation"`
	RuleID         string    `json:"ruleId"`
	Tags           []string  `json:"tags"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Scan struct {
	ID         string       `json:"id"`
	Status     string       `json:"status"`
	Options    ScanOptions  `json:"options"`
	StartedAt  time.Time    `json:"startedAt"`
	FinishedAt time.Time    `json:"finishedAt"`
	OutputDir  string       `json:"outputDir"`
	ReportPath string       `json:"reportPath"`
	Error      string       `json:"error,omitempty"`
	Tasks      []Task       `json:"tasks"`
	Results    []TaskResult `json:"results"`
	Findings   []Finding    `json:"findings"`
}

type ProcessInfo struct {
	PID            int      `json:"pid"`
	PPID           int      `json:"ppid"`
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	CommandLine    string   `json:"commandLine"`
	DecodedCommand string   `json:"decodedCommand,omitempty"`
	CreationDate   string   `json:"creationDate"`
	CPU            float64  `json:"cpu"`
	MemoryMB       float64  `json:"memoryMB"`
	Risk           string   `json:"risk"`
	Reasons        []string `json:"reasons"`
	TrustHints     []string `json:"trustHints,omitempty"`
	Protected      bool     `json:"protected"`
}

type KillProcessRequest struct {
	Force  bool   `json:"force"`
	Tree   bool   `json:"tree"`
	Reason string `json:"reason"`
}

type ProcessActionResult struct {
	OK        bool   `json:"ok"`
	PID       int    `json:"pid"`
	Command   string `json:"command"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}
