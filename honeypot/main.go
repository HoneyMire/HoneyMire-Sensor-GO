package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
)

const (
	schemaVersion = "honeymire.attack/v1"
	counterFile   = "attack_id.txt"
	maxEventBytes = 96 * 1024
	maxEvents     = 2000
	idleTimeout   = 30 * time.Second
)

const (
	telnetSE   byte = 240
	telnetSB   byte = 250
	telnetWILL byte = 251
	telnetWONT byte = 252
	telnetDO   byte = 253
	telnetDONT byte = 254
	telnetIAC  byte = 255

	telnetOptECHO     byte = 1
	telnetOptSGA      byte = 3
	telnetOptLINEMODE byte = 34
)

const (
	telnetLineMaxBytes = 4096
	sshLineMaxBytes    = 256
	sshExecMaxBytes    = 4096
	sshMaxPubkeys      = 8
	sshMaxPubkeyBytes  = 4 * 1024
)

var processStarted = time.Now()

type Honeypot struct {
	DeviceID        string   `json:"device_id"`
	FirmwareVersion string   `json:"firmware_version"`
	FirmwareBuild   string   `json:"firmware_build,omitempty"`
	UptimeS         uint64   `json:"uptime_s,omitempty"`
	Hardware        Hardware `json:"hardware"`
}

type Hardware struct {
	MCU     string `json:"mcu"`
	Board   string `json:"board"`
	Display string `json:"display"`
	FlashMB int    `json:"flash_mb,omitempty"`
	PSRAMKB int    `json:"psram_kb,omitempty"`
	CPUMHz  int    `json:"cpu_mhz,omitempty"`
}

type Attack struct {
	ID             uint64          `json:"id"`
	TS             string          `json:"ts"`
	DurationMS     uint64          `json:"duration_ms,omitempty"`
	Protocol       string          `json:"protocol"`
	Source         Source          `json:"source"`
	Target         *Target         `json:"target,omitempty"`
	Auth           Auth            `json:"auth"`
	Session        *Session        `json:"session,omitempty"`
	Geo            *Geo            `json:"geo,omitempty"`
	Classification *Classification `json:"classification,omitempty"`
	ReportedTo     []string        `json:"reported_to,omitempty"`
}

type Source struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Target struct {
	Port int `json:"port,omitempty"`
}

type Auth struct {
	User          string   `json:"user,omitempty"`
	Pass          string   `json:"pass,omitempty"`
	Authenticated bool     `json:"authenticated,omitempty"`
	Attempts      int      `json:"attempts,omitempty"`
	SSHPubkeys    []SSHKey `json:"ssh_pubkeys,omitempty"`
}

type SSHKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key,omitempty"`
}

type Session struct {
	Commands      int     `json:"commands,omitempty"`
	Events        []Event `json:"events,omitempty"`
	CastV2        string  `json:"cast_v2,omitempty"`
	CastTruncated bool    `json:"cast_truncated,omitempty"`
	Term          *Term   `json:"term,omitempty"`
}

type Event struct {
	K string `json:"k"`
	D string `json:"d"`
}

type Term struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type Geo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Region      string  `json:"region,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
}

type Classification struct {
	Profile        string `json:"profile,omitempty"`
	Confidence     int    `json:"confidence,omitempty"`
	CommandSummary string `json:"command_summary,omitempty"`
}

type Payload struct {
	Schema   string   `json:"schema"`
	Honeypot Honeypot `json:"honeypot"`
	Attack   Attack   `json:"attack"`
}

type hubResponse struct {
	OK             bool   `json:"ok"`
	Dedup          bool   `json:"dedup,omitempty"`
	AttackID       uint64 `json:"attack_id,omitempty"`
	HPLocalID      uint64 `json:"hp_local_id,omitempty"`
	MaxHPLocalID   uint64 `json:"max_hp_local_id,omitempty"`
	GeoFilledByHub bool   `json:"geo_filled_by_hub,omitempty"`
	ReceivedAt     string `json:"received_at,omitempty"`
}

type config struct {
	telnetListen     string
	sshListen        string
	dashboard        string
	dashboardURL     string
	dashboardHost    string
	dashboardAuth    string
	certCache        string
	ipCooldown       time.Duration
	loginAttempts    int
	hubURL           string
	token            string
	deviceID         string
	firmware         string
	board            string
	mcu              string
	display          string
	flashMB          int
	psramKB          int
	cpuMHz           int
	telnetTargetPort int
	sshTargetPort    int
	sshHostKeyPath   string
}

type logger struct {
	plain *log.Logger
	color bool
}

func newLogger() logger {
	fi, err := os.Stdout.Stat()
	color := err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	return logger{plain: log.New(os.Stdout, "", log.LstdFlags), color: color}
}

func (l logger) Info(format string, args ...any)  { l.print("info", "36", format, args...) }
func (l logger) Good(format string, args ...any)  { l.print("ok", "32", format, args...) }
func (l logger) Warn(format string, args ...any)  { l.print("warn", "33", format, args...) }
func (l logger) Error(format string, args ...any) { l.print("err", "31", format, args...) }

func (l logger) print(level, code, format string, args ...any) {
	prefix := strings.ToUpper(level)
	if l.color {
		prefix = "\x1b[" + code + "m" + prefix + "\x1b[0m"
	}
	l.plain.Printf("%-13s %s", "["+prefix+"]", fmt.Sprintf(format, args...))
}

type appState struct {
	cfg           config
	log           logger
	attackCounter uint64
	counterMu     sync.Mutex
	recentMu      sync.RWMutex
	recent        []recentAttack
	cooldownMu    sync.Mutex
	cooldownUntil map[string]time.Time
	stats         stats
}

type stats struct {
	StartedAt        time.Time `json:"started_at"`
	Connections      uint64    `json:"connections"`
	Reported         uint64    `json:"reported"`
	ReportFailures   uint64    `json:"report_failures"`
	Suppressed       uint64    `json:"suppressed"`
	RejectedCooldown uint64    `json:"rejected_cooldown"`
	Deduped          uint64    `json:"deduped"`
	TranscriptBytes  uint64    `json:"transcript_bytes"`
}

type recentAttack struct {
	ID          uint64    `json:"id"`
	When        time.Time `json:"when"`
	Protocol    string    `json:"protocol"`
	Source      string    `json:"source"`
	User        string    `json:"user,omitempty"`
	Pass        string    `json:"pass,omitempty"`
	Commands    int       `json:"commands"`
	Bytes       uint64    `json:"bytes"`
	Truncated   bool      `json:"truncated"`
	Reported    bool      `json:"reported"`
	Dedup       bool      `json:"dedup"`
	Status      string    `json:"status"`
	HubAttackID uint64    `json:"hub_attack_id,omitempty"`
}

type recorder struct {
	events    []Event
	total     uint64
	truncated bool
}

type telnetPersona string

const (
	personaUbuntu  telnetPersona = "Ubuntu"
	personaBusyBox telnetPersona = "BusyBox"
	personaRouter  telnetPersona = "RouterOS"
	personaOpenWrt telnetPersona = "OpenWrt"
	personaDVRDVS  telnetPersona = "DVRDVS"
	personaHiLinux telnetPersona = "HiLinux"
)

type personaProfile struct {
	name         telnetPersona
	banner       string
	loginPrompt  string
	postLoginMsg string
	hostname     string
	fakeUser     string
	notFoundFmt  string
}

var personaProfiles = []personaProfile{
	{personaUbuntu, "Ubuntu 22.04.1 LTS", "%s login: ", "", "ubuntu-server", "ubuntu", "-bash: %s: command not found\n"},
	{personaBusyBox, "", "%s login: ", "BusyBox v1.35.0 (2022-12-01) built-in shell (ash)\nEnter 'help' for a list of built-in commands.", "router", "admin", "%s: not found\n"},
	{personaRouter, "MikroTik RouterOS 7.5", "[%s] > ", "", "MikroTik", "admin", "bad command name %s (line 1 column 1)\n"},
	{personaOpenWrt, "OpenWrt", "%s login: ", "", "OpenWrt", "root", "%s: not found\n"},
	{personaDVRDVS, "", "%s login: ", "DVRDVS DVR System\nType ? for help", "DVRDVS", "admin", "Unknown command: %s\n"},
	{personaHiLinux, "Welcome to HiLinux.\n", "(%s) login: ", "", "hilinux-nvrbox", "root", "-sh: %s: not found\n"},
}

func randomPersona() personaProfile {
	return personaProfiles[mrand.Intn(len(personaProfiles))]
}

func ubuntuPersona() personaProfile {
	return personaProfiles[0]
}

type fakeShell struct {
	user     string
	host     string
	cwd      string
	persona  personaProfile
	history  []string
	exit     bool
	lastOK   bool
	busybox  bool
	files    map[string]string
	lastName string
}

func newFakeShell(user string, persona personaProfile) *fakeShell {
	if strings.TrimSpace(user) == "" {
		user = persona.fakeUser
	}
	cwd := "/root"
	if user != "root" && user != "admin" {
		cwd = "/home/" + user
	}
	return &fakeShell{
		user:    user,
		host:    persona.hostname,
		cwd:     cwd,
		persona: persona,
		lastOK:  true,
		files:   make(map[string]string),
	}
}

func (sh *fakeShell) motd() string {
	switch sh.persona.name {
	case personaUbuntu:
		return "Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n" +
			" * Documentation:  https://help.ubuntu.com\r\n" +
			" * Management:     https://landscape.canonical.com\r\n" +
			" * Support:        https://ubuntu.com/advantage\r\n\r\n" +
			"  System information as of " + strconv.FormatInt(time.Since(processStarted).Milliseconds()/1000, 10) + "\r\n\r\n" +
			"  System load:  0.08              Processes:           98\r\n" +
			"  Usage of /:   23.4% of 19.56GB  Users logged in:     0\r\n" +
			"  Memory usage: 28%               IP address for eth0: 10.0.0.42\r\n" +
			"  Swap usage:   0%\r\n\r\n" +
			"0 packages can be updated.\r\n0 updates are security updates.\r\n\r\n" +
			"Last login: Mon Sep  4 09:14:21 2023 from 192.168.1.5\r\n"
	case personaBusyBox:
		return "BusyBox v1.35.0 (2022-12-01) built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n\r\n"
	case personaOpenWrt:
		return "OpenWrt BARRIER BREAKER 14.07 r42625\r\n\r\n" +
			"  _______                     ________        __\r\n" +
			" |       |.-----.-----.-----.|  |  |  |.----.|  |\r\n" +
			" |   -   ||  _  |  -__|     ||  |  |  ||   _||  |\r\n" +
			" |_______||   __|_____|__|__||________||__|  |__|\r\n" +
			" |  _  | |  |  W I R E L E S S    F R E E D O M\r\n" +
			" | | | | |  |  BARRIER BREAKER (14.07, r42625)\r\n" +
			" |_|_|_|_|__|_|_____________________________\r\n\r\n"
	case personaDVRDVS:
		return "DVRDVS DVR System\r\nType ? for help\r\n\r\n"
	case personaHiLinux:
		return "Welcome to HiLinux (NVR Box)\r\n\r\n"
	default:
		return ""
	}
}

func (sh *fakeShell) prompt() string {
	switch sh.persona.name {
	case personaRouter:
		return "[" + sh.host + "] > "
	case personaBusyBox, personaOpenWrt:
		return sh.host + ":" + sh.displayCwd() + "# "
	case personaDVRDVS:
		return "dvrdvs> "
	case personaHiLinux:
		return sh.host + "# "
	default:
		suffix := "$ "
		if sh.user == "root" {
			suffix = "# "
		}
		return sh.user + "@" + sh.host + ":" + sh.displayCwd() + suffix
	}
}

func (sh *fakeShell) displayCwd() string {
	home := "/root"
	if sh.user != "root" && sh.user != "admin" {
		home = "/home/" + sh.user
	}
	if sh.cwd == home {
		return "~"
	}
	if strings.HasPrefix(sh.cwd, home+"/") {
		return "~" + strings.TrimPrefix(sh.cwd, home)
	}
	return sh.cwd
}

func (sh *fakeShell) execute(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	sh.history = append(sh.history, line)
	if len(sh.history) > 256 {
		sh.history = sh.history[len(sh.history)-256:]
	}
	out := sh.runChain(line)
	return normalizeCRLF(out)
}

func (sh *fakeShell) runChain(raw string) string {
	parts := splitCommandChain(raw)
	var out strings.Builder
	prevOK := true
	prevSep := ""
	for _, part := range parts {
		if part.cmd == "" {
			prevSep = part.sep
			continue
		}
		run := true
		if prevSep == "&&" && !prevOK {
			run = false
		}
		if prevSep == "||" && prevOK {
			run = false
		}
		if run {
			out.WriteString(sh.runOne(parseCommand(part.cmd)))
			prevOK = sh.lastOK
		}
		prevSep = part.sep
		if sh.exit {
			break
		}
	}
	return out.String()
}

type chainPart struct {
	cmd string
	sep string
}

func splitCommandChain(raw string) []chainPart {
	var parts []chainPart
	var b strings.Builder
	inSingle, inDouble := false, false
	flush := func(sep string) {
		parts = append(parts, chainPart{cmd: strings.TrimSpace(b.String()), sep: sep})
		b.Reset()
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
		}
		if !inSingle && !inDouble {
			if i+1 < len(raw) && raw[i:i+2] == "&&" {
				flush("&&")
				i++
				continue
			}
			if i+1 < len(raw) && raw[i:i+2] == "||" {
				flush("||")
				i++
				continue
			}
			if c == ';' || c == '|' {
				flush(string(c))
				continue
			}
		}
		b.WriteByte(c)
	}
	flush("")
	return parts
}

type parsedCommand struct {
	raw  string
	exe  string
	argv []string
}

func parseCommand(raw string) parsedCommand {
	argv := shellFields(raw)
	cmd := parsedCommand{raw: raw, argv: argv}
	if len(argv) > 0 {
		cmd.exe = normalizeExe(argv[0])
	}
	return cmd
}

func shellFields(s string) []string {
	var out []string
	var b strings.Builder
	inSingle, inDouble, esc := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if esc {
			b.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' && !inSingle {
			esc = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && (c == ' ' || c == '\t') {
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func normalizeExe(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	return strings.TrimPrefix(s, "-")
}

func (sh *fakeShell) runOne(c parsedCommand) string {
	sh.lastOK = true
	if len(c.argv) == 0 || c.exe == "" {
		return ""
	}
	e := c.exe
	sh.lastName = e
	if e == "busybox" {
		if len(c.argv) < 2 {
			return "BusyBox v1.30.1 (2020-12-23 15:49:40 UTC) multi-call binary.\nUsage: busybox [function [arguments]...]\n"
		}
		applet := c.argv[1]
		inner := parsedCommand{raw: strings.Join(c.argv[1:], " "), argv: c.argv[1:], exe: normalizeExe(c.argv[1])}
		prev := sh.busybox
		sh.busybox = true
		out := sh.runOne(inner)
		sh.busybox = prev
		if !sh.lastOK && out == sh.notFound(inner.exe) {
			return applet + ": applet not found\n"
		}
		return out
	}
	if strings.HasPrefix(c.argv[0], "./") || strings.HasPrefix(c.argv[0], "/tmp/") || strings.HasPrefix(c.argv[0], "/var/tmp/") || strings.HasPrefix(c.argv[0], "/dev/shm/") {
		return ""
	}
	switch e {
	case "exit", "logout", "quit":
		sh.exit = true
		return ""
	case "enable", "shell", "system", "linuxshell", "unset", "alias", "unalias", "ulimit", "umask", "exec", "eval", "source", ".", "command", "builtin", "chmod", "chown", "chgrp", "rm", "mkdir", "rmdir", "touch", "mv", "cp", "dd", "sleep", "nohup", "setsid", "timeout":
		return ""
	case "sh", "bash", "ash", "dash", "zsh":
		return ""
	case "echo":
		return strings.Join(c.argv[1:], " ") + "\n"
	case "printf":
		if len(c.argv) > 1 {
			return strings.ReplaceAll(c.argv[1], `\n`, "\n")
		}
		return ""
	case "pwd":
		return sh.cwd + "\n"
	case "whoami":
		return sh.user + "\n"
	case "hostname":
		return sh.host + "\n"
	case "id":
		if sh.user == "root" || sh.user == "admin" {
			return "uid=0(root) gid=0(root) groups=0(root)\n"
		}
		return "uid=1000(" + sh.user + ") gid=1000(" + sh.user + ") groups=1000(" + sh.user + ")\n"
	case "uname":
		return sh.cmdUname(c)
	case "cat":
		return sh.cmdCat(c)
	case "head", "tail":
		return sh.cmdCat(c)
	case "ls", "dir":
		return sh.cmdLs(c)
	case "cd":
		return sh.cmdCd(c)
	case "ps":
		return "  PID TTY          TIME CMD\n    1 ?        00:00:02 init\n  501 ?        00:00:00 sshd\n  999 pts/0    00:00:00 sh\n"
	case "netstat":
		return "Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
	case "ss":
		return "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\ntcp   LISTEN 0      128          0.0.0.0:ssh       0.0.0.0:*\n"
	case "ifconfig":
		return "eth0      Link encap:Ethernet  HWaddr 02:42:ac:11:00:02\n          inet addr:10.0.0.42  Bcast:10.0.0.255  Mask:255.255.255.0\n"
	case "ip":
		return "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.42/24 brd 10.0.0.255 scope global eth0\n"
	case "route":
		return "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Iface\ndefault         10.0.0.1        0.0.0.0         UG    eth0\n"
	case "df":
		return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/root       20511356 4801216  14645140  25% /\n"
	case "free":
		return "              total        used        free      shared  buff/cache   available\nMem:         503316       142328       217088        1024       143900       324120\nSwap:             0            0            0\n"
	case "uptime":
		return " 10:14:33 up 12 days,  3:07,  1 user,  load average: 0.08, 0.03, 0.01\n"
	case "w", "who", "last":
		return ""
	case "mount":
		return "/dev/root on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
	case "env", "printenv":
		return "HOME=" + sh.cwd + "\nUSER=" + sh.user + "\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
	case "history":
		var b strings.Builder
		for i, h := range sh.history {
			fmt.Fprintf(&b, "%5d  %s\n", i+1, h)
		}
		return b.String()
	case "wget", "curl", "tftp", "ftpget", "tftpget":
		return ""
	case "which", "whereis", "type":
		if len(c.argv) > 1 {
			return "/bin/" + normalizeExe(c.argv[1]) + "\n"
		}
		return ""
	case "top":
		return "top - 10:14:33 up 12 days,  1 user,  load average: 0.08, 0.03, 0.01\nTasks:  98 total,   1 running,  97 sleeping\n"
	case "clear":
		return "\x1b[H\x1b[2J"
	case ":", "true":
		return ""
	case "false":
		sh.lastOK = false
		return ""
	default:
		sh.lastOK = false
		return sh.notFound(e)
	}
}

func (sh *fakeShell) notFound(name string) string {
	if len(name) > 96 {
		name = name[:96]
	}
	return fmt.Sprintf(sh.persona.notFoundFmt, name)
}

func (sh *fakeShell) cmdUname(c parsedCommand) string {
	all := len(c.argv) == 1
	for _, a := range c.argv[1:] {
		switch a {
		case "-a":
			switch sh.persona.name {
			case personaBusyBox, personaOpenWrt, personaHiLinux:
				return "Linux " + sh.host + " 4.4.194 #1 Wed Dec 1 15:12:01 CST 2022 mips GNU/Linux\n"
			default:
				return "Linux " + sh.host + " 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
			}
		case "-m":
			if sh.persona.name == personaBusyBox || sh.persona.name == personaOpenWrt || sh.persona.name == personaHiLinux {
				return "mips\n"
			}
			return "x86_64\n"
		case "-r":
			if sh.persona.name == personaBusyBox || sh.persona.name == personaOpenWrt || sh.persona.name == personaHiLinux {
				return "4.4.194\n"
			}
			return "5.15.0-91-generic\n"
		case "-s":
			return "Linux\n"
		}
	}
	if all {
		return "Linux\n"
	}
	return "Linux\n"
}

func (sh *fakeShell) cmdCat(c parsedCommand) string {
	if len(c.argv) < 2 {
		return ""
	}
	var b strings.Builder
	for _, p := range c.argv[1:] {
		if strings.HasPrefix(p, "-") {
			continue
		}
		b.WriteString(sh.fileContent(p))
	}
	return b.String()
}

func (sh *fakeShell) fileContent(path string) string {
	switch path {
	case "/etc/passwd":
		if sh.persona.name == personaUbuntu {
			return "root:x:0:0:root:/root:/bin/bash\n" +
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
				"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
				"sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n" +
				"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
		}
		return "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n"
	case "/etc/shadow":
		return "root:*:19000:0:99999:7:::\n"
	case "/etc/os-release":
		if sh.persona.name == personaOpenWrt {
			return "NAME=\"OpenWrt\"\nVERSION=\"14.07, Barrier Breaker\"\nID=openwrt\n"
		}
		if sh.persona.name == personaUbuntu {
			return "PRETTY_NAME=\"Ubuntu 22.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\n"
		}
		return ""
	case "/proc/cpuinfo":
		return "processor\t: 0\nmodel name\t: ARMv7 Processor rev 5\nBogoMIPS\t: 38.40\n"
	case "/proc/meminfo":
		return "MemTotal:         503316 kB\nMemFree:          217088 kB\nMemAvailable:     324120 kB\n"
	case "/proc/mounts":
		return "/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
	case "/proc/self/cmdline":
		return "cat\x00/proc/self/cmdline\x00"
	default:
		if content, ok := sh.files[path]; ok {
			return content
		}
		sh.lastOK = false
		return "cat: " + path + ": No such file or directory\n"
	}
}

func (sh *fakeShell) cmdLs(c parsedCommand) string {
	dir := sh.cwd
	if len(c.argv) > 1 && !strings.HasPrefix(c.argv[len(c.argv)-1], "-") {
		dir = c.argv[len(c.argv)-1]
	}
	switch dir {
	case "/", "/root", "~":
		return "bin  dev  etc  home  proc  root  tmp  usr  var\n"
	case "/tmp", "/var/tmp":
		return ""
	case "/etc":
		return "passwd  shadow  hosts  resolv.conf  os-release  init.d\n"
	default:
		return ""
	}
}

func (sh *fakeShell) cmdCd(c parsedCommand) string {
	if len(c.argv) < 2 || c.argv[1] == "~" {
		sh.cwd = "/root"
		return ""
	}
	if strings.HasPrefix(c.argv[1], "/") {
		sh.cwd = c.argv[1]
	} else {
		sh.cwd = strings.TrimRight(sh.cwd, "/") + "/" + c.argv[1]
	}
	return ""
}

func normalizeCRLF(s string) string {
	var b strings.Builder
	prev := rune(0)
	for _, r := range s {
		if r == '\n' && prev != '\r' {
			b.WriteByte('\r')
		}
		b.WriteRune(r)
		prev = r
	}
	return b.String()
}

func (r *recorder) add(kind string, data []byte) {
	if len(data) == 0 || r.truncated {
		return
	}
	if len(r.events) >= maxEvents || r.total+uint64(len(data)) > maxEventBytes {
		r.truncated = true
		return
	}
	text := string(data)
	if n := len(r.events); n > 0 && r.events[n-1].K == kind {
		next := r.events[n-1].D + text
		if r.total+uint64(len(data)) > maxEventBytes {
			r.truncated = true
			return
		}
		r.events[n-1].D = next
	} else {
		r.events = append(r.events, Event{K: kind, D: text})
	}
	r.total += uint64(len(data))
}

func main() {
	mrand.Seed(time.Now().UnixNano())
	cfg := parseFlags()
	l := newLogger()
	printBanner(l)

	state := &appState{
		cfg:           cfg,
		log:           l,
		cooldownUntil: make(map[string]time.Time),
		stats: stats{
			StartedAt: processStarted,
		},
	}
	state.loadCounter()

	if cfg.dashboard != "" || cfg.dashboardHost != "" {
		go state.serveDashboard()
	}

	started := 0
	if cfg.telnetListen != "" {
		ln, err := net.Listen("tcp", cfg.telnetListen)
		if err != nil {
			l.Error("telnet listen failed on %s: %v", cfg.telnetListen, err)
			os.Exit(1)
		}
		defer ln.Close()
		started++
		go state.acceptLoop("telnet", ln, state.handleTelnetConn)
		l.Good("telnet honeypot listening on %s", cfg.telnetListen)
	}
	if cfg.sshListen != "" {
		ln, err := net.Listen("tcp", cfg.sshListen)
		if err != nil {
			l.Error("ssh listen failed on %s: %v", cfg.sshListen, err)
			os.Exit(1)
		}
		defer ln.Close()
		started++
		signer, err := loadOrCreateSSHSigner(cfg.sshHostKeyPath)
		if err != nil {
			l.Error("ssh host key failed: %v", err)
			os.Exit(1)
		}
		l.Info("ssh host key %s fingerprint %s", cfg.sshHostKeyPath, ssh.FingerprintSHA256(signer.PublicKey()))
		go state.acceptLoop("ssh", ln, func(conn net.Conn) {
			state.handleSSHConn(conn, signer)
		})
		l.Good("ssh honeypot listening on %s", cfg.sshListen)
	}

	if started == 0 {
		l.Error("no honeypot listeners enabled")
		os.Exit(2)
	}
	l.Info("reporting to %s as %s", cfg.hubURL, cfg.deviceID)

	select {}
}

func (s *appState) acceptLoop(protocol string, ln net.Listener, handler func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.log.Warn("%s accept failed: %v", protocol, err)
			continue
		}
		atomic.AddUint64(&s.stats.Connections, 1)
		go handler(conn)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.telnetListen, "telnet-listen", envString("HONEYMIRE_TELNET_LISTEN", envString("HONEYMIRE_LISTEN", ":23")), "TCP address for the Telnet honeypot; set empty to disable")
	flag.StringVar(&cfg.sshListen, "ssh-listen", envString("HONEYMIRE_SSH_LISTEN", ":22"), "TCP address for the SSH honeypot; set empty to disable")
	flag.StringVar(&cfg.dashboard, "dashboard", envString("HONEYMIRE_DASHBOARD", ":8080"), "optional live dashboard address; set empty to disable")
	flag.StringVar(&cfg.dashboardURL, "dashboard-url", envString("HONEYMIRE_DASHBOARD_URL", envString("DASHBOARD_URL", "")), "public dashboard URL/hostname for automatic Let's Encrypt TLS on :80/:443")
	flag.StringVar(&cfg.dashboardAuth, "dashboard-auth", envString("HONEYMIRE_DASHBOARD_AUTH", envString("DASHBOARD_AUTH", "")), "optional dashboard access token")
	flag.StringVar(&cfg.certCache, "cert-cache", envString("HONEYMIRE_CERT_CACHE", "/app/certs"), "Let's Encrypt certificate cache directory")
	flag.DurationVar(&cfg.ipCooldown, "ip-cooldown", envDuration("HONEYMIRE_IP_COOLDOWN", 3*time.Minute), "per-source-IP cooldown after a connection; suppresses Hub reports during cooldown")
	flag.IntVar(&cfg.loginAttempts, "login-attempts-before-accept", envInt("HONEYMIRE_LOGIN_ATTEMPTS_BEFORE_ACCEPT", 3), "credential attempts before the fake shell is granted")
	flag.StringVar(&cfg.hubURL, "hub-url", envString("HONEYMIRE_HUB_URL", ""), "Hub ingest endpoint, including /api/v1/ingest")
	flag.StringVar(&cfg.token, "token", envString("HONEYMIRE_TOKEN", ""), "Bearer token for hub authentication")
	flag.StringVar(&cfg.deviceID, "device-id", envString("HONEYMIRE_DEVICE_ID", "hp-unknown"), "stable honeypot device id")
	flag.StringVar(&cfg.firmware, "firmware", envString("HONEYMIRE_FIRMWARE", "0.1.0"), "firmware/version label to report")
	flag.StringVar(&cfg.board, "board", envString("HONEYMIRE_BOARD", "docker-edge"), "hardware board label")
	flag.StringVar(&cfg.mcu, "mcu", envString("HONEYMIRE_MCU", "esp32-c3"), "hardware MCU label")
	flag.StringVar(&cfg.display, "display", envString("HONEYMIRE_DISPLAY", "none"), "hardware display label")
	flag.IntVar(&cfg.flashMB, "flash-mb", envInt("HONEYMIRE_FLASH_MB", 1), "reported flash size in MiB")
	flag.IntVar(&cfg.psramKB, "psram-kb", envInt("HONEYMIRE_PSRAM_KB", 0), "reported PSRAM size in KiB")
	flag.IntVar(&cfg.cpuMHz, "cpu-mhz", envInt("HONEYMIRE_CPU_MHZ", 160), "reported CPU clock in MHz")
	flag.IntVar(&cfg.telnetTargetPort, "telnet-target-port", envInt("HONEYMIRE_TELNET_TARGET_PORT", envInt("HONEYMIRE_TARGET_PORT", 23)), "reported Telnet target/listening port")
	flag.IntVar(&cfg.sshTargetPort, "ssh-target-port", envInt("HONEYMIRE_SSH_TARGET_PORT", 22), "reported SSH target/listening port")
	flag.StringVar(&cfg.sshHostKeyPath, "ssh-host-key", envString("HONEYMIRE_SSH_HOST_KEY", "ssh_host_key"), "SSH host private key path; generated if missing")
	flag.Parse()

	if cfg.hubURL == "" || cfg.token == "" {
		fmt.Fprintln(os.Stderr, "hub-url and token are required")
		os.Exit(2)
	}
	hubURL, err := normalizeHubURL(cfg.hubURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hub-url: %v\n", err)
		os.Exit(2)
	}
	cfg.hubURL = hubURL
	cfg.telnetListen = normalizeListenAddr(cfg.telnetListen)
	cfg.sshListen = normalizeListenAddr(cfg.sshListen)
	cfg.dashboard = normalizeListenAddr(cfg.dashboard)
	host, err := dashboardHostname(cfg.dashboardURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid dashboard-url: %v\n", err)
		os.Exit(2)
	}
	cfg.dashboardHost = host
	if cfg.dashboardHost != "" {
		cfg.dashboard = ""
		cfg.certCache = filepath.Clean(cfg.certCache)
	}
	return cfg
}

func normalizeHubURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("missing URL")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/api/v1/ingest"
	}
	return parsed.String(), nil
}

func normalizeListenAddr(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, err := strconv.Atoi(value); err == nil {
		return ":" + value
	}
	return value
}

func dashboardHostname(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("missing hostname")
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("Let's Encrypt requires a DNS hostname, not an IP address")
	}
	return strings.ToLower(host), nil
}

func envString(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s=%q: must be an integer\n", key, value)
		os.Exit(2)
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(value); err == nil {
		return parsed
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid %s=%q: use a duration like 3m or seconds like 180\n", key, value)
		os.Exit(2)
	}
	return time.Duration(seconds) * time.Second
}

func printBanner(l logger) {
	lines := []string{
		" _   _                         __  __ _          ",
		"| | | | ___  _ __   ___ _   _  |  \\/  (_)_ __ ___ ",
		"| |_| |/ _ \\| '_ \\ / _ \\ | | | | |\\/| | | '__/ _ \\",
		"|  _  | (_) | | | |  __/ |_| | | |  | | | | |  __/",
		"|_| |_|\\___/|_| |_|\\___|\\__, | |_|  |_|_|_|  \\___|",
		"                        |___/  honeypot            ",
	}
	for _, line := range lines {
		if l.color {
			fmt.Println("\x1b[38;5;179m" + line + "\x1b[0m")
		} else {
			fmt.Println(line)
		}
	}
}

func (s *appState) handleTelnetConn(c net.Conn) {
	defer c.Close()
	start := time.Now()
	tcpAddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		s.log.Warn("non-TCP connection from %s ignored", c.RemoteAddr())
		return
	}

	source := fmt.Sprintf("%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
	if until, cooling := s.isInCooldown(tcpAddr.IP.String(), start); cooling {
		atomic.AddUint64(&s.stats.RejectedCooldown, 1)
		s.log.Info("telnet connection from %s closed immediately by IP cooldown until %s", source, until.Format(time.RFC3339))
		return
	}
	s.log.Info("telnet session opened from %s", source)

	rec := &recorder{}
	sess := newTelnetSession(c, rec)
	sess.sendInitialNeg()

	persona := randomPersona()
	auth := Auth{}
	commands := make([]string, 0, 8)
	var shell *fakeShell
	bannerSent := false

	for {
		if !bannerSent && persona.banner != "" {
			sess.writeString(normalizeCRLF(persona.banner+"\n"), false)
			bannerSent = true
		}
		sess.writeString(fmt.Sprintf(persona.loginPrompt, persona.hostname), false)
		user, _, err := sess.readLine(false)
		if err != nil && user == "" {
			s.finishSession(start, source, tcpAddr, "telnet", s.cfg.telnetTargetPort, rec, auth, commands, err)
			return
		}
		auth.User = user

		sess.writeString("Password: ", false)
		pass, _, err := sess.readLine(true)
		auth.Attempts++
		auth.Pass = pass
		if err != nil && pass == "" {
			s.finishSession(start, source, tcpAddr, "telnet", s.cfg.telnetTargetPort, rec, auth, commands, err)
			return
		}
		if auth.Attempts >= s.cfg.loginAttempts {
			auth.Authenticated = true
			userForShell := user
			if strings.TrimSpace(userForShell) == "" {
				userForShell = persona.fakeUser
			}
			shell = newFakeShell(userForShell, persona)
			break
		}
		sess.writeString("\r\nLogin incorrect\r\n", false)
	}

	sess.paused = false
	if motd := shell.motd(); motd != "" {
		sess.writeString(motd, true)
	}
	sess.writeString(shell.prompt(), true)

	for {
		line, ctrlC, err := sess.readLine(false)
		if ctrlC {
			sess.writeString(shell.prompt(), true)
			continue
		}
		cmd := strings.TrimSpace(line)
		if cmd != "" {
			commands = append(commands, cmd)
		}
		if err != nil {
			s.finishSession(start, source, tcpAddr, "telnet", s.cfg.telnetTargetPort, rec, auth, commands, err)
			return
		}
		out := shell.execute(cmd)
		if out != "" {
			sess.writeString(out, true)
		}
		if shell.exit {
			s.finishSession(start, source, tcpAddr, "telnet", s.cfg.telnetTargetPort, rec, auth, commands, nil)
			return
		}
		sess.writeString(shell.prompt(), true)
	}
}

type telnetSession struct {
	conn     net.Conn
	reader   *bufio.Reader
	out      io.Writer
	rec      *recorder
	inSubneg bool
	lineBuf  []byte
	beepUsed bool
	paused   bool
}

func newTelnetSession(c net.Conn, rec *recorder) *telnetSession {
	return &telnetSession{
		conn:   c,
		reader: bufio.NewReader(c),
		out:    c,
		rec:    rec,
		paused: true,
	}
}

// sendInitialNeg asserts WILL ECHO + WILL SGA + DONT LINEMODE so the
// client routes per-keystroke input to us instead of buffering locally.
func (t *telnetSession) sendInitialNeg() {
	_, _ = t.out.Write([]byte{
		telnetIAC, telnetWILL, telnetOptECHO,
		telnetIAC, telnetWILL, telnetOptSGA,
		telnetIAC, telnetDONT, telnetOptLINEMODE,
	})
}

func (t *telnetSession) write(data []byte, record bool) {
	if len(data) == 0 {
		return
	}
	_, _ = t.out.Write(data)
	if record && !t.paused {
		t.rec.add("o", append([]byte(nil), data...))
	}
}

func (t *telnetSession) writeString(s string, record bool) {
	t.write([]byte(s), record)
}

// readLine performs per-byte interactive line editing. It echoes typed
// characters back to the attacker, masks input with '*' when
// passwordMode is set, supports backspace (DEL/BS), Ctrl-C, line-cap
// bell, transparently absorbs IAC negotiation, and records line-grain
// input events into the asciinema stream.
func (t *telnetSession) readLine(passwordMode bool) (string, bool, error) {
	t.lineBuf = t.lineBuf[:0]
	t.beepUsed = false
	for {
		if t.conn != nil {
			_ = t.conn.SetReadDeadline(time.Now().Add(idleTimeout))
		}
		b, err := t.reader.ReadByte()
		if err != nil {
			if len(t.lineBuf) > 0 && !t.paused {
				t.rec.add("i", append([]byte(nil), t.lineBuf...))
			}
			return string(t.lineBuf), false, err
		}
		if t.inSubneg {
			if b == telnetIAC {
				next, err := t.reader.ReadByte()
				if err != nil {
					return string(t.lineBuf), false, err
				}
				if next == telnetSE {
					t.inSubneg = false
				}
			}
			continue
		}
		if b == telnetIAC {
			cmd, err := t.reader.ReadByte()
			if err != nil {
				return string(t.lineBuf), false, err
			}
			switch cmd {
			case telnetIAC:
				continue
			case telnetSB:
				t.inSubneg = true
			case telnetDO, telnetDONT, telnetWILL, telnetWONT:
				opt, err := t.reader.ReadByte()
				if err != nil {
					return string(t.lineBuf), false, err
				}
				t.replyNeg(cmd, opt)
			}
			continue
		}
		if b == 0 {
			continue
		}
		if b == '\r' || b == '\n' {
			if b == '\r' {
				if peek, err := t.reader.Peek(1); err == nil && len(peek) > 0 && (peek[0] == '\n' || peek[0] == 0) {
					_, _ = t.reader.ReadByte()
				}
			}
			line := string(t.lineBuf)
			if !t.paused {
				evt := append(append([]byte(nil), t.lineBuf...), '\r', '\n')
				t.rec.add("i", evt)
			}
			t.write([]byte{'\r', '\n'}, false)
			return line, false, nil
		}
		if b == 0x7f || b == 0x08 {
			if len(t.lineBuf) > 0 {
				t.lineBuf = t.lineBuf[:len(t.lineBuf)-1]
				if !passwordMode {
					t.write([]byte{'\b', ' ', '\b'}, false)
				}
			}
			if len(t.lineBuf) < telnetLineMaxBytes {
				t.beepUsed = false
			}
			continue
		}
		if b == 0x03 {
			if !t.paused {
				evt := append(append([]byte(nil), t.lineBuf...), '^', 'C', '\r', '\n')
				t.rec.add("i", evt)
			}
			t.write([]byte("^C\r\n"), false)
			t.lineBuf = t.lineBuf[:0]
			return "", true, nil
		}
		if b < 0x20 {
			continue
		}
		if len(t.lineBuf) >= telnetLineMaxBytes {
			if !t.beepUsed {
				t.beepUsed = true
				t.write([]byte{'\a'}, false)
			}
			continue
		}
		t.lineBuf = append(t.lineBuf, b)
		if passwordMode {
			t.write([]byte{'*'}, false)
		} else {
			t.write([]byte{b}, false)
		}
	}
}

// replyNeg responds to peer-initiated IAC negotiation: refuse anything
// the peer asks us to enable, except the ECHO/SGA we already asserted
// (a DO for those is a confirmation we leave alone).
func (t *telnetSession) replyNeg(cmd, opt byte) {
	var reply []byte
	switch cmd {
	case telnetWILL:
		reply = []byte{telnetIAC, telnetDONT, opt}
	case telnetDO:
		if opt == telnetOptECHO || opt == telnetOptSGA {
			return
		}
		reply = []byte{telnetIAC, telnetWONT, opt}
	}
	if len(reply) > 0 {
		_, _ = t.out.Write(reply)
	}
}

func loadOrCreateSSHSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

func (s *appState) handleSSHConn(c net.Conn, signer ssh.Signer) {
	defer c.Close()
	start := time.Now()
	tcpAddr, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		s.log.Warn("non-TCP ssh connection from %s ignored", c.RemoteAddr())
		return
	}
	source := fmt.Sprintf("%s:%d", tcpAddr.IP.String(), tcpAddr.Port)
	if until, cooling := s.isInCooldown(tcpAddr.IP.String(), start); cooling {
		atomic.AddUint64(&s.stats.RejectedCooldown, 1)
		s.log.Info("ssh connection from %s closed immediately by IP cooldown until %s", source, until.Format(time.RFC3339))
		return
	}

	var authMu sync.Mutex
	auth := Auth{Authenticated: true}
	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
		PasswordCallback: func(conn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			authMu.Lock()
			auth.User = conn.User()
			auth.Pass = string(pass)
			auth.Attempts++
			auth.Authenticated = true
			authMu.Unlock()
			return nil, nil
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			authMu.Lock()
			auth.User = conn.User()
			auth.Attempts++
			auth.Authenticated = true
			if len(auth.SSHPubkeys) < sshMaxPubkeys {
				body := authorizedKeyBody(key)
				total := 0
				for _, k := range auth.SSHPubkeys {
					total += len(k.Key)
				}
				if total+len(body) <= sshMaxPubkeyBytes {
					auth.SSHPubkeys = append(auth.SSHPubkeys, SSHKey{
						Type:        key.Type(),
						Fingerprint: ssh.FingerprintSHA256(key),
						Key:         body,
					})
				}
			}
			authMu.Unlock()
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	sshConn, chans, reqs, err := ssh.NewServerConn(c, serverConfig)
	if err != nil {
		if isBenignNetClose(err) {
			s.log.Info("ssh probe from %s disconnected during handshake", source)
		} else {
			s.log.Warn("ssh handshake from %s failed: %v", source, err)
		}
		return
	}
	defer sshConn.Close()
	s.log.Info("ssh session opened from %s as %s", source, sshConn.User())
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "session channels only")
			continue
		}
		channel, requests, err := ch.Accept()
		if err != nil {
			s.log.Warn("ssh channel from %s failed: %v", source, err)
			continue
		}
		s.handleSSHSession(c, channel, requests, start, source, tcpAddr, &authMu, &auth)
		return
	}

	authMu.Lock()
	capturedAuth := auth
	if len(auth.SSHPubkeys) > 0 {
		capturedAuth.SSHPubkeys = append([]SSHKey(nil), auth.SSHPubkeys...)
	}
	authMu.Unlock()
	s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, &recorder{}, capturedAuth, nil, io.EOF)
}

func authorizedKeyBody(key ssh.PublicKey) string {
	fields := strings.Fields(string(ssh.MarshalAuthorizedKey(key)))
	if len(fields) >= 2 {
		return fields[1]
	}
	return ""
}

func isBenignNetClose(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return errors.Is(err, io.EOF) ||
		strings.Contains(text, "connection reset by peer") ||
		strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "broken pipe")
}

func (s *appState) handleSSHSession(conn net.Conn, channel ssh.Channel, requests <-chan *ssh.Request, start time.Time, source string, tcpAddr *net.TCPAddr, authMu *sync.Mutex, auth *Auth) {
	defer channel.Close()
	rec := &recorder{}
	execCh := make(chan string, 1)
	shellCh := make(chan struct{}, 1)

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
				select {
				case shellCh <- struct{}{}:
				default:
				}
			case "exec":
				req.Reply(true, nil)
				select {
				case execCh <- parseSSHExecCommand(req.Payload):
				default:
				}
			case "env":
				// Accept but ignore — lets `ssh -o SendEnv=...` succeed
				// without granting the attacker any real influence.
				req.Reply(true, nil)
			case "subsystem", "x11-req", "auth-agent-req@openssh.com":
				s.log.Info("ssh denied channel-req=%s from %s", req.Type, source)
				req.Reply(false, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	authMu.Lock()
	capturedAuth := *auth
	if len(auth.SSHPubkeys) > 0 {
		capturedAuth.SSHPubkeys = append([]SSHKey(nil), auth.SSHPubkeys...)
	}
	authMu.Unlock()

	select {
	case cmd := <-execCh:
		s.finishSSHExec(channel, start, source, tcpAddr, rec, capturedAuth, cmd)
	case <-shellCh:
		s.runSSHShell(conn, channel, start, source, tcpAddr, rec, capturedAuth)
	case <-time.After(idleTimeout):
		s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, rec, capturedAuth, nil, timeoutError{})
	}
}

// runSSHShell is the SSH counterpart to the telnet interactive flow.
// It reads per byte from the channel so it can echo each keystroke
// back, support backspace / Ctrl-C / Ctrl-D, and cap line length —
// matching the C++ run_fake_shell behavior.
func (s *appState) runSSHShell(conn net.Conn, channel ssh.Channel, start time.Time, source string, tcpAddr *net.TCPAddr, rec *recorder, auth Auth) {
	shell := newFakeShell(auth.User, ubuntuPersona())
	reader := bufio.NewReader(channel)

	writeRec := func(text string) {
		if text == "" {
			return
		}
		_, _ = io.WriteString(channel, text)
		rec.add("o", []byte(text))
	}
	writeRaw := func(data []byte) {
		if len(data) == 0 {
			return
		}
		_, _ = channel.Write(data)
	}

	if motd := shell.motd(); motd != "" {
		writeRec(motd)
	}
	writeRec(shell.prompt())

	commands := make([]string, 0, 8)
	var lineBuf []byte

	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		b, err := reader.ReadByte()
		if err != nil {
			if len(lineBuf) > 0 {
				rec.add("i", append([]byte(nil), lineBuf...))
			}
			s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, rec, auth, commands, err)
			return
		}
		switch {
		case b == '\r' || b == '\n':
			if b == '\r' {
				if peek, err := reader.Peek(1); err == nil && len(peek) > 0 && peek[0] == '\n' {
					_, _ = reader.ReadByte()
				}
			}
			evt := append(append([]byte(nil), lineBuf...), '\r', '\n')
			rec.add("i", evt)
			writeRaw([]byte{'\r', '\n'})
			line := string(lineBuf)
			lineBuf = lineBuf[:0]
			cmd := strings.TrimSpace(line)
			if cmd != "" {
				commands = append(commands, cmd)
			}
			out := shell.execute(cmd)
			if out != "" {
				writeRec(out)
			}
			if shell.exit {
				s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, rec, auth, commands, nil)
				return
			}
			writeRec(shell.prompt())
		case b == 0x7f || b == 0x08:
			if len(lineBuf) > 0 {
				lineBuf = lineBuf[:len(lineBuf)-1]
				writeRaw([]byte{'\b', ' ', '\b'})
			}
		case b == 0x03:
			evt := append(append([]byte(nil), lineBuf...), '^', 'C', '\r', '\n')
			rec.add("i", evt)
			writeRaw([]byte("^C\r\n"))
			lineBuf = lineBuf[:0]
			writeRec(shell.prompt())
		case b == 0x04:
			if len(lineBuf) == 0 {
				s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, rec, auth, commands, nil)
				return
			}
		case b < 0x20:
			// Strip remaining control bytes.
		default:
			if len(lineBuf) >= sshLineMaxBytes {
				continue
			}
			lineBuf = append(lineBuf, b)
			writeRaw([]byte{b})
		}
	}
}

type sshExecPayload struct {
	Command string
}

func parseSSHExecCommand(payload []byte) string {
	var parsed sshExecPayload
	if err := ssh.Unmarshal(payload, &parsed); err != nil {
		return ""
	}
	cmd := strings.TrimSpace(parsed.Command)
	if len(cmd) > sshExecMaxBytes {
		cmd = cmd[:sshExecMaxBytes]
	}
	return cmd
}

func (s *appState) finishSSHExec(channel ssh.Channel, start time.Time, source string, tcpAddr *net.TCPAddr, rec *recorder, auth Auth, cmd string) {
	commands := make([]string, 0, 1)
	shell := newFakeShell(auth.User, ubuntuPersona())
	if cmd != "" {
		commands = append(commands, cmd)
		rec.add("i", []byte(cmd+"\n"))
	}
	output := shell.execute(cmd)
	if output != "" {
		_, _ = io.WriteString(channel, output)
		rec.add("o", []byte(output))
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
	s.finishSession(start, source, tcpAddr, "ssh", s.cfg.sshTargetPort, rec, auth, commands, nil)
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "idle timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (s *appState) finishSession(start time.Time, source string, tcpAddr *net.TCPAddr, protocol string, targetPort int, rec *recorder, auth Auth, commands []string, sessionErr error) {
	if isIdleTimeout(sessionErr) {
		s.log.Info("%s session from %s closed after %s idle", protocol, source, idleTimeout)
	} else if sessionErr != nil && !errors.Is(sessionErr, io.EOF) {
		s.log.Warn("session from %s ended: %v", source, sessionErr)
	}

	attackID := s.nextAttackID()
	payload := s.buildPayload(attackID, start, tcpAddr, protocol, targetPort, rec, auth, commands)

	status := "failed"
	reported := false
	dedup := false
	var hubAttackID uint64
	s.markCooldown(tcpAddr.IP.String(), start)
	if resp, err := s.sendWithRetry(payload); err != nil {
		atomic.AddUint64(&s.stats.ReportFailures, 1)
		s.log.Error("attack %d report failed: %v", attackID, err)
	} else {
		reported = true
		dedup = resp.Dedup
		hubAttackID = resp.AttackID
		status = "reported"
		atomic.AddUint64(&s.stats.Reported, 1)
		if resp.Dedup {
			status = "deduped"
			atomic.AddUint64(&s.stats.Deduped, 1)
		}
		s.log.Good("attack %d %s from %s (%d commands, %d bytes)", attackID, status, source, len(commands), rec.total)
	}
	atomic.AddUint64(&s.stats.TranscriptBytes, rec.total)
	s.addRecent(recentAttack{
		ID:          attackID,
		When:        start,
		Protocol:    protocol,
		Source:      source,
		User:        auth.User,
		Pass:        auth.Pass,
		Commands:    len(commands),
		Bytes:       rec.total,
		Truncated:   rec.truncated,
		Reported:    reported,
		Dedup:       dedup,
		Status:      status,
		HubAttackID: hubAttackID,
	})
}

func (s *appState) isInCooldown(ip string, now time.Time) (time.Time, bool) {
	if s.cfg.ipCooldown <= 0 {
		return time.Time{}, false
	}
	s.cooldownMu.Lock()
	defer s.cooldownMu.Unlock()
	if until, ok := s.cooldownUntil[ip]; ok && now.Before(until) {
		return until, true
	}
	return time.Time{}, false
}

func (s *appState) markCooldown(ip string, now time.Time) {
	if s.cfg.ipCooldown <= 0 {
		return
	}
	s.cooldownMu.Lock()
	defer s.cooldownMu.Unlock()
	until := now.Add(s.cfg.ipCooldown)
	s.cooldownUntil[ip] = until
}

func isIdleTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (s *appState) buildPayload(id uint64, start time.Time, tcpAddr *net.TCPAddr, protocol string, targetPort int, rec *recorder, auth Auth, commands []string) Payload {
	profile, confidence := classify(commands, tcpAddr.IP)
	return Payload{
		Schema: schemaVersion,
		Honeypot: Honeypot{
			DeviceID:        s.cfg.deviceID,
			FirmwareVersion: s.cfg.firmware,
			FirmwareBuild:   processStarted.UTC().Format(time.RFC3339),
			UptimeS:         uint64(time.Since(processStarted).Seconds()),
			Hardware: Hardware{
				MCU:     s.cfg.mcu,
				Board:   s.cfg.board,
				Display: s.cfg.display,
				FlashMB: s.cfg.flashMB,
				PSRAMKB: s.cfg.psramKB,
				CPUMHz:  s.cfg.cpuMHz,
			},
		},
		Attack: Attack{
			ID:         id,
			TS:         start.UTC().Format(time.RFC3339Nano),
			DurationMS: uint64(math.Max(0, float64(time.Since(start).Milliseconds()))),
			Protocol:   protocol,
			Source:     Source{IP: tcpAddr.IP.String(), Port: tcpAddr.Port},
			Target:     &Target{Port: targetPort},
			Auth:       auth,
			Session: &Session{
				Commands:      len(commands),
				Events:        rec.events,
				CastTruncated: rec.truncated,
				Term:          &Term{Cols: 80, Rows: 24},
			},
			Classification: &Classification{
				Profile:        profile,
				Confidence:     confidence,
				CommandSummary: strings.Join(commands, "\n"),
			},
		},
	}
}

func classify(commands []string, ip net.IP) (string, int) {
	if ip.IsLoopback() || ip.IsPrivate() {
		return "lan", 90
	}
	if len(commands) == 0 {
		return "creds-only", 70
	}
	summary := strings.ToLower(strings.Join(commands, "\n"))
	switch {
	case strings.Contains(summary, "mirai") || strings.Contains(summary, "busybox"):
		return "mirai", 80
	case strings.Contains(summary, "wget") || strings.Contains(summary, "curl") || strings.Contains(summary, "chmod"):
		return "iot-loader", 75
	case strings.Contains(summary, "xmrig") || strings.Contains(summary, "stratum"):
		return "crypto-miner", 85
	default:
		return "scripted", 55
	}
}

func (s *appState) sendWithRetry(payload Payload) (hubResponse, error) {
	backoffs := []time.Duration{0, 5 * time.Second, 15 * time.Second, 60 * time.Second, 300 * time.Second}
	var lastErr error
	for attempt, wait := range backoffs {
		if wait > 0 {
			time.Sleep(wait)
		}
		resp, retryAfter, err := s.sendOnce(payload)
		if err == nil {
			if resp.MaxHPLocalID > 0 {
				s.bumpCounter(resp.MaxHPLocalID)
			}
			return resp, nil
		}
		lastErr = err
		if !isRetryable(err) {
			return hubResponse{}, err
		}
		if retryAfter > 0 && attempt < len(backoffs)-1 {
			time.Sleep(retryAfter)
		}
	}
	return hubResponse{}, lastErr
}

type httpStatusError struct {
	code int
	msg  string
}

func (e httpStatusError) Error() string { return e.msg }

func isRetryable(err error) bool {
	var status httpStatusError
	if !errors.As(err, &status) {
		return true
	}
	return status.code == http.StatusTooManyRequests || status.code >= 500
}

func (s *appState) sendOnce(payload Payload) (hubResponse, time.Duration, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return hubResponse{}, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, s.cfg.hubURL, bytes.NewReader(body))
	if err != nil {
		return hubResponse{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+s.cfg.token)
	req.Header.Set("User-Agent", "HoneyMire-Honeypot/"+s.cfg.firmware)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return hubResponse{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("hub returned HTTP %d", resp.StatusCode)
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		if len(data) > 0 {
			msg += ": " + strings.TrimSpace(string(data))
		}
		if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(msg), "csrf") {
			msg += " (check HONEYMIRE_HUB_URL: the reporter must POST to /api/v1/ingest, not a browser page)"
		}
		return hubResponse{}, parseRetryAfter(resp.Header.Get("Retry-After")), httpStatusError{code: resp.StatusCode, msg: msg}
	}

	var decoded hubResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return hubResponse{}, 0, err
	}
	return decoded, 0, nil
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		return time.Until(when)
	}
	return 0
}

func (s *appState) loadCounter() {
	data, err := os.ReadFile(counterFile)
	if err != nil {
		return
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		s.log.Warn("ignoring invalid %s: %v", counterFile, err)
		return
	}
	atomic.StoreUint64(&s.attackCounter, id)
}

func (s *appState) nextAttackID() uint64 {
	id := atomic.AddUint64(&s.attackCounter, 1)
	s.persistCounter(id)
	return id
}

func (s *appState) bumpCounter(maxSeen uint64) {
	for {
		current := atomic.LoadUint64(&s.attackCounter)
		if maxSeen <= current {
			return
		}
		if atomic.CompareAndSwapUint64(&s.attackCounter, current, maxSeen) {
			s.persistCounter(maxSeen)
			s.log.Warn("local counter recovered to %d from hub max_hp_local_id=%d", maxSeen, maxSeen)
			return
		}
	}
}

func (s *appState) persistCounter(id uint64) {
	s.counterMu.Lock()
	defer s.counterMu.Unlock()
	_ = os.WriteFile(counterFile, []byte(fmt.Sprintf("%d\n", id)), 0644)
}

func (s *appState) addRecent(a recentAttack) {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	s.recent = append([]recentAttack{a}, s.recent...)
	if len(s.recent) > 50 {
		s.recent = s.recent[:50]
	}
}

func (s *appState) serveDashboard() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dashboardHTML)
	mux.HandleFunc("/api/status", s.statusJSON)
	mux.HandleFunc("/dashboard-login", s.dashboardLogin)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})

	handler := s.dashboardAuthMiddleware(mux)
	if s.cfg.dashboardHost != "" {
		if err := os.MkdirAll(s.cfg.certCache, 0700); err != nil {
			s.log.Error("certificate cache setup failed: %v", err)
			return
		}
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.cfg.dashboardHost),
			Cache:      autocert.DirCache(s.cfg.certCache),
		}
		s.log.Info("dashboard TLS host %s using ACME cache %s", s.cfg.dashboardHost, s.cfg.certCache)
		if s.cfg.dashboardAuth == "" {
			s.log.Warn("public HTTPS dashboard has no DASHBOARD_AUTH")
		}
		redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + s.cfg.dashboardHost + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		go func() {
			s.log.Good("dashboard ACME/redirect listening on http://%s:80", s.cfg.dashboardHost)
			if err := http.ListenAndServe(":80", manager.HTTPHandler(redirect)); err != nil {
				s.log.Error("dashboard HTTP listener stopped: %v", err)
			}
		}()
		server := &http.Server{
			Addr:      ":443",
			Handler:   handler,
			TLSConfig: manager.TLSConfig(),
		}
		s.log.Good("dashboard listening on https://%s", s.cfg.dashboardHost)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			s.log.Error("dashboard HTTPS listener stopped: %v", err)
		}
		return
	}

	s.log.Good("dashboard listening on http://localhost%s", s.cfg.dashboard)
	if err := http.ListenAndServe(s.cfg.dashboard, handler); err != nil {
		s.log.Error("dashboard stopped: %v", err)
	}
}

func (s *appState) dashboardAuthMiddleware(next http.Handler) http.Handler {
	if s.cfg.dashboardAuth == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/dashboard-login" {
			next.ServeHTTP(w, r)
			return
		}
		if s.dashboardAuthorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.Error(w, "dashboard auth required", http.StatusUnauthorized)
			return
		}
		s.dashboardLoginForm(w, "")
	})
}

func (s *appState) dashboardAuthorized(r *http.Request) bool {
	if s.cfg.dashboardAuth == "" {
		return true
	}
	if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != r.Header.Get("Authorization") {
		return constantTokenEqual(bearer, s.cfg.dashboardAuth)
	}
	cookie, err := r.Cookie("honeymire_dashboard")
	if err != nil {
		return false
	}
	return constantTokenEqual(cookie.Value, dashboardAuthCookieValue(s.cfg.dashboardAuth))
}

func (s *appState) dashboardLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.dashboardLoginForm(w, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.dashboardLoginForm(w, "Invalid form submission.")
		return
	}
	if !constantTokenEqual(r.FormValue("token"), s.cfg.dashboardAuth) {
		s.dashboardLoginForm(w, "Invalid dashboard token.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "honeymire_dashboard",
		Value:    dashboardAuthCookieValue(s.cfg.dashboardAuth),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.cfg.dashboardHost != "",
		MaxAge:   30 * 24 * 60 * 60,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *appState) dashboardLoginForm(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = dashboardLoginTemplate.Execute(w, struct {
		Message string
	}{Message: message})
}

func dashboardAuthCookieValue(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func constantTokenEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *appState) snapshot() dashboardData {
	s.recentMu.RLock()
	recent := append([]recentAttack(nil), s.recent...)
	s.recentMu.RUnlock()
	return dashboardData{
		DeviceID: s.cfg.deviceID,
		Telnet:   s.cfg.telnetListen,
		SSH:      s.cfg.sshListen,
		HubURL:   hubOrigin(s.cfg.hubURL),
		Board:    s.cfg.board,
		Uptime:   humanDuration(time.Since(processStarted)),
		Counter:  atomic.LoadUint64(&s.attackCounter),
		Stats: stats{
			StartedAt:        s.stats.StartedAt,
			Connections:      atomic.LoadUint64(&s.stats.Connections),
			Reported:         atomic.LoadUint64(&s.stats.Reported),
			ReportFailures:   atomic.LoadUint64(&s.stats.ReportFailures),
			Suppressed:       atomic.LoadUint64(&s.stats.Suppressed),
			RejectedCooldown: atomic.LoadUint64(&s.stats.RejectedCooldown),
			Deduped:          atomic.LoadUint64(&s.stats.Deduped),
			TranscriptBytes:  atomic.LoadUint64(&s.stats.TranscriptBytes),
		},
		Recent: recent,
	}
}

func hubOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return value
	}
	return parsed.Scheme + "://" + parsed.Host
}

func (s *appState) dashboardHTML(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, s.snapshot()); err != nil {
		s.log.Warn("dashboard render failed: %v", err)
	}
}

func (s *appState) statusJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.snapshot())
}

type dashboardData struct {
	DeviceID string         `json:"device_id"`
	Telnet   string         `json:"telnet"`
	SSH      string         `json:"ssh"`
	HubURL   string         `json:"hub_url"`
	Board    string         `json:"board"`
	Uptime   string         `json:"uptime"`
	Counter  uint64         `json:"counter"`
	Stats    stats          `json:"stats"`
	Recent   []recentAttack `json:"recent"`
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %02ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

var dashboardLoginTemplate = template.Must(template.New("dashboard-login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HoneyMire Dashboard Login</title>
  <style>
    :root {
      --bg:#111418; --fg:#d9dee6; --mut:#8993a3; --card:#161a20;
      --panel:#1a1f26; --acc:#c9a45b; --bad:#c95b65; --bord:#2a3038;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font: 14px/1.45 -apple-system, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0f1216;
      color: var(--fg);
      padding: 18px;
    }
    form {
      width: min(380px, 100%);
      background: var(--card);
      border: 1px solid var(--bord);
      border-radius: 6px;
      padding: 18px;
    }
    h1 { margin: 0 0 14px; font-size: 15px; font-weight: 650; }
    label { display: block; color: var(--mut); font-size: 12px; margin-bottom: 6px; }
    input {
      width: 100%;
      background: var(--panel);
      border: 1px solid var(--bord);
      border-radius: 4px;
      color: var(--fg);
      font: inherit;
      padding: 9px 10px;
    }
    button {
      margin-top: 12px;
      width: 100%;
      background: var(--acc);
      border: 0;
      border-radius: 4px;
      color: #111418;
      font-weight: 650;
      padding: 9px 10px;
      cursor: pointer;
    }
    .msg { color: var(--bad); margin: 0 0 10px; }
  </style>
</head>
<body>
  <form method="post" action="/dashboard-login">
    <h1>HoneyMire Dashboard</h1>
    {{if .Message}}<p class="msg">{{.Message}}</p>{{end}}
    <label for="token">Dashboard token</label>
    <input id="token" name="token" type="password" autocomplete="current-password" autofocus>
    <button type="submit">Enter</button>
  </form>
</body>
</html>`))

var dashboardTemplate = template.Must(template.New("dashboard").Funcs(template.FuncMap{
	"since": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return humanDuration(time.Since(t)) + " ago"
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <title>HoneyMire Honeypot</title>
  <style>
    :root {
      --bg:#111418; --fg:#d9dee6; --mut:#8993a3; --card:#161a20;
      --panel:#1a1f26; --acc:#c9a45b; --bad:#c95b65; --good:#6aa57a;
      --bord:#2a3038; --link:#9bb6d8; --code:#0d1014;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      font: 14px/1.45 -apple-system, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #0f1216;
      color: var(--fg);
    }
    header {
      padding: 12px 22px;
      border-bottom: 1px solid var(--bord);
      background: rgba(18, 22, 27, .96);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    header h1 { margin: 0; font-size: 15px; color: var(--fg); font-weight: 650; }
    nav span { color: var(--mut); margin-left: 14px; font-size: 13px; }
    main { padding: 22px; max-width: 1520px; margin: 0 auto; }
    .card { background: var(--card); border: 1px solid var(--bord); border-radius: 6px; padding: 16px; margin-bottom: 16px; }
    .card h3 { margin: 0 0 12px; font-size: 15px; font-weight: 650; color: #eef2f7; }
    .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
    .kpi { background: var(--panel); border: 1px solid var(--bord); border-radius: 6px; padding: 11px 12px; }
    .kpi b { display: block; font-size: 20px; color: var(--fg); font-weight: 650; }
    .kpi span { color: var(--mut); font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; }
    th, td { padding: 9px 10px; border-bottom: 1px solid var(--bord); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: var(--mut); font-weight: 600; text-transform: uppercase; letter-spacing: .04em; font-size: 11px; background: #14181e; }
    tr:hover td { background: #191e25; }
    code { background: var(--code); border: 1px solid var(--bord); border-radius: 4px; padding: 1px 4px; color: #e8edf5; }
    .mut { color: var(--mut); }
    .status { display:inline-block; min-width: 70px; padding: 2px 7px; border-radius: 999px; border: 1px solid var(--bord); color: var(--mut); text-align:center; }
    .status.reported, .status.deduped { color: var(--good); border-color: rgba(106,165,122,.45); }
    .status.suppressed { color: var(--mut); border-color: rgba(137,147,163,.45); }
    .status.failed { color: var(--bad); border-color: rgba(201,91,101,.45); }
    .topline { display:flex; justify-content:space-between; gap: 16px; flex-wrap:wrap; color: var(--mut); font-size: 13px; }
    .empty { color: var(--mut); padding: 20px 0 4px; }
    @media (max-width: 780px) {
      main { padding: 14px; }
      table, thead, tbody, th, td, tr { display: block; }
      thead { display: none; }
      td { border-bottom: 0; padding: 6px 0; }
      tr { border-bottom: 1px solid var(--bord); padding: 10px 0; }
    }
  </style>
</head>
<body>
  <header>
    <h1>HoneyMire Honeypot</h1>
    <nav><span>{{.DeviceID}}</span><span>{{.Board}}</span></nav>
  </header>
  <main>
    <section class="card">
      <div class="topline">
        <span>Telnet <code>{{.Telnet}}</code></span>
        <span>SSH <code>{{.SSH}}</code></span>
        <span>Hub <code>{{.HubURL}}</code></span>
        <span>Uptime <code>{{.Uptime}}</code></span>
      </div>
    </section>
    <section class="card">
      <div class="topline">
        <span>HoneyMire is an ESP32 and edge honeypot project for capturing SSH/Telnet attack sessions and forwarding them to a Hub for analysis.</span>
        <span><a href="https://honeymire.org" rel="noopener noreferrer">honeymire.org</a> · <a href="https://github.com/honeymire/honeymire" rel="noopener noreferrer">GitHub</a></span>
      </div>
    </section>
    <section class="kpis card">
      <div class="kpi"><b>{{.Stats.Connections}}</b><span>Connections</span></div>
      <div class="kpi"><b>{{.Stats.Reported}}</b><span>Reported</span></div>
      <div class="kpi"><b>{{.Stats.ReportFailures}}</b><span>Failures</span></div>
      <div class="kpi"><b>{{.Stats.Suppressed}}</b><span>Suppressed</span></div>
      <div class="kpi"><b>{{.Stats.RejectedCooldown}}</b><span>Cooldown drops</span></div>
      <div class="kpi"><b>{{.Stats.Deduped}}</b><span>Deduped</span></div>
      <div class="kpi"><b>{{.Counter}}</b><span>Local counter</span></div>
      <div class="kpi"><b>{{.Stats.TranscriptBytes}}</b><span>Transcript bytes</span></div>
    </section>
    <section class="card">
      <h3>Recent attacks</h3>
      {{if .Recent}}
      <table>
        <thead><tr><th>When</th><th>Proto</th><th>Source</th><th>Creds</th><th>Commands</th><th>Bytes</th><th>Status</th></tr></thead>
        <tbody>
          {{range .Recent}}
          <tr>
            <td class="mut">{{since .When}}</td>
            <td><code>{{.Protocol}}</code></td>
            <td><code>{{.Source}}</code></td>
            <td><code>{{.User}}</code> / <code>{{.Pass}}</code></td>
            <td>{{.Commands}}</td>
            <td>{{.Bytes}}{{if .Truncated}} <span class="mut">truncated</span>{{end}}</td>
            <td><span class="status {{.Status}}">{{.Status}}</span></td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <div class="empty">No captured sessions yet.</div>
      {{end}}
    </section>
  </main>
</body>
</html>`))
