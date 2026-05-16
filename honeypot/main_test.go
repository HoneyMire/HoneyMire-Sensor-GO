package main

import (
	"bufio"
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newTestTelnetSession(input []byte, out *bytes.Buffer) *telnetSession {
	return &telnetSession{
		reader: bufio.NewReader(bytes.NewReader(input)),
		out:    out,
		rec:    &recorder{},
		paused: false,
	}
}

func TestTelnetReadLineStripsNegotiation(t *testing.T) {
	input := []byte{
		telnetIAC, telnetWILL, 1, // peer says WILL ECHO -> we reply DONT
		telnetIAC, telnetDO, 99, // unknown option we did not assert -> we reply WONT
		'h', 'i', '\r', '\n',
	}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, ctrlC, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine returned error: %v", err)
	}
	if ctrlC {
		t.Fatal("ctrl-c flagged unexpectedly")
	}
	if line != "hi" {
		t.Fatalf("line = %q, want %q", line, "hi")
	}

	want := []byte{
		telnetIAC, telnetDONT, 1, // reply to WILL ECHO
		telnetIAC, telnetWONT, 99, // reply to DO unknown
		'h', 'i', // per-byte echo
		'\r', '\n', // CRLF after enter
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out = %v, want %v", out.Bytes(), want)
	}
}

func TestTelnetReadLineHonorsPriorAssertion(t *testing.T) {
	// After we assert WILL ECHO+SGA the peer's DO 1 / DO 3 are
	// confirmations; we must not respond with WONT.
	input := []byte{
		telnetIAC, telnetDO, telnetOptECHO,
		telnetIAC, telnetDO, telnetOptSGA,
		'x', '\r', '\n',
	}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	if _, _, err := sess.readLine(false); err != nil {
		t.Fatalf("readLine: %v", err)
	}
	want := []byte{'x', '\r', '\n'}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out = %v, want %v (no negotiation reply expected)", out.Bytes(), want)
	}
}

func TestTelnetReadLineSkipsSubnegotiation(t *testing.T) {
	input := []byte{
		telnetIAC, telnetSB, 31, 0, 80, 0, 24, telnetIAC, telnetSE,
		'i', 'd', '\n',
	}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, _, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine returned error: %v", err)
	}
	if line != "id" {
		t.Fatalf("line = %q, want %q", line, "id")
	}
}

func TestTelnetReadLineBackspace(t *testing.T) {
	input := []byte{'a', 'b', 0x7f, 'c', '\r', '\n'}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, _, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if line != "ac" {
		t.Fatalf("line = %q, want %q", line, "ac")
	}
	want := []byte{'a', 'b', '\b', ' ', '\b', 'c', '\r', '\n'}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out = %v, want %v", out.Bytes(), want)
	}
}

func TestTelnetReadLinePasswordMasking(t *testing.T) {
	input := []byte{'s', 'e', 'c', '\r', '\n'}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, _, err := sess.readLine(true)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if line != "sec" {
		t.Fatalf("line = %q, want %q", line, "sec")
	}
	want := []byte{'*', '*', '*', '\r', '\n'}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out = %v, want %v", out.Bytes(), want)
	}
}

func TestTelnetReadLineCtrlC(t *testing.T) {
	input := []byte{'a', 'b', 0x03}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, ctrlC, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if !ctrlC {
		t.Fatal("expected ctrl-c flag")
	}
	if line != "" {
		t.Fatalf("line = %q, want empty after ctrl-c", line)
	}
	want := []byte{'a', 'b', '^', 'C', '\r', '\n'}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("out = %v, want %v", out.Bytes(), want)
	}
}

func TestTelnetReadLineCapBell(t *testing.T) {
	// Type one byte past the cap; expect a single \a bell and the
	// over-cap byte to be dropped.
	input := make([]byte, telnetLineMaxBytes+2)
	for i := 0; i < telnetLineMaxBytes; i++ {
		input[i] = 'x'
	}
	input[telnetLineMaxBytes] = 'y'
	input[telnetLineMaxBytes+1] = '\n'
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, _, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if len(line) != telnetLineMaxBytes {
		t.Fatalf("line length = %d, want %d", len(line), telnetLineMaxBytes)
	}
	if !bytes.Contains(out.Bytes(), []byte{'\a'}) {
		t.Fatal("expected bell byte in echo stream")
	}
	if bytes.Count(out.Bytes(), []byte{'\a'}) != 1 {
		t.Fatal("expected exactly one bell byte (rearm-on-cleanup only)")
	}
}

func TestTelnetReadLineStripsControlChars(t *testing.T) {
	input := []byte{'a', 0x01, 0x1f, 'b', '\r', '\n'}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)

	line, _, err := sess.readLine(false)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if line != "ab" {
		t.Fatalf("line = %q, want %q", line, "ab")
	}
}

func TestTelnetReadLineRecordsLineGrain(t *testing.T) {
	input := []byte{'l', 's', '\r', '\n'}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)
	rec := sess.rec

	if _, _, err := sess.readLine(false); err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if len(rec.events) == 0 {
		t.Fatal("expected at least one recorded event")
	}
	// First recorded event should be input-direction with full line+CRLF.
	if rec.events[0].K != "i" {
		t.Fatalf("first event kind = %q, want %q", rec.events[0].K, "i")
	}
	if rec.events[0].D != "ls\r\n" {
		t.Fatalf("first event data = %q, want %q", rec.events[0].D, "ls\r\n")
	}
}

func TestTelnetReadLinePausedSkipsRecording(t *testing.T) {
	input := []byte{'r', 'o', 'o', 't', '\r', '\n'}
	var out bytes.Buffer
	sess := newTestTelnetSession(input, &out)
	sess.paused = true

	if _, _, err := sess.readLine(false); err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if len(sess.rec.events) != 0 {
		t.Fatalf("expected no recorded events while paused, got %d", len(sess.rec.events))
	}
}

func TestParseSSHExecCommand(t *testing.T) {
	payload := ssh.Marshal(struct {
		Command string
	}{Command: "uname -a"})

	if got := parseSSHExecCommand(payload); got != "uname -a" {
		t.Fatalf("parseSSHExecCommand = %q, want %q", got, "uname -a")
	}
}

func TestParseSSHExecCommandCap(t *testing.T) {
	long := bytes.Repeat([]byte("a"), sshExecMaxBytes+200)
	payload := ssh.Marshal(struct {
		Command string
	}{Command: string(long)})

	got := parseSSHExecCommand(payload)
	if len(got) != sshExecMaxBytes {
		t.Fatalf("len = %d, want %d", len(got), sshExecMaxBytes)
	}
}

func TestFakeShellEmptyCommand(t *testing.T) {
	shell := newFakeShell("root", ubuntuPersona())
	if got := shell.execute(""); got != "" {
		t.Fatalf("empty command = %q, want empty", got)
	}
}

func TestFakeShellMiraiProbeSequence(t *testing.T) {
	shell := newFakeShell("root", personaProfile{
		name:        personaBusyBox,
		hostname:    "router",
		fakeUser:    "admin",
		notFoundFmt: "%s: not found\n",
	})
	for _, cmd := range []string{"enable", "shell", "sh"} {
		if got := shell.execute(cmd); got != "" {
			t.Fatalf("%s = %q, want empty", cmd, got)
		}
	}
	if got := shell.execute("/bin/busybox MIRAI"); got != "MIRAI: applet not found\r\n" {
		t.Fatalf("busybox probe = %q", got)
	}
}
