package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tallowbrook.example/identity/internal/audit"
	"tallowbrook.example/identity/internal/passwords"
)

const adminUsage = `usage:
  idp admin htpasswd <user>       read a password on stdin, print the edge htpasswd line
  idp admin audit-key <dir>       create the audit key pair in dir
`

func admin(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, adminUsage)
		return 2
	}
	switch args[0] {
	case "htpasswd":
		in := bufio.NewReader(os.Stdin)
		pw, err := in.ReadString('\n')
		if err != nil && pw == "" {
			fmt.Fprintln(os.Stderr, "no password on stdin")
			return 1
		}
		line, err := passwords.HtpasswdLine(args[1], strings.TrimRight(pw, "\r\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(line)
		return 0
	case "audit-key":
		if err := writeAuditKey(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	default:
		fmt.Fprint(os.Stderr, adminUsage)
		return 2
	}
}

func writeAuditKey(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	priv, err := os.OpenFile(filepath.Join(dir, "audit-key.asc"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer priv.Close()
	pub, err := os.OpenFile(filepath.Join(dir, "audit-key.pub.asc"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer pub.Close()
	return audit.NewSigningKey(priv, pub)
}
