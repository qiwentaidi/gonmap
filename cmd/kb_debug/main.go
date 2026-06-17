package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "request timeout")
	useSSL := flag.Bool("ssl", false, "negotiate SSL before startup")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("usage: go run ./cmd/kb_debug [--ssl] host:port")
		return
	}

	target := flag.Arg(0)
	cases := []struct {
		name     string
		user     string
		database string
		extra    [][2]string
	}{
		{name: "startup_user_system_db_system", user: "system", database: "system"},
		{name: "startup_user_system", user: "system"},
		{name: "startup_user_kingbase", user: "kingbase"},
		{name: "startup_user_sys", user: "sys"},
		{name: "startup_database_system", database: "system"},
		{name: "startup_empty"},
		{name: "startup_user_system_app", user: "system", extra: [][2]string{{"application_name", "psql"}}},
	}

	for _, tc := range cases {
		fmt.Printf("== %s ==\n", tc.name)
		packet := buildStartupPacket(tc.user, tc.database, tc.extra...)
		fmt.Printf("packet_hex=%x\n", packet)
		text, err := sendStartup(target, *timeout, *useSSL, packet)
		if err != nil {
			fmt.Printf("error=%v\n\n", err)
			continue
		}
		raw := []byte(text)
		limit := min(160, len(raw))
		fmt.Printf("raw_len=%d\n", len(raw))
		fmt.Printf("raw_hex=%x\n", raw[:limit])
		fmt.Printf("raw_text=%s\n\n", strconv.QuoteToASCII(string(raw[:limit])))
	}
}

func buildStartupPacket(user, database string, extra ...[2]string) []byte {
	params := bytes.NewBuffer(nil)
	if user != "" {
		params.WriteString("user")
		params.WriteByte(0)
		params.WriteString(user)
		params.WriteByte(0)
	}
	if database != "" {
		params.WriteString("database")
		params.WriteByte(0)
		params.WriteString(database)
		params.WriteByte(0)
	}
	params.WriteString("client_encoding")
	params.WriteByte(0)
	params.WriteString("UTF8")
	params.WriteByte(0)
	for _, pair := range extra {
		if pair[0] == "" {
			continue
		}
		params.WriteString(pair[0])
		params.WriteByte(0)
		params.WriteString(pair[1])
		params.WriteByte(0)
	}
	params.WriteByte(0)

	totalLen := int32(4 + 4 + params.Len())
	packet := bytes.NewBuffer(make([]byte, 0, totalLen))
	_ = binary.Write(packet, binary.BigEndian, totalLen)
	_ = binary.Write(packet, binary.BigEndian, int32(196608))
	packet.Write(params.Bytes())
	return packet.Bytes()
}

func sendStartup(target string, timeout time.Duration, useSSL bool, packet []byte) (string, error) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if useSSL {
		if _, err := conn.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
			return "", err
		}
		reply := make([]byte, 1)
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		if _, err := io.ReadFull(conn, reply); err != nil {
			return "", err
		}
		if reply[0] != 'S' {
			return "", fmt.Errorf("ssl rejected: %q", reply[0])
		}
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ServerName:         splitNetlocHost(target),
		})
		if err := tlsConn.Handshake(); err != nil {
			return "", err
		}
		conn = tlsConn
	}

	if _, err := conn.Write(packet); err != nil {
		return "", err
	}

	var out bytes.Buffer
	tmp := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(tmp)
		if n > 0 {
			out.Write(tmp[:n])
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if n > 0 {
				break
			}
			return "", err
		}
		if n < len(tmp) {
			break
		}
	}
	return out.String(), nil
}

func splitNetlocHost(netloc string) string {
	host, _, err := net.SplitHostPort(netloc)
	if err == nil {
		return host
	}
	return netloc
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
