package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// hex_to_nmap_probe 工具
// 用途：将 nuclei 格式的 hex 字符串转换为 nmap probe 格式
//
// 使用方法：
//   go run ./cmd/hex_to_probe <hex_string>
//   go run ./cmd/hex_to_probe 00000000c8005100...
//
// 转换规则：
//   输入：连续的十六进制字符串（nuclei 格式）
//   输出：\xHH 转义序列格式（nmap probe 格式）
//
// 示例：
//   输入: "00000000c805"
//   输出: "\x00\x00\x00\x00\xc8\x05"
//
// 完整的 nmap probe 格式：
//   Probe TCP <ServiceName> q|<hex_escaped_bytes>|
//   例如：Probe TCP Dameng q|\x00\x00\x00\x00\xc8\x05|

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <hex_string>\n", os.Args[0])
		os.Exit(1)
	}

	output, err := toNmapProbe(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hex string: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(output)
}

func toNmapProbe(input string) (string, error) {
	normalized := strings.TrimSpace(input)
	normalized = strings.TrimPrefix(normalized, "0x")
	normalized = strings.TrimPrefix(normalized, "0X")

	data, err := hex.DecodeString(normalized)
	if err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.Grow(len(data) * 4)
	for _, b := range data {
		fmt.Fprintf(&builder, "\\x%02x", b)
	}
	return builder.String(), nil
}
