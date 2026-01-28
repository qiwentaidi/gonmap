package main

import (
	"fmt"
	"os"
	"strings"
)

// hex_to_nmap_probe 工具
// 用途：将 nuclei 格式的 hex 字符串转换为 nmap probe 格式
//
// 使用方法：
//   go run cmd/hex_to_nmap_probe.go <hex_string>
//   go run cmd/hex_to_nmap_probe.go 00000000c8005100...
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
	if len(os.Args) < 2 {
		fmt.Println("用法: go run hex_to_nmap_probe.go <hex_string>")
		fmt.Println("示例: go run hex_to_nmap_probe.go 00000000c8005100")
		fmt.Println("\n将 nuclei 格式的 hex 字符串转换为 nmap probe 格式")
		os.Exit(1)
	}

	hexStr := os.Args[1]

	// 验证输入
	if len(hexStr)%2 != 0 {
		fmt.Fprintf(os.Stderr, "错误: hex 字符串长度必须是偶数\n")
		os.Exit(1)
	}

	// 转换为 \xHH 格式
	var result strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		result.WriteString("\\x")
		result.WriteString(hexStr[i : i+2])
	}

	nmapFormat := result.String()
	byteCount := len(hexStr) / 2

	// 输出结果
	fmt.Println("=== Hex 到 Nmap Probe 转换 ===")
	fmt.Printf("\n输入 (nuclei hex): %s\n", hexStr)
	fmt.Printf("字节数: %d\n\n", byteCount)

	fmt.Println("输出 (nmap probe 格式):")
	fmt.Println(nmapFormat)

	fmt.Println("\n完整的 Probe 定义示例:")
	fmt.Printf("Probe TCP ServiceName q|%s|\n", nmapFormat)

	// 分段输出（便于查看）
	fmt.Println("\n分段输出 (每10字节一行，便于检查):")
	for i := 0; i < len(hexStr); i += 20 {
		end := i + 20
		if end > len(hexStr) {
			end = len(hexStr)
		}
		for j := i; j < end; j += 2 {
			fmt.Printf("\\x%s", hexStr[j:j+2])
		}
		fmt.Println()
	}
}
