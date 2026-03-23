# UDP 扫描使用说明

`gonmap` 现在支持通过 `ScanOptions.Protocol` 显式指定 UDP 扫描。

## 示例

```go
package main

import (
	"time"

	"github.com/qiwentaidi/gonmap"
)

func main() {
	engine := gonmap.New()

	status, resp := engine.ScanWithOptions("8.8.8.8", 53, &gonmap.ScanOptions{
		Timeout:  5 * time.Second,
		Protocol: gonmap.ScanProtocolUDP,
	})

	_, _ = status, resp
}
```

## 协议选项

- `gonmap.ScanProtocolAuto`: 自动模式，沿用原有 TCP 优先逻辑
- `gonmap.ScanProtocolTCP`: 仅使用 TCP 探针
- `gonmap.ScanProtocolUDP`: 仅使用 UDP 探针

## 当前限制

- UDP 模式不会执行 TLS/SSL 二次探测
- `UDP + ProxyURL` 当前不支持，会直接返回错误
- SOCKS5 代理目前仅支持 TCP 路径
