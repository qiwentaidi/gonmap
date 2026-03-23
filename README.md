# gonmap

`gonmap` 是一个基于 Nmap service probes 规则的服务识别库，适合在已知目标 `host:port` 上做协议识别、产品识别和基础指纹提取。

当前仓库已经整理出一层稳定的 SDK 入口，推荐外部项目优先通过 [`lib/sdk.go`](/Users/qwtd/Code/gonmap/lib/sdk.go) 使用，而不是直接依赖内部实现细节。

## 功能概览

- 支持 TCP 服务识别
- 支持 UDP 探针扫描入口
- 支持默认扫描参数配置
- 支持单次扫描参数覆盖
- 支持代理、超时、读取大小等常见控制项
- 支持快速扫描与深度识别两种使用方式

## 安装

```bash
go get github.com/qiwentaidi/gonmap
```

导入 SDK：

```go
import "github.com/qiwentaidi/gonmap/lib"
```

## 快速开始

最简单的调用方式：

```go
package main

import (
	"fmt"
	"time"

	"github.com/qiwentaidi/gonmap/lib"
)

func main() {
	sdk := lib.New(&lib.Options{
		Timeout:  5 * time.Second,
		Protocol: lib.ScanProtocolTCP,
	})

	status, resp := sdk.Scan("139.199.81.233", 5236, nil)
	fmt.Println("status:", status)

	if resp != nil && resp.FingerPrint != nil {
		fmt.Println("service:", resp.FingerPrint.Service)
		fmt.Println("product:", resp.FingerPrint.ProductName)
		fmt.Println("version:", resp.FingerPrint.Version)
	}
}
```

## SDK 使用方式

### 1. 创建 SDK

SDK 通过 [`lib.New()`]() 创建：

```go
sdk := lib.New(&lib.Options{
	Filter:       9,
	DeepIdentify: false,
	Timeout:      5 * time.Second,
	ProxyURL:     "",
	ReadSize:     10240,
	Protocol:     lib.ScanProtocolTCP,
})
```

如果不需要默认参数，也可以直接：

```go
sdk := lib.New(nil)
```

### 2. 扫描单个端口

```go
status, resp := sdk.Scan("114.132.250.138", 80, nil)
```

### 3. 覆盖默认参数

`lib.New()` 里配置的是默认参数，单次扫描时仍然可以覆盖：

```go
status, resp := sdk.Scan("114.132.250.138", 80, &lib.ScanOptions{
	Timeout:  10 * time.Second,
	Protocol: lib.ScanProtocolTCP,
	ReadSize: 4096,
})
```

覆盖规则：

- `lib.Options` 作为 SDK 默认配置
- `sdk.Scan(..., &lib.ScanOptions{})` 作为单次调用覆盖
- 单次调用里未填写的字段，继续沿用 SDK 默认值

## SDK 配置说明

[`lib.Options`]() 字段说明：

- `Filter`
  控制探针稀有度上限。值越小越偏快速扫描，值越大越偏完整识别。
- `DeepIdentify`
  是否启用更深度的探针识别流程。
- `Timeout`
  单个端口扫描的默认超时时间。
- `ProxyURL`
  默认代理地址，目前主要用于 TCP 扫描。
- `ReadSize`
  单次扫描读取响应的默认最大字节数。
- `Protocol`
  默认扫描协议，可选 `tcp`、`udp`、`auto`。

[`lib.ScanOptions`]() 当前支持：

- `Timeout`
- `ProxyURL`
- `ReadSize`
- `DeepIdentify`
- `Protocol`

## 扫描协议

协议常量在 [`lib/sdk.go`]() 中导出：

```go
lib.ScanProtocolAuto
lib.ScanProtocolTCP
lib.ScanProtocolUDP
```

建议：

- TCP 服务识别优先使用 `lib.ScanProtocolTCP`
- UDP 场景明确指定 `lib.ScanProtocolUDP`
- 不确定时可使用 `lib.ScanProtocolAuto`

UDP 示例：

```go
status, resp := sdk.Scan("114.132.250.138", 53, &lib.ScanOptions{
	Timeout:  5 * time.Second,
	Protocol: lib.ScanProtocolUDP,
})
```

## 返回值说明

扫描返回：

```go
status, resp := sdk.Scan(host, port, options)
```

### Status 含义

状态常量：

```go
lib.Closed
lib.Open
lib.Matched
lib.NotMatched
lib.Unknown
```

含义说明：

- `Matched`
  端口开放，并且识别到了协议或服务。
- `NotMatched`
  端口开放，收到了响应，但现有指纹没有匹配上。
- `Open`
  没有被明确判定为关闭，但也没有足够信息完成识别。
- `Closed`
  明确关闭。
- `Unknown`
  当前流程下无法给出确定结论，UDP 场景较常见。

### Response 结构

[`Response`]() 主要字段：

- `Raw`
  原始响应内容
- `TLS`
  是否通过 TLS 路径探测
- `FingerPrint`
  指纹结果

[`FingerPrint`]() 主要字段：

- `ProbeName`
- `Service`
- `ProductName`
- `Version`
- `Info`
- `Hostname`
- `OperatingSystem`
- `DeviceType`

## 常见使用模式

### 1. 默认参数统一配置

适合微服务或长期常驻进程：

```go
sdk := lib.New(&lib.Options{
	Timeout:  3 * time.Second,
	ReadSize: 10240,
	Protocol: lib.ScanProtocolTCP,
})

status, resp := sdk.Scan("1.1.1.1", 443, nil)
```

### 2. 单次任务单独覆盖

适合不同任务超时不同的场景：

```go
status, resp := sdk.Scan("1.1.1.1", 443, &lib.ScanOptions{
	Timeout:  15 * time.Second,
	Protocol: lib.ScanProtocolTCP,
})
```

### 3. 深度识别

```go
sdk := lib.New(&lib.Options{
	DeepIdentify: true,
	Timeout:      5 * time.Second,
})
```

### 4. 代理扫描

```go
sdk := lib.New(&lib.Options{
	Timeout:  5 * time.Second,
	ProxyURL: "socks5://127.0.0.1:1080",
	Protocol: lib.ScanProtocolTCP,
})
```
