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
- `DisableFingerprint`
- `Protocol`

[`lib.PortDiscoveryOptions`]() 当前支持：

- `Timeout`
- `Concurrency`
- `Mode`
- `Rate`

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

## 端口发现模式

端口发现模式常量在 [`lib/sdk.go`]() 中导出：

```go
lib.PortDiscoveryModeConnect
lib.PortDiscoveryModeSYN
```

默认使用 `connect`，也就是普通 TCP connect 检测。`syn` 模式只用于批量端口发现阶段，发现开放端口后，后续服务指纹识别仍然会走 `ScanOptions.Protocol: lib.ScanProtocolTCP` 的现有 TCP 探针流程。

SYN 模式在 Linux/macOS 上使用 raw IPv4 socket，需要 root/CAP_NET_RAW 等系统权限；Windows 上使用 Npcap/libpcap 二层发包，需要安装 Npcap 并以具备抓包发包权限的方式运行。SYN 模式不会在初始化、发包或解析失败时回退到 connect，避免结果来源产生歧义。

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
  当启用 `DisableFingerprint` 时，TCP 端口连通后也会直接返回这个状态。
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

### 0. 大规模目标先做端口发现，再做指纹识别

如果你要扫几百个目标，尤其是全端口，不建议直接对每个 `host:port` 调 `sdk.Scan()`。

原因很简单：

- `sdk.Scan()` 的定位是服务识别，不是高速端口发现
- 它会主动发送应用层探针，带宽和耗时都会明显高于纯 connect 扫描
- RustScan 快的核心也是先做高速端口发现，再把开放端口交给后续识别工具

推荐两阶段：

```go
package main

import (
	"fmt"
	"time"

	"github.com/qiwentaidi/gonmap/lib"
)

func main() {
	sdk := lib.New(nil)
	ports := lib.ExpandPortRange(1, 65535)

	openPorts := sdk.DiscoverOpenPorts([]string{"127.0.0.1"}, ports, &lib.PortDiscoveryOptions{
		Timeout:     time.Second,
		Concurrency: 4096,
	})

	for _, openPort := range openPorts {
		status, resp := sdk.Scan(openPort.Host, openPort.Port, &lib.ScanOptions{
			Timeout:  3 * time.Second,
			Protocol: lib.ScanProtocolTCP,
		})
		fmt.Println(openPort.Host, openPort.Port, status, resp != nil)
	}
}
```

这条路径更接近 RustScan 的思路：

- 第一阶段只做 TCP connect，速度快、带宽低
- 第二阶段只对开放端口做 `gonmap` 指纹识别

如果希望第一阶段改成 SYN 发现：

```go
openPorts := sdk.DiscoverOpenPorts([]string{"127.0.0.1"}, ports, &lib.PortDiscoveryOptions{
	Mode:    lib.PortDiscoveryModeSYN,
	Timeout: 800 * time.Millisecond,
	Rate:    3000,
})
```

如果目标很多，connect 模式优先调这两个参数：

- `PortDiscoveryOptions.Concurrency`
- `PortDiscoveryOptions.Timeout`

SYN 模式优先调：

- `PortDiscoveryOptions.Rate`
- `PortDiscoveryOptions.Timeout`

如果你希望直接以“目标组 + 端口组”的方式跑完整流程，可以使用新的批量入口：

```go
result := sdk.ScanHostPorts("127.0.0.1", lib.ExpandPortRange(1, 1024), &lib.BatchScanOptions{
	DiscoveryOptions: lib.PortDiscoveryOptions{
		Timeout:     500 * time.Millisecond,
		Concurrency: 1024,
	},
	FingerprintOptions: lib.ScanOptions{
		Timeout:  2 * time.Second,
		Protocol: lib.ScanProtocolTCP,
	},
	FingerprintWorkers: 64,
})

fmt.Println("open:", result.OpenPorts)
fmt.Println("stable:", result.StablePorts)
fmt.Println("suspicious:", result.SuspiciousPorts)
fmt.Println("wrapped:", result.LikelyWrappedPorts)
fmt.Println("likely_noise:", result.LikelyNoise, result.NoiseReason)
```

批量入口会在发现开放端口时立即将其送入有界的指纹识别队列；发现与识别并行执行，最终返回值仍会等待两阶段完成并按端口排序。重复发现的同一主机端口只识别一次。直接调用 `DiscoverOpenPorts` 再逐个调用 `Scan` 的示例仍是分阶段执行。

SYN 发现版本只需要替换 `DiscoveryOptions`：

```go
DiscoveryOptions: lib.PortDiscoveryOptions{
	Mode:    lib.PortDiscoveryModeSYN,
	Timeout: 800 * time.Millisecond,
	Rate:    3000,
}
```

多目标版本：

```go
results := sdk.ScanHostsPorts([]string{
	"example.com",
	"example.net",
}, lib.ExpandPortRange(1, 65535), &lib.BatchScanOptions{})
```

如果你的上层已经拿到一批单端口结果，也可以只做后处理分析：

```go
analysis := lib.AnalyzeHostResults("example.com", []int{80, 20000}, []lib.BatchPortResult{
	{
		Port:   80,
		Status: lib.Matched,
		Response: &lib.Response{
			FingerPrint: &lib.FingerPrint{Service: "http", ProductName: "nginx"},
		},
	},
	{
		Port:   20000,
		Status: lib.Open,
	},
}, &lib.BatchScanOptions{})

fmt.Println(analysis.StablePorts)
fmt.Println(analysis.SuspiciousPorts)
fmt.Println(analysis.LikelyWrappedPorts)
```

这个入口会：

- 先批量做开放测试
- 再只对开放端口做指纹识别
- 最后按主机汇总结果
- 对“高位端口大量 generic open”做疑似噪音标记
- 对“高位端口统一落成 generic wrapped fingerprint”做疑似边界接管标记

如果你只关心端口是否开放，不关心协议识别，可以直接关闭识别层：

```go
status, resp := sdk.Scan("127.0.0.1", 22, &lib.ScanOptions{
	Timeout:            500 * time.Millisecond,
	Protocol:           lib.ScanProtocolTCP,
	DisableFingerprint: true,
})
fmt.Println(status, resp == nil) // Open true
```

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
