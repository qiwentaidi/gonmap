package gonmap

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Open 是端口开放，没有返回报文，没识别出协议
// Matched 是端口开放，且识别出协议
// NotMatched 是端口开放，有返回报文，但是没有识别出协议

type Nmap struct {
	exclude      []int
	portProbeMap map[int][]string
	probeNameMap map[string]*probe
	probeSort    []string

	filter             int
	defaultScanOptions ScanOptions

	bypassAllProbePort []int
	sslSecondProbeMap  []string
	allProbeMap        []string
	sslProbeMap        []string
}

//扫描类

func (n *Nmap) Scan(ip string, port int, timeout time.Duration, proxyURL string) (status Status, response *Response) {
	return n.ScanWithOptions(ip, port, &ScanOptions{
		Timeout:  timeout,
		ProxyURL: proxyURL,
	})
}

func (n *Nmap) ScanWithOptions(ip string, port int, options *ScanOptions) (status Status, response *Response) {
	scanOptions := n.normalizeScanOptions(options)
	return newScanSession(n, ip, port, scanOptions).scan()
}

func (n *Nmap) getFinger(responseRaw string, tls bool, requestName string) *FingerPrint {
	data := n.convResponse(responseRaw)
	probe := n.probeNameMap[requestName]

	finger := probe.match(data)

	if tls {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.probeNameMap[requestName].fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.probeNameMap[requestName].fallback
	fallbackProbe := n.probeNameMap[fallback]
	for fallback != "" {
		//logger.Println(requestName, " fallback is :", fallback)
		finger = fallbackProbe.match(data)
		fallback = n.probeNameMap[fallback].fallback
		if finger.Service != "" {
			break
		}
	}
	//标记当前探针名称
	finger.ProbeName = requestName
	return finger
}

func (n *Nmap) convResponse(s1 string) string {
	//为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	var builder strings.Builder
	builder.Grow(len(s1))
	for i := 0; i < len(s1); i++ {
		builder.WriteRune(rune(s1[i]))
	}
	return builder.String()
}

//配置类

func (n *Nmap) OpenDeepIdentify() {
	n.defaultScanOptions.DeepIdentify = true
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	var probe = n.probeNameMap[probeName]
	probe.loadMatch(expr, false)
}

//初始化类

func (n *Nmap) loads(s string) {
	lines := strings.Split(s, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeLines) != 0 {
				probeGroups = append(probeGroups, probeLines)
				probeLines = []string{}
			}
		}
		probeLines = append(probeLines, line)
	}
	probeGroups = append(probeGroups, probeLines)

	for _, lines := range probeGroups {
		p := parseProbe(lines)
		n.pushProbe(*p)
	}
}

func (n *Nmap) loadExclude(expr string) {
	n.exclude = parsePortList(expr)
}

func (n *Nmap) pushProbe(p probe) {
	n.probeSort = append(n.probeSort, p.name)
	n.probeNameMap[p.name] = &p

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	if p.rarity > n.filter {
		return
	}
	//0记录所有使用的探针
	n.portProbeMap[0] = append(n.portProbeMap[0], p.name)

	//分别压入sslports,ports
	for _, i := range p.ports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.name)
	}

	for _, i := range p.sslports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.name)
	}

}

func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeNameMap {
		fallback := probeType.fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.probeNameMap["TCP_"+fallback]; ok {
			n.probeNameMap[probeName].fallback = "TCP_" + fallback
		} else {
			n.probeNameMap[probeName].fallback = "UDP_" + fallback
		}
	}
}

func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

func (n *Nmap) sortOfRarity(list []string) []string {
	if len(list) == 0 {
		return list
	}
	var raritySplice []int
	for _, probeName := range list {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	for i := 0; i < len(raritySplice)-1; i++ {
		for j := 0; j < len(raritySplice)-i-1; j++ {
			if raritySplice[j] > raritySplice[j+1] {
				m := raritySplice[j+1]
				raritySplice[j+1] = raritySplice[j]
				raritySplice[j] = m
				mp := list[j+1]
				list[j+1] = list[j]
				list[j] = mp
			}
		}
	}

	for _, probeName := range list {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	return list
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 工具函数
func DnsScan(host string, port int) bool {
	domainServer := fmt.Sprintf("%s:%d", host, port)
	c := dns.Client{
		Timeout: 2 * time.Second,
	}
	m := dns.Msg{}
	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
	m.SetQuestion("www.baidu.com.", dns.TypeA)
	_, _, err := c.Exchange(&m, domainServer)
	if err == nil {
		return true
	} else {
		return false
	}
}
