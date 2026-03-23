package simplenet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type deadlineConn interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
}

var readChunkPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 256)
		return &buf
	},
}

var responseBufferPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func readResponse(conn deadlineConn, size int, allowEarlyBreak bool) (string, error) {
	tmpPtr := readChunkPool.Get().(*[]byte)
	tmp := *tmpPtr
	defer readChunkPool.Put(tmpPtr)

	buf := responseBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	if size > 0 {
		buf.Grow(min(size, 4096))
	}
	defer responseBufferPool.Put(buf)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		length, err := conn.Read(tmp)
		if length > 0 {
			_, _ = buf.Write(tmp[:length])
		}
		if allowEarlyBreak && length < len(tmp) {
			break
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", errors.New(err.Error() + " STEP3:READ")
		}
		if size > 0 && buf.Len() > size {
			break
		}
	}

	if buf.Len() == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return buf.String(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// netloc 主机地址
func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		//fmt.Println(conn)
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	// 设计权衡：当读取量小于缓冲区时提前退出，以加快扫描速度。
	// 这在大多数请求-响应协议中工作良好，但对分包传输可能截断响应。
	return readResponse(conn, size, true)
}

func tcpSendWithProxy(protocol string, netloc string, data string, duration time.Duration, size int, socksAddress string, auth *proxy.Auth) (string, error) {
	if socksAddress == "" {
		return "", errors.New("socks address is empty")
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddress, auth, &net.Dialer{
		Timeout: duration,
	})
	if err != nil {
		return "", err
	}
	protocol = strings.ToLower(protocol)
	conn, err := dialer.Dial(protocol, netloc)
	if err != nil {
		//fmt.Println(conn)
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	return readResponse(conn, size, true)
}

// tlsSend函数用于发送TLS请求
func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	// 将协议转换为小写
	protocol = strings.ToLower(protocol)
	// 创建TLS配置
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	// 创建网络拨号器
	dialer := &net.Dialer{
		Timeout:  duration,
		Deadline: time.Now().Add(duration * 2),
	}
	// 使用网络拨号器和TLS配置建立连接
	conn, err := tls.DialWithDialer(dialer, protocol, netloc, config)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	// 向连接中写入数据
	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	// TLS 版本不使用 early break，因为 TLS 记录可能分多次到达。
	return readResponse(conn, size, false)
}

func tlsSendWithProxy(protocol string, netloc string, data string, duration time.Duration, size int, socksAddress string, auth *proxy.Auth) (string, error) {
	if socksAddress == "" {
		return "", errors.New("socks address is empty")
	}

	// 创建 SOCKS5 代理 Dialer
	dialer, err := proxy.SOCKS5("tcp", socksAddress, auth, &net.Dialer{
		Timeout: duration,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	// 使用 Dialer 建立原始连接
	rawConn, err := dialer.Dial(protocol, netloc)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", netloc, err)
	}
	defer rawConn.Close()

	// 封装为 TLS 连接
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, // 跳过证书验证（生产环境需要谨慎）
		ServerName:         strings.Split(netloc, ":")[0],
	})

	// 执行 TLS 握手
	err = tlsConn.Handshake()
	if err != nil {
		return "", fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	// 发送数据
	_, err = tlsConn.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to send data: %w", err)
	}
	text, err := readResponse(tlsConn, size, false)
	if err != nil {
		return "", err
	}
	return text, nil
}

func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int, proxyURL string) (string, error) {
	protocol = strings.ToLower(protocol)
	if proxyURL != "" {
		if protocol == "udp" {
			return "", errors.New("SOCKS5 proxy for UDP is not supported")
		}
		u, err := url.Parse(proxyURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse proxy URL: %w", err)
		}
		var auth *proxy.Auth
		if u.User != nil {
			username := u.User.Username()
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: username, Password: password}
		}
		if tls {
			return tlsSendWithProxy(protocol, netloc, data, duration, size, u.Host, auth)
		} else {
			return tcpSendWithProxy(protocol, netloc, data, duration, size, u.Host, auth)
		}
	}
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
