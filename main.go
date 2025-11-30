package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	dns "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/model"
	region "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/dns/v2/region"
)

// 命令行参数结构
type Config struct {
	ListURL   string
	TargetURL string
	AK        string
	SK        string
	ZoneID    string
	Domain    string // 完整域名 e.g. eo.example.com
	Region    string
	Threads   int
}

type Result struct {
	IP      string
	Latency float64
}

func main() {
	// 1. 定义和解析命令行参数
	cfg := Config{}
	flag.StringVar(&cfg.ListURL, "u", "", "IP列表下载地址 (http/https)")
	flag.StringVar(&cfg.TargetURL, "t", "", "测速目标URL (用于验证连通性)")
	flag.StringVar(&cfg.AK, "ak", "", "华为云 Access Key")
	flag.StringVar(&cfg.SK, "sk", "", "华为云 Secret Key")
	flag.StringVar(&cfg.ZoneID, "zone", "", "华为云 Zone ID")
	flag.StringVar(&cfg.Domain, "domain", "", "要更新的完整域名 (不带末尾点)")
	flag.StringVar(&cfg.Region, "region", "cn-east-3", "华为云区域 (默认 cn-east-3)")
	flag.IntVar(&cfg.Threads, "n", 20, "并发线程数")
	flag.Parse()

	if cfg.ListURL == "" || cfg.TargetURL == "" || cfg.AK == "" || cfg.SK == "" || cfg.ZoneID == "" || cfg.Domain == "" {
		fmt.Println("错误: 缺少必要参数。")
		flag.Usage()
		os.Exit(1)
	}

	// 2. 下载 IP 列表
	fmt.Printf("[1/4] 正在下载 IP 列表: %s\n", cfg.ListURL)
	ips, err := downloadIPs(cfg.ListURL)
	if err != nil {
		fmt.Printf("下载失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      获取到 %d 个 IP\n", len(ips))

	// 3. 测速
	fmt.Printf("[2/4] 开始测速 (Target: %s, Threads: %d)\n", cfg.TargetURL, cfg.Threads)
	bestIP := runSpeedTest(ips, cfg.TargetURL, cfg.Threads)
	if bestIP == "" {
		fmt.Println("      未找到可用 IP，程序退出。")
		os.Exit(1)
	}
	fmt.Printf("      最优 IP: %s\n", bestIP)

	// 4. 更新 DNS
	fmt.Printf("[3/4] 更新华为云 DNS (%s -> %s)\n", cfg.Domain, bestIP)
	if err := updateHuaweiDNS(cfg, bestIP); err != nil {
		fmt.Printf("      更新失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[4/4] 全部完成！SUCCESS")
}

// 下载 IP 列表
func downloadIPs(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ips []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, nil
}

// 测速核心逻辑
func runSpeedTest(ips []string, targetURL string, concurrency int) string {
	u, _ := url.Parse(targetURL)
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	results := make(chan Result, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(testIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 强制指定 IP 连接
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			transport := &http.Transport{
				DialContext: func(ctx, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, testIP+":"+port)
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
			}
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}

			start := time.Now()
			resp, err := client.Get(targetURL)
			if err == nil {
				defer resp.Body.Close()
				latency := float64(time.Since(start).Milliseconds())
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					results <- Result{IP: testIP, Latency: latency}
					fmt.Printf(".") // 进度条效果
				}
			}
		}(ip)
	}

	wg.Wait()
	close(results)
	fmt.Println()

	var validResults []Result
	for r := range results {
		validResults = append(validResults, r)
	}

	if len(validResults) == 0 {
		return ""
	}

	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Latency < validResults[j].Latency
	})

	return validResults[0].IP
}

// 华为云 DNS 更新逻辑
func updateHuaweiDNS(cfg Config, ip string) error {
	auth := basic.NewCredentialsBuilder().
		WithAk(cfg.AK).
		WithSk(cfg.SK).
		Build()

	client := dns.NewDnsClient(
		dns.DnsClientBuilder().
			WithRegion(region.ValueOf(cfg.Region)).
			WithCredential(auth).
			Build())

	// 1. 必须先搜索到 Record ID
	listReq := &model.ListRecordSetsRequest{}
	listReq.ZoneId = &cfg.ZoneID
	listReq.Name = &cfg.Domain // 搜索该域名
	resp, err := client.ListRecordSets(listReq)
	if err != nil {
		return fmt.Errorf("查询记录集失败: %v", err)
	}

	var recordID string
	// 华为云返回的 Name 默认带点，需要处理
	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	if resp.Recordsets != nil {
		for _, r := range *resp.Recordsets {
			if r.Name != nil && *r.Name == searchDomain {
				recordID = *r.Id
				break
			}
		}
	}

	if recordID == "" {
		return fmt.Errorf("未在 Zone 中找到域名 %s 的记录，请先手动创建一条。", cfg.Domain)
	}

	// 2. 更新记录
	updateReq := &model.UpdateRecordSetRequest{
		ZoneId:      cfg.ZoneID,
		RecordsetId: recordID,
	}
	body := &model.UpdateRecordSetReq{
		Records: []string{ip},
		Type:    "A",
		Ttl:     io.Pointer(int32(300)), // 5分钟 TTL
		Name:    searchDomain,
	}
	updateReq.Body = body

	_, err = client.UpdateRecordSet(updateReq)
	return err
}

// 辅助函数：生成指针 (Go SDK 需要)
func Pointer[T any](v T) *T {
	return &v
}