package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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
	ListURL   string // 在线URL
	FilePath  string // 本地文件路径
	TargetURL string
	AK        string
	SK        string
	ProjectID string // 新增：项目ID，解决鉴权报错
	ZoneID    string
	Domain    string
	Region    string
	Threads   int
}

type Result struct {
	IP      string
	Latency float64
}

func main() {
	cfg := Config{}
	// 参数定义
	flag.StringVar(&cfg.ListURL, "u", "", "IP列表下载地址 (http/https)")
	flag.StringVar(&cfg.FilePath, "f", "", "本地IP列表文件路径 (例如: ips.txt)")
	flag.StringVar(&cfg.TargetURL, "t", "", "测速目标URL")
	flag.StringVar(&cfg.AK, "ak", "", "华为云 Access Key")
	flag.StringVar(&cfg.SK, "sk", "", "华为云 Secret Key")
	flag.StringVar(&cfg.ProjectID, "pid", "", "华为云 Project ID (必填，解决401报错)")
	flag.StringVar(&cfg.ZoneID, "zone", "", "华为云 Zone ID")
	flag.StringVar(&cfg.Domain, "domain", "", "要更新的完整域名")
	flag.StringVar(&cfg.Region, "region", "cn-east-3", "华为云区域")
	flag.IntVar(&cfg.Threads, "n", 20, "并发线程数")
	flag.Parse()

	// 1. 参数校验
	if (cfg.ListURL == "" && cfg.FilePath == "") || cfg.TargetURL == "" {
		fmt.Println("错误: 必须提供 IP 来源 (-u 或 -f) 以及测速目标 (-t)")
		flag.Usage()
		os.Exit(1)
	}
	if cfg.AK == "" || cfg.SK == "" || cfg.ZoneID == "" || cfg.ProjectID == "" {
		fmt.Println("错误: 缺少华为云相关参数 (ak, sk, zone, pid 均为必填)")
		flag.Usage()
		os.Exit(1)
	}

	// 2. 获取 IP 列表
	fmt.Println("[1/4] 获取 IP 列表...")
	ips, err := getIPs(cfg)
	if err != nil {
		fmt.Printf("获取失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      成功加载 %d 个 IP\n", len(ips))

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

// 统一获取 IP 逻辑：优先读取本地文件，没有则下载
func getIPs(cfg Config) ([]string, error) {
	var scanner *bufio.Scanner
	var sourceName string

	if cfg.FilePath != "" {
		// 读取本地文件
		sourceName = "Local File: " + cfg.FilePath
		file, err := os.Open(cfg.FilePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		// 下载网络文件
		sourceName = "Remote URL: " + cfg.ListURL
		resp, err := http.Get(cfg.ListURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)
	}

	fmt.Printf("      来源: %s\n", sourceName)

	var ips []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 忽略空行和注释
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, nil
}

// 测速核心逻辑 (保持不变)
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

			dialer := &net.Dialer{Timeout: 3 * time.Second}
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
					fmt.Printf(".")
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
	// 修复：显式传入 ProjectId，避免 SDK 自动请求 IAM 导致 401 报错
	auth := basic.NewCredentialsBuilder().
		WithAk(cfg.AK).
		WithSk(cfg.SK).
		WithProjectId(cfg.ProjectID). // 关键修改
		Build()

	client := dns.NewDnsClient(
		dns.DnsClientBuilder().
			WithRegion(region.ValueOf(cfg.Region)).
			WithCredential(auth).
			Build())

	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	// 1. 搜索记录
	listReq := &model.ListRecordSetsByZoneRequest{}
	listReq.ZoneId = cfg.ZoneID
	listReq.Name = &searchDomain
	
	resp, err := client.ListRecordSetsByZone(listReq)
	if err != nil {
		return fmt.Errorf("查询记录集失败: %v", err)
	}

	var recordID string
	if resp.Recordsets != nil {
		for _, r := range *resp.Recordsets {
			if r.Name != nil && *r.Name == searchDomain && r.Type != nil && *r.Type == "A" {
				recordID = *r.Id
				break
			}
		}
	}

	if recordID == "" {
		return fmt.Errorf("未在 Zone 中找到域名 %s 的 A 记录", cfg.Domain)
	}

	// 2. 更新记录
	newRecords := []string{ip}
	
	updateReq := &model.UpdateRecordSetRequest{
		ZoneId:      cfg.ZoneID,
		RecordsetId: recordID,
	}
	body := &model.UpdateRecordSetReq{
		Records: &newRecords,
		Type:    "A",
		Ttl:     Pointer(int32(300)),
		Name:    searchDomain,
	}
	updateReq.Body = body

	_, err = client.UpdateRecordSet(updateReq)
	return err
}

func Pointer[T any](v T) *T {
	return &v
}