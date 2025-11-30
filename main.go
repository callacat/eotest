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
	ProjectID string // 项目ID
	ZoneID    string
	Domain    string
	Region    string
	Threads   int
	TopN      int    // 新增：更新前N个IP
	OutFile   string // 新增：结果保存路径
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
	flag.StringVar(&cfg.ProjectID, "pid", "", "华为云 Project ID (解决401报错)")
	flag.StringVar(&cfg.ZoneID, "zone", "", "华为云 Zone ID")
	flag.StringVar(&cfg.Domain, "domain", "", "要更新的完整域名")
	flag.StringVar(&cfg.Region, "region", "cn-east-3", "华为云区域")
	flag.IntVar(&cfg.Threads, "n", 20, "并发线程数")
	flag.IntVar(&cfg.TopN, "top", 1, "更新延迟最低的前 N 个 IP 到 DNS (默认1，华为云最多支持50)")
	flag.StringVar(&cfg.OutFile, "o", "result.txt", "测速结果保存文件")
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
	fmt.Println("[1/5] 获取 IP 列表...")
	ips, err := getIPs(cfg)
	if err != nil {
		fmt.Printf("获取失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      成功加载 %d 个 IP\n", len(ips))

	// 3. 测速
	fmt.Printf("[2/5] 开始测速 (Target: %s, Threads: %d)\n", cfg.TargetURL, cfg.Threads)
	allResults := runSpeedTest(ips, cfg.TargetURL, cfg.Threads)
	
	if len(allResults) == 0 {
		fmt.Println("      未找到可用 IP，程序退出。")
		os.Exit(1)
	}

	// 4. 保存结果
	fmt.Printf("[3/5] 保存结果到 %s\n", cfg.OutFile)
	if err := saveResults(allResults, cfg.OutFile); err != nil {
		fmt.Printf("      保存失败: %v\n", err)
	} else {
		fmt.Printf("      已保存 %d 条有效记录\n", len(allResults))
	}

	// 5. 选取 Top N 并更新 DNS
	count := cfg.TopN
	if count > len(allResults) {
		count = len(allResults)
	}
	if count > 50 {
		count = 50 // 华为云强制限制
		fmt.Println("      提示: 更新数量已自动限制为 50 (平台上限)")
	}

	bestIPs := make([]string, count)
	for i := 0; i < count; i++ {
		bestIPs[i] = allResults[i].IP
	}

	fmt.Printf("[4/5] 准备更新 DNS (%s)\n", cfg.Domain)
	fmt.Printf("      选中 IP (%d个): %v\n", len(bestIPs), bestIPs)
	
	if err := updateHuaweiDNS(cfg, bestIPs); err != nil {
		fmt.Printf("[5/5] 更新失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[5/5] 全部完成！SUCCESS")
}

// 统一获取 IP 逻辑
func getIPs(cfg Config) ([]string, error) {
	var scanner *bufio.Scanner
	var sourceName string

	if cfg.FilePath != "" {
		sourceName = "Local File: " + cfg.FilePath
		file, err := os.Open(cfg.FilePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
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
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, nil
}

// 测速核心逻辑 (返回完整的排序后的结果列表)
func runSpeedTest(ips []string, targetURL string, concurrency int) []Result {
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

	// 排序
	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Latency < validResults[j].Latency
	})

	return validResults
}

// 保存结果到本地文件
func saveResults(results []Result, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	// 写入表头
	fmt.Fprintln(w, "IP地址\t\t延迟(ms)")
	fmt.Fprintln(w, "--------------------------")
	
	for _, res := range results {
		fmt.Fprintf(w, "%-15s\t%.2f\n", res.IP, res.Latency)
	}
	return w.Flush()
}

// 华为云 DNS 更新逻辑 (支持多IP)
func updateHuaweiDNS(cfg Config, ips []string) error {
	auth := basic.NewCredentialsBuilder().
		WithAk(cfg.AK).
		WithSk(cfg.SK).
		WithProjectId(cfg.ProjectID).
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

	// 2. 更新记录 (传入 IP 列表)
	updateReq := &model.UpdateRecordSetRequest{
		ZoneId:      cfg.ZoneID,
		RecordsetId: recordID,
	}
	body := &model.UpdateRecordSetReq{
		Records: &ips, // 指针指向字符串切片
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
```

### 新增功能使用示例

**场景：** 读取本地 `ips.txt`，将测速结果保存到 `log.txt`，并且选出延迟最低的 **3** 个 IP 更新到 DNS。

```bash
./smartdns-linux-amd64 \
  -f "ips.txt" \
  -t "https://test.dsurl.eu.org" \
  -domain "eo-arm.dsurl.eu.org" \
  -zone "ZoneID..." \
  -ak "AK..." \
  -sk "SK..." \
  -pid "ProjectID..." \
  -top 3 \
  -o "log.txt"