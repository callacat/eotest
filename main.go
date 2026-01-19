package main

import (
	"bufio"
	"context"
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
	TopN      int    // 更新前N个IP
	OutFile   string // 结果保存路径
	// 新增参数
	Timeout   int    // 超时时间(ms)
	MatchStr  string // 响应内容校验字符串
	TTL       int    // DNS TTL值
}

type Result struct {
	IP      string
	Latency float64
}

// 全局变量，用于在 preCheck 阶段缓存找到的 RecordID
var cachedRecordID string

func main() {
	cfg := Config{}
	// 参数定义
	flag.StringVar(&cfg.ListURL, "u", "", "IP列表下载地址")
	flag.StringVar(&cfg.FilePath, "f", "", "本地IP列表文件路径 (例如: ips.txt)")
	flag.StringVar(&cfg.TargetURL, "t", "", "测速目标URL")
	flag.StringVar(&cfg.AK, "ak", "", "华为云 Access Key")
	flag.StringVar(&cfg.SK, "sk", "", "华为云 Secret Key")
	flag.StringVar(&cfg.ProjectID, "pid", "", "华为云 Project ID")
	flag.StringVar(&cfg.ZoneID, "zone", "", "华为云 Zone ID")
	flag.StringVar(&cfg.Domain, "domain", "", "要更新的完整域名 (例如 eoip.dsurl.eu.org)")
	flag.StringVar(&cfg.Region, "region", "cn-east-3", "华为云区域")
	flag.IntVar(&cfg.Threads, "n", 20, "并发线程数")
	flag.IntVar(&cfg.TopN, "top", 1, "更新延迟最低的前 N 个 IP (默认1)")
	flag.StringVar(&cfg.OutFile, "o", "result.txt", "测速结果保存文件")
	// 新增参数
	flag.IntVar(&cfg.Timeout, "timeout", 2000, "测速超时时间 (ms，默认 2000)")
	flag.StringVar(&cfg.MatchStr, "match", "", "响应内容需包含的字符串 (可选，用于校验内容防止假200)")
	flag.IntVar(&cfg.TTL, "ttl", 60, "DNS记录的TTL值 (默认60)")
	
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

	// 2. 前置检查：验证华为云权限并查找记录ID
	fmt.Println("[1/5] 验证华为云权限及域名记录...")
	if err := preCheckDNS(cfg); err != nil {
		fmt.Printf("\n❌ 验证失败，程序终止: \n%v\n", err)
		os.Exit(1)
	}
	fmt.Println("      ✅ 验证通过，目标记录 ID 已锁定")

	// 3. 获取 IP 列表
	fmt.Println("[2/5] 获取 IP 列表...")
	ips, err := getIPs(cfg)
	if err != nil {
		fmt.Printf("获取失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      成功加载 %d 个 IP\n", len(ips))

	// 4. 测速
	fmt.Printf("[3/5] 开始测速 (Target: %s, Threads: %d, Timeout: %dms)\n", cfg.TargetURL, cfg.Threads, cfg.Timeout)
	if cfg.MatchStr != "" {
		fmt.Printf("      🔍 启用内容校验: 必须包含 \"%s\"\n", cfg.MatchStr)
	}
	
	allResults := runSpeedTest(ips, cfg.TargetURL, cfg.Threads, cfg.Timeout, cfg.MatchStr)
	
	if len(allResults) == 0 {
		fmt.Println("\n      ❌ 未找到可用 IP (所有 IP 均超时或校验失败)，程序退出。")
		os.Exit(1)
	}

	// 5. 保存结果
	fmt.Printf("[4/5] 保存结果到 %s\n", cfg.OutFile)
	if err := saveResults(allResults, cfg.OutFile); err != nil {
		fmt.Printf("      保存失败: %v\n", err)
	} else {
		fmt.Printf("      已保存 %d 条有效记录\n", len(allResults))
	}

	// 6. 选取 Top N 并更新 DNS
	count := cfg.TopN
	if count > len(allResults) {
		count = len(allResults)
	}
	if count > 50 { // 华为云限制单条记录集最多50个值
		count = 50
	}

	bestIPs := make([]string, count)
	for i := 0; i < count; i++ {
		bestIPs[i] = allResults[i].IP
	}

	fmt.Printf("[5/5] 准备更新 DNS (%s, TTL: %d)\n", cfg.Domain, cfg.TTL)
	fmt.Printf("      选中 IP: %v\n", bestIPs)
	
	if err := updateHuaweiDNS(cfg, bestIPs); err != nil {
		fmt.Printf("❌ 更新失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[5/5] 全部完成！SUCCESS")
}

// 优化后的前置检查：使用 API 过滤而非本地遍历
func preCheckDNS(cfg Config) error {
	client, err := getDNSClient(cfg)
	if err != nil {
		return err
	}

	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	// 构造请求：直接让服务端过滤 Name
	listReq := &model.ListRecordSetsByZoneRequest{
		ZoneId: cfg.ZoneID,
		Name:   &searchDomain, 
	}
	
	resp, err := client.ListRecordSetsByZone(listReq)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "APIGW.0301") {
			return fmt.Errorf("鉴权失败 (401)。请检查：\n1. ProjectID [%s] 是否属于 Region [%s]\n2. AK/SK 是否正确", cfg.ProjectID, cfg.Region)
		}
		if strings.Contains(errMsg, "DNS.1005") || strings.Contains(errMsg, "not found") {
			return fmt.Errorf("ZoneID [%s] 不存在或无权访问", cfg.ZoneID)
		}
		return err
	}

	if resp.Recordsets == nil || len(*resp.Recordsets) == 0 {
		return fmt.Errorf("未找到域名为 [%s] 的记录，请先在华为云后台手动创建一条 A 记录", searchDomain)
	}

	// 即使服务端过滤了，我们还是做一次精确匹配校验，并确保是 A 记录
	for _, r := range *resp.Recordsets {
		if r.Name != nil && *r.Name == searchDomain && r.Type != nil && *r.Type == "A" {
			cachedRecordID = *r.Id
			return nil
		}
	}
	
	return fmt.Errorf("找到同名记录，但类型不是 A 记录 (可能是 CNAME?)")
}

func getDNSClient(cfg Config) (*dns.DnsClient, error) {
	auth := basic.NewCredentialsBuilder().
		WithAk(cfg.AK).
		WithSk(cfg.SK).
		WithProjectId(cfg.ProjectID).
		Build()

	reg := region.ValueOf(cfg.Region)
	if reg == nil {
		return nil, fmt.Errorf("无效的 Region: %s", cfg.Region)
	}

	return dns.NewDnsClient(
		dns.DnsClientBuilder().
			WithRegion(reg).
			WithCredential(auth).
			Build()), nil
}

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
		client := &http.Client{Timeout: 10 * time.Second} // 给下载列表也加个超时
		resp, err := client.Get(cfg.ListURL)
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
			// 简单的 IP 格式校验，去除带端口的写法 (如果有)
			if strings.Contains(line, ":") && !strings.Contains(line, "[") { 
				// 假设是 ipv4:port 的情况，只取 ip
				parts := strings.Split(line, ":")
				line = parts[0]
			}
			ips = append(ips, line)
		}
	}
	return ips, nil
}

// 优化后的测速逻辑：支持自定义超时和内容匹配
func runSpeedTest(ips []string, targetURL string, concurrency int, timeoutMs int, matchStr string) []Result {
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

	// 计算超时 Duration
	timeoutDuration := time.Duration(timeoutMs) * time.Millisecond

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(testIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			// 自定义 Dialer
			dialer := &net.Dialer{
				Timeout:   timeoutDuration,
				KeepAlive: 0, // 测速无需 KeepAlive
			}
			
			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					// 强制连接到指定 IP
					return dialer.DialContext(ctx, network, testIP+":"+port)
				},
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, ServerName: host},
				DisableKeepAlives:     true, // 禁用复用
				ResponseHeaderTimeout: timeoutDuration,
				TLSHandshakeTimeout:   timeoutDuration,
			}
			
			client := &http.Client{
				Transport: transport, 
				Timeout:   timeoutDuration,
			}

			start := time.Now()
			
			// 构建请求，模拟浏览器 User-Agent
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				latency := float64(time.Since(start).Milliseconds())

				isValid := false
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					isValid = true
					// 如果配置了 matchStr，则读取 Body 进行校验
					if matchStr != "" {
						// 只读前 4KB 避免大文件消耗内存
						bodyStart := make([]byte, 4096)
						n, _ := io.ReadFull(resp.Body, bodyStart)
						bodyStr := string(bodyStart[:n])
						
						if !strings.Contains(bodyStr, matchStr) {
							isValid = false // 内容不匹配
						}
					}
				}

				if isValid {
					results <- Result{IP: testIP, Latency: latency}
					fmt.Printf(".")
				} else {
					// fmt.Printf("x") // 可选：打印失败标记
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

	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Latency < validResults[j].Latency
	})

	return validResults
}

func saveResults(results []Result, filepath string) error {
	f, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "IP地址\t\t延迟(ms)")
	fmt.Fprintln(w, "--------------------------")
	for _, res := range results {
		fmt.Fprintf(w, "%-15s\t%.2f\n", res.IP, res.Latency)
	}
	return w.Flush()
}

func updateHuaweiDNS(cfg Config, ips []string) error {
	client, err := getDNSClient(cfg)
	if err != nil {
		return err
	}

	if cachedRecordID == "" {
		return fmt.Errorf("RecordID 未缓存")
	}

	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	updateReq := &model.UpdateRecordSetRequest{
		ZoneId:      cfg.ZoneID,
		RecordsetId: cachedRecordID,
	}
	// 使用命令行配置的 TTL
	ttlVal := int32(cfg.TTL)

	body := &model.UpdateRecordSetReq{
		Records: &ips,
		Type:    "A",
		Ttl:     Pointer(ttlVal),
		Name:    searchDomain,
	}
	updateReq.Body = body

	resp, err := client.UpdateRecordSet(updateReq)
	if err == nil {
		fmt.Printf("      ✅ 更新成功! Name: %s, TTL: %d, Records: %v\n", *resp.Name, *resp.Ttl, *resp.Records)
	}
	return err
}

func Pointer[T any](v T) *T {
	return &v
}