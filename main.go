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
	TopN      int    // 更新前N个IP
	OutFile   string // 结果保存路径
}

type Result struct {
	IP      string
	Latency float64
}

// 全局变量，用于在 preCheck 阶段缓存找到的 RecordID，避免最后重复查询
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

	// 2.【新功能】前置检查：验证华为云权限并查找记录ID
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
	fmt.Printf("[3/5] 开始测速 (Target: %s, Threads: %d)\n", cfg.TargetURL, cfg.Threads)
	allResults := runSpeedTest(ips, cfg.TargetURL, cfg.Threads)
	
	if len(allResults) == 0 {
		fmt.Println("      未找到可用 IP，程序退出。")
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
	if count > 50 {
		count = 50
	}

	bestIPs := make([]string, count)
	for i := 0; i < count; i++ {
		bestIPs[i] = allResults[i].IP
	}

	fmt.Printf("[5/5] 准备更新 DNS (%s)\n", cfg.Domain)
	fmt.Printf("      选中 IP: %v\n", bestIPs)
	
	// 这里直接使用 cachedRecordID，不再重复查询
	if err := updateHuaweiDNS(cfg, bestIPs); err != nil {
		fmt.Printf("❌ 更新失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[5/5] 全部完成！SUCCESS")
}

// 【核心新增】前置检查函数
func preCheckDNS(cfg Config) error {
	client, err := getDNSClient(cfg)
	if err != nil {
		return err
	}

	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	// 尝试列出该 Zone 下的记录
	listReq := &model.ListRecordSetsByZoneRequest{}
	listReq.ZoneId = cfg.ZoneID
	// 不限制名字，先拉取一部分，看看是否存在鉴权问题
	limit := int32(50) 
	listReq.Limit = &limit
	
	resp, err := client.ListRecordSetsByZone(listReq)
	if err != nil {
		// 转换错误信息，使其更易读
		errMsg := err.Error()
		if strings.Contains(errMsg, "APIGW.0301") {
			return fmt.Errorf("鉴权失败 (401)。请检查：\n1. ProjectID [%s] 是否属于 Region [%s]\n2. AK/SK 是否正确", cfg.ProjectID, cfg.Region)
		}
		if strings.Contains(errMsg, "DNS.1005") || strings.Contains(errMsg, "not found") {
			return fmt.Errorf("ZoneID [%s] 不存在或无权访问", cfg.ZoneID)
		}
		return err
	}

	// 鉴权通过，开始查找特定记录
	if resp.Recordsets == nil || len(*resp.Recordsets) == 0 {
		return fmt.Errorf("该 Zone [%s] 下没有任何记录", cfg.ZoneID)
	}

	// 遍历查找完全匹配的记录
	var foundRecord *model.RecordSet
	
	// 调试日志：打印出前几个记录，帮用户排查域名写错的问题
	// fmt.Println("      [Debug] API 返回的记录列表 (前5条):")
	for i, r := range *resp.Recordsets {
		// if i < 5 {
		// 	fmt.Printf("      - Name: %s | Type: %s | ID: %s\n", *r.Name, *r.Type, *r.Id)
		// }
		
		if r.Name != nil && *r.Name == searchDomain && r.Type != nil && *r.Type == "A" {
			foundRecord = &(*resp.Recordsets)[i]
			break
		}
	}

	if foundRecord != nil {
		cachedRecordID = *foundRecord.Id
		return nil
	}

	// 如果没找到，打印详细的诊断信息
	fmt.Println("\n⚠️  错误：未找到匹配的 A 记录")
	fmt.Printf("   你请求的域名是: [%s] (自动补全了点)\n", searchDomain)
	fmt.Printf("   API 在该 Zone 下看到的前 10 条记录如下:\n")
	for i, r := range *resp.Recordsets {
		if i >= 10 { break }
		fmt.Printf("   👉 Name: %-25s | Type: %-5s\n", *r.Name, *r.Type)
	}
	fmt.Println("\n   请检查：")
	fmt.Println("   1. 你填写的 -domain 是否和列表中的 Name 完全一致？")
	fmt.Println("   2. 该域名是否是 A 记录？(如果是 CNAME 则无法更新 IP)")
	fmt.Println("   3. 如果列表里没有，请先在华为云后台手动创建一条 A 记录 (填 1.1.1.1 占位)")
	
	return fmt.Errorf("记录不存在")
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

// 测速核心逻辑
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

	sort.Slice(validResults, func(i, j int) bool {
		return validResults[i].Latency < validResults[j].Latency
	})

	return validResults
}

// 保存结果
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

// 华为云 DNS 更新逻辑 (使用缓存的ID)
func updateHuaweiDNS(cfg Config, ips []string) error {
	client, err := getDNSClient(cfg)
	if err != nil {
		return err
	}

	if cachedRecordID == "" {
		return fmt.Errorf("程序逻辑错误：RecordID 未缓存")
	}

	searchDomain := cfg.Domain
	if !strings.HasSuffix(searchDomain, ".") {
		searchDomain += "."
	}

	updateReq := &model.UpdateRecordSetRequest{
		ZoneId:      cfg.ZoneID,
		RecordsetId: cachedRecordID,
	}
	body := &model.UpdateRecordSetReq{
		Records: &ips,
		Type:    "A",
		Ttl:     Pointer(int32(300)),
		Name:    searchDomain,
	}
	updateReq.Body = body

	resp, err := client.UpdateRecordSet(updateReq)
	if err == nil {
		fmt.Printf("      ✅ 更新成功! Name: %s, Records: %v\n", *resp.Name, *resp.Records)
	}
	return err
}

func Pointer[T any](v T) *T {
	return &v
}