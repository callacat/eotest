# Auto DNS Speedtest & Updater (eotest)

eotest 是一个基于 Go 语言编写的高性能 DNS 优选与自动更新工具。

它专为**华为云 DNS** 用户设计，能够从远程 URL 或本地文件获取 IP 列表，通过高并发测速筛选出延迟最低的优质 IP，并自动更新到指定的域名解析记录（A 记录）中。

适用于优化 EdgeOne、Cloudflare 自选 IP 或其他需要根据网络状况动态调整解析 IP 的场景。

## 🌟 核心特性

- **多源支持**：支持从 HTTP/HTTPS URL 下载 IP 列表，也支持读取本地 TXT 文件。
- **高并发测速**：利用 Go 协程（Goroutines）进行极速 TCP/HTTP 延迟测试。
- **智能校验（新）**：
- **状态码过滤**：自动丢弃非 2xx 响应的 IP。
- **内容特征匹配**：支持 `-match` 参数，通过检查网页关键词防止 IP 劫持或“假墙”污染。
- **华为云原生集成**：
- 直接对接华为云 DNS API v2。
- **智能检索**：通过 API 精确过滤记录，无需担心域名记录过多导致找不到目标。
- **高度可配置**：支持自定义并发数、超时时间、更新 IP 数量（Top N）。
- **安全防拦截**：内置模拟浏览器 User-Agent，避免被 CDN 节点拦截。

## 🚀 快速开始

### 1. 准备工作

在使用前，请确保您拥有以下华为云凭证：

1. **AK/SK (Access Key / Secret Key)**：在华为云“我的凭证” -> “访问密钥”中获取。
2. **Project ID**：在“我的凭证” -> “API凭证”中获取（需选择对应的 Region，如 `cn-east-3`）。
3. **Zone ID**：在云解析 DNS 控制台 -> 点击您的域名 -> “基本信息”中查看。
4. **准备域名**：在后台为需要更新的子域名（如 `best.example.com`）手动创建一条 A 记录（IP 可随意填写，如 `1.1.1.1`），用于初始化。

### 2. 编译安装

确保您的环境已安装 Go 1.20 或更高版本。

```
# 下载代码
git clone https://github.com/your-repo/eotest.git
cd eotest

# 整理依赖
go mod tidy

# 编译 (Linux/macOS)
go build -ldflags="-s -w" -o eotest main.go

# 编译 (Windows)
go build -ldflags="-s -w" -o eotest.exe main.go
```

### 3. 运行示例

**基础用法**：从 URL 获取 IP，测速并更新到华为云。

```
./eotest \
  -u "https://raw.githubusercontent.com/example/ips/main/list.txt" \
  -t "https://www.google.com" \
  -domain "g.example.com" \
  -ak "YOUR_ACCESS_KEY" \
  -sk "YOUR_SECRET_KEY" \
  -pid "YOUR_PROJECT_ID" \
  -zone "YOUR_ZONE_ID"
```

## 📖 参数说明

使用 `./eotest -h` 可查看完整帮助信息。

### 必填参数

| 参数      | 说明                                           | 示例                      |
| --------- | ---------------------------------------------- | ------------------------- |
| `-t`      | **测速目标 URL**。程序会计算访问此链接的延迟。 | `https://www.youtube.com` |
| `-ak`     | 华为云 Access Key                              | `A6D...`                  |
| `-sk`     | 华为云 Secret Key                              | `x9c...`                  |
| `-pid`    | 华为云 Project ID                              | `0b4...`                  |
| `-zone`   | 域名对应的 Zone ID                             | `2c9...`                  |
| `-domain` | **完整域名**。需与后台记录名称完全一致。       | `cf.mysite.com`           |

### 选填参数 (优化与控制)

| 参数       | 默认值       | 说明                                                         |
| ---------- | ------------ | ------------------------------------------------------------ |
| `-u`       | -            | **IP 来源 URL**。从网络下载 IP 列表。                        |
| `-f`       | -            | **本地 IP 文件**。从本地 TXT 读取 IP。**注意：`-u` 和 `-f` 二选一**。 |
| `-region`  | `cn-east-3`  | 华为云区域代码。                                             |
| `-n`       | `20`         | **并发线程数**。建议设置为 20-50，过高可能导致丢包。         |
| `-top`     | `1`          | **优选数量**。更新延迟最低的前 N 个 IP 到 DNS 解析中。       |
| `-o`       | `result.txt` | 测速结果保存的文件路径。                                     |
| `-timeout` | `2000`       | **超时时间 (ms)**。单个 IP 连接的最长等待时间。              |
| `-match`   | -            | **内容校验字符串**。只有响应 Body 中包含此字符串才视为有效 IP。 |

*(推荐用于防止劫持)* |

## 💡 进阶场景配置

### 场景一：精准防劫持 (推荐)

为了防止测到的 IP 是被运营商劫持的（虽然返回 200 OK，但内容是广告页），可以使用 `-match` 参数校验网页标题或特定关键词。

```
./eotest \
  -f ip_list.txt \
  -t "https://my-private-site.com" \
  -match "<title>My Dashboard</title>" \
  -timeout 1500 \
  ...华为云参数...
```

### 场景二：负载均衡

将测速最快的前 5 个 IP 同时更新到 DNS 记录中，实现客户端的简单负载均衡。

```
./eotest ... -top 5
```

## ⚠️ 注意事项

1. **覆盖风险**：程序执行成功后，会**覆盖**该域名下原有的所有 A 记录值，请务必确保该子域名仅用于自动优选。
2. **API 限制**：华为云 API 对请求频率有限制，建议不要将定时任务设置得过于频繁（如建议 > 10分钟一次）。
3. **安全性**：请勿将包含 AK/SK 的命令行直接分享给他人。建议在服务器环境变量中调用或使用脚本封装。

## License

MIT License

---

**Exported with [gemini-to-markdown](https://github.com/faithleysath/gemini-to-markdown)** ⭐

*A JavaScript tool to export Gemini Canvas/Deep Research pages into Markdown*