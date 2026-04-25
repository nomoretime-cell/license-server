# License Server

硬件授权服务器 —— 基于 RSA 数字签名的通用硬件授权系统，HTTPS 通信，JWT 员工认证，SQLite/MySQL/PostgreSQL 审计日志。

服务端不感知具体硬件字段（MAC、CPU UID 等），客户端传什么 payload 就签什么、记什么，做到业务无关。

## 项目结构

```
license-server/
├── cmd/server/main.go   # 入口
├── internal/
│   ├── model.go         # 数据模型 & 配置
│   ├── crypto.go        # RSA 签名密钥 & TLS 证书生成
│   ├── db.go            # 审计日志数据库（database/sql，可切换 SQLite/MySQL/PostgreSQL）
│   └── server.go        # HTTP 路由、中间件、业务逻辑
├── config.json          # 服务配置
├── keys/                # License 签名用 RSA 密钥对（长期不变）
├── certs/               # HTTPS 用 TLS 自签名证书（可定期轮换）
├── audit.db             # SQLite 审计日志数据库（运行时自动创建）
├── scripts/test.py      # 集成测试脚本 (Python3, 无第三方依赖)
└── Dockerfile
```

## 两套密钥说明

| 密钥 | 目录 | 用途 | 生命周期 |
|------|------|------|----------|
| `keys/private.pem` + `keys/public.pem` | `keys/` | License 数字签名 | 和产品线一样长（10年+），基本不换 |
| `certs/server.crt` + `certs/server.key` | `certs/` | HTTPS 通信加密 | 1-3 年，可定期轮换 |

不能复用：TLS 证书会过期轮换，而相机中硬编码的公钥需要长期稳定。

## 快速开始

### 1. 生成密钥对

一条命令同时生成 License 签名密钥 + TLS 自签名证书：

```bash
go run cmd/server/main.go -genkeys
```

生成的文件：
- `keys/private.pem` — License 签名私钥，仅留在服务端
- `keys/public.pem` — License 验签公钥，硬编码进相机固件
- `certs/server.crt` — TLS 证书（自签名，生产环境建议替换为正式证书）
- `certs/server.key` — TLS 私钥

### 2. 本地运行

```bash
go run cmd/server/main.go -config config.json
```

服务默认监听 `https://0.0.0.0:8443`。

### 3. Docker 构建 & 运行

```bash
# 构建镜像
# 同时传大写和小写是因为 Go 工具链读的是大写变量，而部分 Linux 工具读的是小写变量，两者都传可以确保兼容。
docker build \
  --build-arg http_proxy=http://192.168.0.45:7897 \
  --build-arg https_proxy=http://192.168.0.45:7897 \
  --build-arg HTTP_PROXY=http://192.168.0.45:7897 \
  --build-arg HTTPS_PROXY=http://192.168.0.45:7897 \
  -t license-server:$(date +%Y%m%d)-$(git rev-parse --short HEAD) .

# 运行容器
docker run -d --name license-server -p 8443:8443 license-server
```

如需挂载外部密钥、配置和持久化审计数据库：

```bash
docker run -d --name license-server -p 8443:8443 \
  -v $(pwd)/keys:/app/keys:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/config.json:/app/config.json:ro \
  -v $(pwd)/data:/app/data \
  license-server
```

> 挂载 `data` 目录并将 `config.json` 中 `db_dsn` 改为 `data/audit.db`，确保容器重启后审计日志不丢失。

### 4. 运行测试

确保服务已启动（本地或 Docker），然后：

```bash
python3 scripts/test.py
```

测试覆盖：HTTPS 连接、登录认证、License 签发、审计日志持久化、签名验证、篡改检测。

### 5. 查看审计日志（SQLite）

```bash
sqlite3 audit.db "SELECT id, operator, payload, issued_at FROM audit_logs;"
```

## API 说明

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/health` | GET | 无 | 健康检查 |
| `/api/v1/login` | POST | 无 | 员工登录，获取 JWT |
| `/api/v1/license/issue` | POST | JWT | 签发 License |
| `/api/v1/license/audit` | GET | JWT | 查看审计日志 |

### 安全机制

- **HTTPS**：TLS 1.2+ 加密通信，防中间人攻击和抓包重放
- **IP 白名单**：配置 `ip_whitelist`，空数组表示不限制
- **JWT 认证**：操作员登录后获取 Token，所有授权操作可追溯到人
- **审计日志**：每次签发 License 记录操作员、完整 payload、时间，持久化到数据库，防内部滥用

## 三方模块集成指南

整个授权系统分三个模块，各模块需要的文件和职责如下：

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  授权服务端   │         │  授权客户端   │         │   相机软件    │
│              │         │  (产线工具)   │         │  (嵌入式端)   │
│ private.pem  │◄─HTTPS─►│  员工账号密码  │──写入──►│  public.pem  │
│ config.json  │         │  server.crt  │         │  License.lic │
│ server.crt   │         │              │         │              │
│ server.key   │         │              │         │              │
└──────────────┘         └──────────────┘         └──────────────┘
```

### 授权客户端（产线授权工具）

授权客户端运行在产线电脑上，由操作员使用，负责采集相机硬件信息并向服务端申请 License。

**需要的信息：**

| 项目 | 说明 | 来源 |
|------|------|------|
| `server.crt` | TLS 证书（自签名时需要） | 由服务端管理员提供，用于信任 HTTPS 连接 |
| 员工账号密码 | JWT 登录凭证 | 服务端 `config.json` 中的 `users` 配置 |
| 服务端地址 | 如 `https://license.example.com:8443` | 部署后确定 |

**工作流程（伪代码）：**

```python
import ssl

# 信任自签名证书（生产环境用正式证书则不需要）
ctx = ssl.create_default_context()
ctx.load_verify_locations("server.crt")

# 1. 登录获取 JWT
resp = POST("https://license.example.com:8443/api/v1/login",
    body={"username": "operator01", "password": "op01pass"},
    ssl_context=ctx)
token = resp["data"]["token"]

# 2. 采集相机硬件信息（payload 内容由客户端定义，服务端不感知具体字段）
hardware_payload = {
    "mac_address": read_camera_mac(),      # 相机网口 MAC
    "cpu_uid": read_camera_cpu_uid(),       # 相机主控 CPU 唯一 ID
    "camera_model": "CAM-X100",            # 相机型号
    "encrypt_version": 1,                  # 加密版本号
}

# 3. 申请 License
resp = POST("https://license.example.com:8443/api/v1/license/issue",
    headers={"Authorization": f"Bearer {token}"},
    body={"payload": hardware_payload, "valid_days": 3650},
    ssl_context=ctx)

# 4. 将返回的 License 写入相机隐藏目录
license_data = resp["data"]
write_file("/camera/.license/License.lic", json.dumps(license_data))
```

**请求体结构：**

```json
{
  "payload": { ... },
  "valid_days": 3650
}
```

- `payload`：任意 JSON 对象，服务端透传签名，不解析具体字段
- `valid_days`：授权有效天数（可选，默认 3650 天）

**返回的 License.lic 文件结构：**

```json
{
  "payload": {
    "camera_model": "CAM-X100",
    "cpu_uid": "CPU-UID-00001",
    "encrypt_version": 1,
    "mac_address": "AA:BB:CC:DD:EE:FF"
  },
  "issued_at": "2026-04-18T06:00:00Z",
  "expires_at": "2036-04-16T06:00:00Z",
  "signature": "base64 编码的 RSA-SHA256 数字签名..."
}
```

### 相机软件（嵌入式验证端）

相机软件在每次启动时验证 License，确认设备是经过公司授权的合法设备。

**需要的文件：**

| 文件 | 说明 | 集成方式 |
|------|------|----------|
| `keys/public.pem` | RSA 公钥 | **编译时硬编码**到固件中（混淆后嵌入二进制） |
| `License.lic` | 授权文件 | 由授权客户端写入相机的隐藏目录 |

**验证流程（C/C++ 伪代码）：**

签名覆盖的内容是 **envelope**（`payload` + `issued_at` + `expires_at`），按 key 字母序排列。

```c
int verify_license() {
    // 1. 读取 License.lic
    char *lic_json = read_file("/camera/.license/License.lic");
    if (!lic_json) return ERROR_NO_LICENSE;

    // 2. 解析各字段
    json_t *lic = json_parse(lic_json);
    unsigned char *sig_raw = base64_decode(lic->signature);

    // 3. 重建签名信封（key 按字母序，紧凑格式，与服务端一致）
    //    {"expires_at":"...","issued_at":"...","payload":{...}}
    char *envelope_str = json_build_compact_sorted(
        "expires_at", lic->expires_at,
        "issued_at",  lic->issued_at,
        "payload",    lic->payload    // payload 内部 key 也按字母序
    );

    // 4. 用内置公钥验证签名
    int ok = rsa_verify_pkcs1_sha256(
        EMBEDDED_PUBLIC_KEY,
        envelope_str, strlen(envelope_str),
        sig_raw, sig_raw_len
    );
    if (!ok) return ERROR_INVALID_SIGNATURE;

    // 5. 校验硬件指纹（业务字段在 payload 内部，由客户端自行定义和解析）
    if (strcmp(lic->payload->mac_address, get_local_mac()) != 0)
        return ERROR_MAC_MISMATCH;
    if (strcmp(lic->payload->cpu_uid, get_local_cpu_uid()) != 0)
        return ERROR_CPU_MISMATCH;

    // 6. 校验有效期
    if (current_time() > parse_time(lic->expires_at))
        return ERROR_LICENSE_EXPIRED;

    return LICENSE_OK;
}
```

**关键安全要点：**

- **服务端业务无关**：服务端不解析 `payload` 内容，只负责签名和记录，新增/修改硬件字段无需改服务端代码
- **公钥硬编码**：`public.pem` 的内容在编译时以字节数组形式嵌入二进制，不以文件形式存在于文件系统
- **JSON 序列化一致性**：验签时 envelope 的 JSON 必须与服务端完全一致 —— **紧凑格式，key 按字母序**（包括嵌套的 payload），服务端使用 Go `json.Marshal` 对 `map[string]interface{}` 序列化（天然字母序）
- **硬件绑定**：License 复制到其他设备会因 MAC/CPU UID 不匹配而失败
- **篡改检测**：修改任何字段（payload 或有效期），签名验证就会失败

### 各模块文件分发总结

| 文件 | 授权服务端 | 授权客户端 | 相机软件 |
|------|:---:|:---:|:---:|
| `keys/private.pem` | **保存** | - | - |
| `keys/public.pem` | 保存 | - | **硬编码** |
| `certs/server.crt` | **保存** | **配置信任** | - |
| `certs/server.key` | **保存** | - | - |
| `config.json` | **保存** | - | - |
| 员工账号密码 | 配置中 | **运行时输入** | - |
| `License.lic` | - | 写入相机 | **读取验证** |

## 配置说明

编辑 `config.json`：

```json
{
  "listen_addr": ":8443",
  "private_key_path": "keys/private.pem",
  "tls_cert_path": "certs/server.crt",
  "tls_key_path": "certs/server.key",
  "ip_whitelist": [],
  "jwt_secret": "your-jwt-secret",
  "jwt_expire_hours": 8,
  "db_driver": "sqlite3",
  "db_dsn": "audit.db",
  "users": [
    {"username": "admin", "password": "admin123"}
  ]
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `listen_addr` | 监听地址 | `:443` |
| `private_key_path` | License 签名私钥路径 | - |
| `tls_cert_path` | HTTPS 证书路径 | - |
| `tls_key_path` | HTTPS 私钥路径 | - |
| `ip_whitelist` | IP 白名单，空数组不限制 | `[]` |
| `jwt_secret` | JWT 签名密钥 | - |
| `jwt_expire_hours` | JWT 过期时间（小时） | `8` |
| `db_driver` | 数据库驱动 | `sqlite3` |
| `db_dsn` | 数据库连接串 | `audit.db` |
| `users` | 操作员账号列表 | - |

## 数据库切换

审计日志使用 Go 标准库 `database/sql` 接口，切换数据库只需改配置和驱动导入。

### 本地开发（SQLite，默认）

```json
{
  "db_driver": "sqlite3",
  "db_dsn": "audit.db"
}
```

### 切换到阿里云 MySQL

1. 修改 `config.json`：

```json
{
  "db_driver": "mysql",
  "db_dsn": "user:password@tcp(rm-xxx.mysql.rds.aliyuncs.com:3306)/license_db?parseTime=true"
}
```

2. 修改 `cmd/server/main.go` 的驱动导入：

```go
// 替换
_ "github.com/mattn/go-sqlite3"
// 为
_ "github.com/go-sql-driver/mysql"
```

3. 安装驱动并重新编译：

```bash
go get github.com/go-sql-driver/mysql
go build ./cmd/server
```

> 注意：MySQL 的自增语法是 `AUTO_INCREMENT`（SQLite 是 `AUTOINCREMENT`），建表 DDL 需微调。如需同时支持多种数据库，可通过 `db_driver` 判断使用不同的建表语句。

### 切换到阿里云 PostgreSQL

```json
{
  "db_driver": "postgres",
  "db_dsn": "host=pgm-xxx.pg.rds.aliyuncs.com port=5432 user=xxx password=xxx dbname=license_db sslmode=require"
}
```

驱动导入改为 `_ "github.com/lib/pq"`，PostgreSQL 使用 `SERIAL` 替代 `AUTOINCREMENT`。
