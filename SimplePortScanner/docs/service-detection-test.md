# 协议探测服务识别 - 测试用例

## 编译

```powershell
cd SimplePortScanner/build
cmake ..
cmake --build . --config Release
```

## 测试 1：标准端口 SSH（22）

**前提：** 本机 OpenSSH 服务已启动。

```powershell
.\Release\SimplePortScanner.exe
# 菜单选 1，IP: 127.0.0.1，端口: 22，超时 500ms，线程 10
```

**期望：**

- `detectedService`: SSH
- `method`: probe
- `banner` 含 `SSH-2.0-...`
- 控制台输出 `[probe]`

## 测试 2：标准端口 HTTP（80 / 8080）

**前提：** 本机有 Web 服务监听 80 或 8080。

**期望：**

- `detectedService`: HTTP
- `method`: probe
- `banner` 为 Server 头或 HTTP 状态行

## 测试 3：标准端口 HTTPS（443）

**前提：** 本机有 TLS 服务监听 443。

**期望：**

- `detectedService`: HTTPS
- `method`: probe
- 探测方式为 TLS ClientHello，无需 OpenSSL

## 测试 4：非标准端口 HTTP（证明优于查表）

**目的：** 端口表会把 9000 显示为 Unknown，但协议探测应识别 HTTP。

**步骤：**

1. 用 Python 临时启动 HTTP 服务：

```powershell
python -m http.server 9000
```

2. 扫描 `127.0.0.1`，端口 `9000`

**期望：**

| 字段 | 值 |
|------|-----|
| PortGuess（端口猜测） | Unknown |
| DetectedService | HTTP |
| Method | probe |

这说明**准确识别依赖协议特征，而非端口号**。

## 测试 5：Redis（6379）

**前提：** 本机 Redis 已启动且允许 127.0.0.1 连接。

**期望：**

- `detectedService`: Redis
- `method`: probe
- 通过 `PING` 收到 `+PONG`

## 测试 6：CSV 导出字段

导出 CSV 后应包含列：

`IP,Port,Status,PortGuess,DetectedService,Version,Method,Banner,TimeMs`

对比 `PortGuess` 与 `DetectedService`，在非标准端口场景下应不同。

## 答辩对比说明

- **Connect 扫描**：回答端口是否开放
- **协议探测**：在应用层收发特征数据，识别真实服务
- **port-guess**：仅当探测与 Banner 推断均失败时，才回退到静态端口表
