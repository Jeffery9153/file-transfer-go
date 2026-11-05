# 文件快传 - P2P文件传输工具


**安全、快速、简单的点对点文件传输解决方案 - 单账号登录后即传即用**

## [在线体验](https://transfer.52python.cn) •  [关注我](https://x.com/_MatrixSeven) • [帮助文档](https://transfer.52python.cn/help)

![项目演示](img.png)



## ✨ 核心功能[端到端数据传输完全基于WebRTC的P2P直连/文件在线传输]
<div align="center">

![React](https://img.shields.io/badge/React-18-blue.svg)
![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue.svg)
![Go](https://img.shields.io/badge/Go-1.22-blue.svg)
![WebRTC](https://img.shields.io/badge/WebRTC-green.svg)
![Tailwind CSS](https://img.shields.io/badge/Tailwind%20CSS-3.4-blue.svg)

</div>

- 📁 **文件传输** - 支持多文件同时传输
- 🔐 **单账号登录** - 全站强制登录，首次设置密码并生成一次性找回码
- 📝 **文字传输** - 快速分享文本内容
- 🖥️ **桌面共享** - 实时屏幕共享
- 🖥️ **目录同步** - 在现代浏览器下支持目录同步
- 🔗 **连接状态同步** - 实时连接状态UI同步
- 🔒 **端到端加密** - 数据传输安全，服务器不存储文件
- 🖥️ **文件断点传输** - P2P/WS下大文件断点续传支持
- 📱 **响应式设计** - 完美适配手机、平板、电脑
- 🖥️ **多平台支持** - 支持linux/macos/win 单文件部署


## 🚀 技术栈

### 前端技术栈
- **Next.js 15** - React全栈框架，支持SSR/SSG
- **React 18** - 现代化UI组件库
- **TypeScript 5** - 类型安全的JavaScript超集
- **Tailwind CSS 3.4** - 实用优先的CSS框架
- **Radix UI** - 无障碍访问的组件库
- **Zustand** - 轻量级状态管理
- **Lucide React** - 现代化图标库

### 后端技术栈
- **Go 1.22** - 高性能编程语言
- **WebSocket** - 实时双向通信
- **内存存储** - 轻量级数据存储
- **标准库** - 原生HTTP服务器

### 传输协议
- **WebRTC DataChannel** - 端到端数据传输
- **P2P直连** - 点对点连接，无需中转
- **ICE框架** - 网络连接协商
- **STUN/TURN** - NAT穿透支持


### 架构特点
- **微服务架构** - 前后端分离
- **实时通信** - WebSocket + WebRTC
- **响应式设计** - 移动端适配
- **容器化** - Docker部署支持

## 📦 快速部署

### 方式一：Docker 一键部署（推荐）

```bash
# 使用 Docker Compose（最简单）
git clone https://github.com/MatrixSeven/file-transfer-go.git
cd file-transfer-go
docker-compose up -d

# 或者直接使用 Docker 镜像
docker run -d -p 8080:8080 --name file-transfer-go matrixseven/file-transfer-go:latest
```

### 方式二：本地构建部署

```bash
git clone https://github.com/MatrixSeven/file-transfer-go.git
cd file-transfer-go
./build-fullstack.sh 
./dist/file-transfer-go
```

访问 http://localhost:8080 开始使用

### 方式三：开发环境部署

```bash
# 后端服务
make dev

# 前端服务（新终端）
cd chuan-next && yarn && yarn dev
```

### 部署配置说明

#### 环境变量配置
- `NODE_ENV`: 运行环境（development/production）
- `PORT`: 服务端口（默认8080）
- `GO_BACKEND_URL`: 后端服务地址
- `DATA_DIR`: 账号数据目录（默认 `./data`），存放 `auth.json` 与 `secret.key`，**必须持久化**

#### Docker 配置选项
```yaml
# docker-compose.yml 可配置项
environment:
  - NODE_ENV=production
  - PORT=8080
  - DATA_DIR=/app/data
ports:
  - "8080:8080"
volumes:
  # 登录功能必需：不挂载则容器重建后账号与找回码全部丢失
  - ./data:/app/data
restart: unless-stopped
```

#### 多架构支持
项目支持多架构Docker镜像：
- `linux/amd64` - x86_64 架构
- `linux/arm64` - ARM 64位架构

#### 镜像版本
- `latest` - 最新稳定版本
- `v1.0.x` - 特定版本号
- `dev` - 开发版本

## 🔐 账号与登录

服务为**单账号模式**，未登录无法访问任何页面与接口（登录页、静态资源除外）。

### 首次使用
1. 打开站点，自动进入「首次使用，设置管理员账号」
2. 填写用户名与密码（≥ 8 位），提交后账号立即创建并自动登录
3. 页面展示**一次性找回码**（形如 `A7K2-9XQP-M4RT-8ZNV-3C6H-WQ2D`）
   - 只显示这一次，可复制或下载 `.txt`
   - 必须勾选「我已保存」才能进入应用

### 忘记密码
1. 登录页点「忘记密码？用找回码重置」
2. 输入找回码（不区分大小写，空格与连字符可忽略）+ 新密码
3. 重置成功后**旧码立即作废**，系统下发新的找回码，需重新保存

### 安全设计
| 项目 | 实现 |
|---|---|
| 密码存储 | PBKDF2-HMAC-SHA256，21 万轮 + 16 字节随机盐，常量时间比较 |
| 找回码存储 | 同样只存哈希，明文不落库、不写日志 |
| 会话 | HMAC-SHA256 签名的 HttpOnly Cookie，7 天有效，密钥存 `data/secret.key` |
| 暴力破解 | 同一来源连续 5 次失败锁定 3 分钟（密码与找回码分别计数） |
| 全站保护 | 页面未登录 302 跳 `/login`；`/api/*`、`/ws/*` 未登录返回 401 |

### 数据文件
```
data/
├── auth.json    # 用户名、密码哈希、找回码哈希（0600 权限）
└── secret.key   # 会话签名密钥（0600 权限）
```
> 这两个文件等价于账号本身：**务必备份，且不要提交到版本库**（`.gitignore` 已排除）。
> 若同时丢失密码和找回码，只能停止服务、删除 `data/auth.json` 后重新初始化。

## 🎯 使用方法

### 发送文件
1. 选择文件 → 生成取件码 → 分享6位码

### 文字传输
1. 输入文字内容 → 生成取件码 → 分享给对方

### 桌面共享
1. 点击共享桌面 → 生成取件码 → 对方输入码观看

## 📊 项目架构

```
发送方 ←─── WebSocket信令 ───→ 服务器 ←─── WebSocket信令 ───→ 接收方
   │                                                            │
   └────────────── WebRTC P2P直连传输 ──────────────────────────┘
```

## 🛠️ 本地开发

```bash
# 后端
make dev

# 前端
cd chuan-next && yarn && yarn dev
```

## 📄 许可证

MIT License

---

<div align="center">

⭐ 如果觉得这个项目对你有帮助，请给个星标！

[![Star History Chart](https://api.star-history.com/svg?repos=MatrixSeven/file-transfer-go&type=timeline)]

</div>
