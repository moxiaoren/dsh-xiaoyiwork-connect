# dsh-xiaoyiwork-connect

把已登录的 **小艺Work 桌面端** 模型代理，接到 DeepSeek Harness (DSH) 对话窗口里零配置使用，**直接消耗小艺Work 额度**（无需单独申请 API Key）。

> **平台要求：Windows 专用。** proxyKey 存放于 Windows 注册表（`HKCU\Software\ClawDesktop\keychain\model-proxy`），主密钥由 **DPAPI(CurrentUser)** 保护——这两者都是 Windows 独有的机制。macOS / Linux 不可用。

## 原理（已逆向核实，无需修改小艺Work）

小艺Work 自带一个 OpenAI 兼容的本地模型代理：

- 监听 `127.0.0.1:19693`（`GAUSSPD_MODEL_PROXY_PORT`），SSE 流式路径 `/celia/v1/sse-api/chat/completions`。
- 鉴权接受请求头 `Authorization: Bearer <proxyKey>`（或 `X-Api-Key`）。
- 该代理把请求转发到小艺云模型端点，**因此 DSH 发往该地址的请求即消耗小艺Work 额度**。

`proxyKey` 以 Chromium **OSCrypt v10** 信封存放在注册表里——注意值类型是 `REG_SZ`（String），内容就是**单层** base64 的信封字节：

```
HKCU\Software\ClawDesktop\keychain\model-proxy
  值名 cHJveHlLZXk
  数据 = base64( "v10" + iv(12) + ciphertext + tag(16) )      # AES-256-GCM
```

信封的 AES 主密钥**不在注册表里**，而在小艺Work 自己的 `%APPDATA%\xiaoyiwork\Local State` → `os_crypt.encrypted_key`，由 **DPAPI(CurrentUser)** 保护（去掉开头 `DPAPI` 这 **5** 个字节后即为 DPAPI blob；多切 4 字节会报 `The data is invalid`）。解出的是 **32 字节**主密钥。明文是 `{"s":"model-proxy","a":"proxyKey","v":"mpk_…"}`，取 `v` 即 proxyKey。

尺寸可自检：信封 **124** 字节 = 3 + 12 + **93** + 16，而该明文 JSON 正好 **93** 字符（GCM 是流密码，密文长度 == 明文长度）。

### 凭据处理：全程不落盘（安全设计）

**早期方案**是把 proxyKey 解密后写到本地明文文件（如 `xiaoyiwork.proxykey`），再由插件轮询读取——但明文文件会被同机任何进程读到，等同泄露密码。

**本插件已弃用该方案**：因为 DSH 桌面端和小艺Work **同属当前登录的 Windows 用户**，而 DPAPI(CurrentUser) 可由同用户进程直接解密。所以插件**直接在自己的进程内**：

1. 起一次 PowerShell：读注册表信封，同时读 `Local State` 的 `encrypted_key` 并用 `ProtectedData.Unprotect`（DPAPI, CurrentUser）还原主密钥——PS 5.1 必须先 `Add-Type -AssemblyName System.Security`，否则 `[ProtectedData]` 报「找不到类型 [System.Security.Cryptography.ProtectedData]」；
2. 回到 Node 用 `createDecipheriv("aes-256-gcm", 主密钥, iv)` 解出明文（PS 5.1 的 .NET Framework 没有 `AesGcm`，AES-GCM 只能在 Node 侧做）；
3. 仅在**内存**里持有明文、注入到请求头；

**全程不写任何磁盘文件**。没有明文文件，就不存在"被别的进程读到密码"的风险。取不到 key（小艺Work 未运行 / 未登录）时模型组隐藏，每 30s 重试，待小艺Work 启动后自动显示。

> 想跳过自动解密，可在插件 config 里给 `apiKey`，或设环境变量 `DSH_XIAOYIWORK_PROXY_KEY`——两者优先级都高于读注册表，且不依赖 PowerShell。

## 安装

在 DSH 桌面端的插件市场里搜索 `dsh-xiaoyiwork-connect` 安装，或在终端执行：

```bash
dsh plugin add dsh-xiaoyiwork-connect
```

该命令会：① 把依赖写进 profile 的 `package.json`；② 跑 pnpm 把插件正式链接进 `node_modules`（重启不丢）；③ 把它加进 `bundles`。执行完重启 DSH 桌面版即可。

也可以直接从源码装：

```bash
dsh plugin add github:moxiaoren/dsh-xiaoyiwork-connect
```

### 在 DSH 里用

- 打开对话窗口 → 模型选择器出现「小艺Work 模型代理」分组（含 DeepSeek-V4-Flash / V4-Pro / GLM-5.3 / MiniMax M3 / Kimi K3 等，名字带「· 小艺Work」后缀）。
- **小艺Work App 必须保持运行**（代理只在 App 运行时监听 19693）；启动时若尚未登录，模型组会隐藏，登录并启动后约 30s 内自动出现。

## 注意事项 / 诚实声明

- **额度消耗真实存在**：经此路由的对话直接计入小艺Work 账号，请知悉资费。
- **仅本机、同用户可用**：DPAPI 是用户态绑定，插件必须在与登录小艺Work 同一 Windows 账户下运行；换用户/换机不可用。
- **不落盘凭据**：proxyKey 只在进程内存内解密使用，不写任何文件（无明文泄露面）。
- **不修改小艺Work**：纯读取注册表 + 内存内 DPAPI 解密 + 本地代理转发，不注入、不改动 App 进程，比"改 App 添加外部 provider"更稳。
- **已验证（实测）**：注册表值 `GetValueKind` = `String`、内容 168 字符单层 base64 → 124 字节信封（前缀 `v10`）；`Local State` 的 `encrypted_key` 去 5 字节 `DPAPI` 头后经 DPAPI 解出 **32 字节**主密钥（切 9 字节会报 `The data is invalid`）；密文 93 字节与该明文 JSON 的 93 字符长度吻合；端点 `POST http://127.0.0.1:19693/celia/v1/sse-api/chat/completions`（`Authorization: Bearer <proxyKey>`，SSE 流式）返回 200，`LLM_DeepSeekV4_Think` 返回 `reasoning_content`+`content`，`DeepSeek_V4.1_Flash_VE` 返回 `content`。
- **已在真机验证通过**：注册路径（`ctx.llm.registerAdapter` + `PiAiAdapter`，与 `dsh-workbuddy-connect` 同款真实 API）已在 DSH 桌面端实际运行并出现在模型选择器中，经该分组发起对话可正常返回。宿主日志会打「小艺Work 模型代理插件已加载（llm-xiaoyiwork）」与「已注册小艺Work 模型代理路由「xiaoyiwork」」，取不到 key 时打**具体原因**——排障看宿主日志即可，不必再猜。

## 文件清单

- `cordis.patch.yml` — 路由注册清单（bundle patch，id=llm-xiaoyiwork）。
- `package.json` — 插件元信息与 peerDeps（cordis / schemastery / dsh-llm / dsh-llm-pi-ai / pi-ai）。
- `lib/index.js` — 路由注册逻辑：构造 PiAiAdapter 并通过 `ctx.llm.registerAdapter(["xiaoyiwork"], adapter)` 注册（与 workbuddy 同款真实 API）；一次 PowerShell 调用取回「注册表信封 + DPAPI 还原的主密钥」，Node 侧 AES-256-GCM 解出 proxyKey，**全程内存内、不落盘**；解出的 key 缓存复用，未注册时每 30s 重试。

## License

MIT
