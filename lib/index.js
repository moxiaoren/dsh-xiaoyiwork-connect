// dsh-xiaoyiwork-connect — 复用已登录的小艺Work 桌面端模型代理额度。
//
// 采用与 dsh-workbuddy-connect 完全相同的注册路径：直接构造一个 PiAiAdapter
// 实例并通过 ctx.llm.registerAdapter() 注册（这是宿主 llm 服务真实暴露的 API），
// 而不是旧版猜测的 registerProvider/upsertProvider/registerRoute 等不存在的方法。
//
// 端点事实（已实测核实）：
//   * 小艺Work 自带 OpenAI 兼容本地代理，监听 127.0.0.1:19693
//     （GAUSSPD_MODEL_PROXY_PORT），SSE 路径 /celia/v1/sse-api/chat/completions。
//   * 鉴权接受 `Authorization: Bearer <proxyKey>`。
//   * OpenAI SDK 会在 baseUrl 后自动拼 /chat/completions，故 baseUrl 填
//     http://127.0.0.1:19693/celia/v1/sse-api（不含尾段）。
//   * proxyKey 以小艺Work 自己的 Chromium OSCrypt v10 信封（AES-256-GCM，主密钥由
//     DPAPI CurrentUser 保护）存入注册表：
//       HKCU\Software\ClawDesktop\keychain\model-proxy
//       值名 cHJveHlLZXk（= base64url("proxyKey")，是字段名本身，不是密钥）
//       值   = base64( "v10" + iv(12) + ciphertext + tag(16) )   ← 值类型是 REG_SZ，单层 base64
//     AES 主密钥在小艺Work 的 Local State（os_crypt.encrypted_key，DPAPI 保护，去 5 字节头）。
//   * 解密【不落盘】proxyKey：起一次 PowerShell 取回「注册表信封 + DPAPI 还原的主密钥」，
//     回到 Node 用 AES-256-GCM 当场解出，仅内存使用。

import { createProvider } from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { PiAiAdapter } from "@deepseek-ai/dsh-llm-pi-ai";
import { resolveRetryPolicy } from "@deepseek-ai/dsh-llm";
import { existsSync } from "node:fs";
import { createDecipheriv } from "node:crypto";
import { execFileSync } from "node:child_process";

/** Stable Cordis plugin name. */
const name = "llm-xiaoyiwork";
/** The model registry required before the provider can register. */
const inject = ["llm"];

const DISPLAY_NAME = "小艺Work 模型代理";
const BASE_URL = "http://127.0.0.1:19693/celia/v1/sse-api";
const STREAM_IDLE_TIMEOUT_MS = 300_000;
const POLL_MS = 30_000;

// proxyKey 注册表位置。
const REG_PATH = "HKCU:\\Software\\ClawDesktop\\keychain\\model-proxy";
const REG_NAME = "cHJveHlLZXk";

// 小艺Work 的 OSCrypt 主密钥所在（Local State）。按 env 解析，失败再试常见路径。
const LOCAL_STATE_CANDIDATES = [
  process.env.APPDATA && `${process.env.APPDATA}\\xiaoyiwork\\Local State`,
  process.env.LOCALAPPDATA && `${process.env.LOCALAPPDATA}\\xiaoyiwork\\Local State`,
].filter(Boolean);

// 绝对路径调用 Windows PowerShell，避开 PATH 差异；系统目录意外缺失时退回 PATH 查找。
const POWERSHELL_EXE = `${process.env.SystemRoot || "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
const POWERSHELL = existsSync(POWERSHELL_EXE) ? POWERSHELL_EXE : "powershell.exe";
// -EncodedCommand 接收 UTF-16LE 的 base64，彻底绕开命令行上引号/非 ASCII 的转义分歧。
const POWERSHELL_ARGS = ["-NoProfile", "-NonInteractive", "-EncodedCommand"];

// 小艺Work 订阅模型目录（来自 %APPDATA%\xiaoyiwork\users\<uid>\models.json）。
const MODELS = [
  { id: "LLM_DeepSeekV4_Think", name: "DeepSeek-V4-Flash", reasoning: "think" },
  { id: "DeepSeek_V4.1_Flash_VE", name: "DeepSeek-V4.1-Flash", reasoning: "none" },
  { id: "LLM_DeepSeekV4_Pro_Think", name: "DeepSeek-V4-Pro", reasoning: "think" },
  { id: "OpenPanguV2-Pro", name: "openPangu-2.1-Pro", reasoning: "none" },
  { id: "GLM_5.3_VE", name: "GLM-5.3", reasoning: "none" },
  { id: "GLM_5.3_FLASH_VE", name: "GLM-5.3-Flash", reasoning: "none" },
  { id: "MiniMax-M3", name: "MiniMax M3", reasoning: "none" },
  { id: "Kimi_K3", name: "Kimi K3", reasoning: "none" },
];

// 小艺Work 不暴露 kgw 风格 reasoning_effort 细档；think 模型给 low/medium/high 三档。
const THINKING_LEVEL_MAP = {
  off: null,
  low: "low",
  medium: "medium",
  high: "high",
};

/** No per-token pricing is knowable for a subscription quota; report zero. */
const NO_COST = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
};

/**
 * Inert auth plane: every ambient question answers "nothing stored, nothing set".
 * PiAiAdapter otherwise walks ctx.credentials / ctx.authorization, which this
 * route does not own.
 */
const INERT_AUTH = {
  credentials: {
    async read() {},
    async list() {
      return [];
    },
    async modify() {
      throw new Error("dsh-xiaoyiwork-connect: the xiaoyiwork route has no pi-ai credential lifecycle");
    },
    async delete() {},
  },
  authContext: {
    async env() {},
    async fileExists() {
      return false;
    },
  },
};

// ─────────────────────────── proxyKey 解密 ───────────────────────────

// 解析小艺Work 的信封 JSON { s:'model-proxy', a:'proxyKey', v:<明文key> }；
// 少数情况下也可能直存明文 key，故做容错。
function parseEnvelope(plain) {
  const trimmed = String(plain).trim();
  if (!trimmed) return undefined;
  try {
    const env = JSON.parse(trimmed);
    if (env && typeof env.v === "string") return env.v.length ? env.v : undefined;
  } catch {
    /* 不是 JSON 信封，当作裸 key */
  }
  return trimmed.length ? trimmed : undefined;
}

// 一次 PowerShell 调用取回两样东西：
//   ENV = 注册表里 proxyKey 信封的裸字节（base64）
//   MK  = 小艺Work Local State 里 os_crypt 主密钥（DPAPI CurrentUser 还原后的裸字节）
// 合成一次调用，就只有一个失败面、一句可读错误。
// 注意：PS 5.1 默认不加载 System.Security，缺 Add-Type 时 [ProtectedData] 会报「找不到类型」。
function readEnvelopeAndMasterKey() {
  const lsPath = LOCAL_STATE_CANDIDATES.find((p) => {
    try {
      return p && existsSync(p);
    } catch {
      return false;
    }
  });
  if (!lsPath) throw new Error("找不到小艺Work 的 Local State（小艺Work 未安装或从未运行过？）");

  const ps = [
    '$ErrorActionPreference="Stop"',
    "Add-Type -AssemblyName System.Security",
    `$k=Get-Item -LiteralPath '${REG_PATH}' -ErrorAction Stop`,
    `$v=$k.GetValue('${REG_NAME}')`,
    `$t=$k.GetValueKind('${REG_NAME}')`,
    // REG_SZ 里放的就是 base64（单层）；REG_BINARY 才是裸字节。
    // 把 REG_SZ 的字符串再 base64 一次，Node 解出来只会是 base64 文本本身——旧版就栽在这里。
    'if($t -eq [Microsoft.Win32.RegistryValueKind]::Binary){$envB64=[Convert]::ToBase64String($v)}' +
      'else{$s=[string]$v;try{$envB64=[Convert]::ToBase64String([Convert]::FromBase64String($s))}' +
      'catch{$envB64=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($s))}}',
    `$ls=Get-Content -LiteralPath '${lsPath.replace(/'/g, "''")}' -Raw -Encoding UTF8`,
    '$m=[regex]::Match($ls,\'"encrypted_key"\\s*:\\s*"([^"]+)"\')',
    // 报错信息保持纯 ASCII：PowerShell 重定向到管道时按 OEM 代码页输出，中文会变乱码。
    'if(-not $m.Success){throw "no os_crypt.encrypted_key in xiaoyiwork Local State"}',
    '$b=[Convert]::FromBase64String($m.Groups[1].Value)',
    // 头只有 "DPAPI" 5 字节；其后 01 00 00 00 属于 DPAPI blob 自身，多切 4 字节必然报 data invalid。
    '$mk=[System.Security.Cryptography.ProtectedData]::Unprotect($b[5..($b.Length-1)],$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
    'Write-Output ("ENV=" + $envB64)',
    'Write-Output ("MK=" + [Convert]::ToBase64String($mk))',
  ].join(";");

  let out;
  try {
    const encoded = Buffer.from(ps, "utf16le").toString("base64");
    out = execFileSync(POWERSHELL, [...POWERSHELL_ARGS, encoded], { windowsHide: true, timeout: 20_000 }).toString("utf8");
  } catch (error) {
    throw new Error(`PowerShell 调用失败（${POWERSHELL}）：${error?.message ?? error}`);
  }
  const envLine = /^ENV=(.+)$/m.exec(out);
  const mkLine = /^MK=(.+)$/m.exec(out);
  if (!envLine || !mkLine) throw new Error("PowerShell 没有返回 ENV/MK");
  return { env: Buffer.from(envLine[1].trim(), "base64"), masterKey: Buffer.from(mkLine[1].trim(), "base64") };
}

// 当场解密 proxyKey，返回 { key } 或 { error }（错误原因交给调用方记日志，不再静默失败）。
// 信封 = "v10" + iv(12) + ciphertext + tag(16)，AES-256-GCM；主密钥 32 字节。
// 只有 OSCrypt 这一条路：小艺Work 用的是它自己 Local State 的键，DSH 的 Electron safeStorage
// 拿的是 DSH 的键，跨应用解不开，所以不做 safeStorage 尝试。
function decryptProxyKey() {
  let env;
  let masterKey;
  try {
    ({ env, masterKey } = readEnvelopeAndMasterKey());
  } catch (error) {
    return { error: error?.message ?? String(error) };
  }
  const magic = env.subarray(0, 3).toString("latin1");
  if (magic !== "v10") return { error: `注册表信封前缀不是 v10（读到 ${JSON.stringify(magic)}）` };
  const body = env.subarray(3);
  if (body.length <= 12 + 16) return { error: `信封长度异常（${env.length} 字节）` };
  if (masterKey.length !== 32) return { error: `OSCrypt 主密钥长度 ${masterKey.length}，应为 32` };
  try {
    const decipher = createDecipheriv("aes-256-gcm", masterKey, body.subarray(0, 12));
    decipher.setAuthTag(body.subarray(body.length - 16));
    const plaintext = Buffer.concat([decipher.update(body.subarray(12, body.length - 16)), decipher.final()]);
    const key = parseEnvelope(plaintext.toString("utf8"));
    return key ? { key } : { error: "解密成功但信封里没有 key 字段" };
  } catch (error) {
    return { error: `AES-GCM 解密失败：${error?.message ?? error}` };
  }
}

// 兜底优先级：config.apiKey → 环境变量 → 注册表解密。
// 解出来的 key 缓存一次就够：它是小艺Work 的长期 key，而解密要起 PowerShell，
// 不该每个 LLM 请求都跑一遍。失败原因留在 _keyError 给 apply 记日志。
let _keyCache;
let _keyError;
function resolveKey(config) {
  if (_keyCache) return _keyCache;
  const fromConfig = config && typeof config.apiKey === "string" ? config.apiKey : "";
  if (fromConfig) return (_keyCache = fromConfig);
  const fromEnv = process.env.DSH_XIAOYIWORK_PROXY_KEY;
  if (fromEnv) return (_keyCache = fromEnv);
  const result = decryptProxyKey();
  if (result.key) {
    _keyError = undefined;
    return (_keyCache = result.key);
  }
  _keyError = result.error;
  return undefined;
}

// ─────────────────────────── adapter 构造 ───────────────────────────

function toPiModel(m) {
  return {
    id: m.id,
    name: `${m.name} · 小艺Work`,
    api: "openai-completions",
    provider: "xiaoyiwork",
    baseUrl: BASE_URL,
    input: ["text"],
    ...(m.reasoning === "think"
      ? { reasoning: true, thinkingLevelMap: THINKING_LEVEL_MAP }
      : { reasoning: false }),
    cost: NO_COST,
    contextWindow: 128_000,
    maxTokens: 8_192,
    compat: { maxTokensField: "max_tokens" },
  };
}

function createXiaoyiworkAdapter(resolveToken) {
  const buildModels = () => MODELS.map(toPiModel);
  const provider = {
    ...createProvider({
      id: "xiaoyiwork",
      name: DISPLAY_NAME,
      auth: {
        apiKey: {
          name: "小艺Work 本地代理 proxyKey",
          async resolve({ credential }) {
            const apiKey = credential?.key;
            return apiKey === undefined || apiKey.length === 0
              ? undefined
              : { auth: { apiKey }, source: "xiaoyiwork" };
          },
        },
      },
      models: buildModels(),
      api: openAICompletionsApi(),
    }),
    getModels: () => buildModels(),
  };
  const profile = {
    provider: "xiaoyiwork",
    displayName: DISPLAY_NAME,
    streamIdleTimeoutMs: STREAM_IDLE_TIMEOUT_MS,
    retryPolicy: resolveRetryPolicy(undefined, "dsh-xiaoyiwork-connect retryPolicy"),
    configuredMaxTokens: new Map(),
    modelErrors: new Map(),
    piProvider: provider,
  };
  let profiles = new Map([["xiaoyiwork", profile]]);
  return {
    adapter: new PiAiAdapter({
      profiles: () => profiles,
      auth: INERT_AUTH,
      resolveApiKey: async () => resolveToken(),
    }),
    invalidate: () => {
      profiles = new Map([["xiaoyiwork", profile]]);
    },
  };
}

// ─────────────────────────── 插件入口 ───────────────────────────

function apply(ctx, config) {
  let stopped = false;
  let releaseAdapter = undefined;
  const log = ctx.logger ?? { info: () => {}, warn: () => {}, error: () => {} };
  // 无条件打一行：这样「插件有没有被加载」在宿主日志里一眼可辨，不必再靠猜。
  log.info("小艺Work 模型代理插件已加载（llm-xiaoyiwork）");

  let loggedError;
  const tick = () => {
    if (stopped || releaseAdapter) return; // 注册成功后不再每 30s 起一次 PowerShell
    const apiKey = resolveKey(config);
    if (!apiKey) {
      // 同一原因只报一次，避免 30s 刷屏。
      if (_keyError !== loggedError) {
        loggedError = _keyError;
        log.warn(
          `未取到小艺Work proxyKey，模型组暂不注册：${_keyError ?? "未知原因"}；每 30s 重试，` +
            "也可在插件 config 设 apiKey 或设环境变量 DSH_XIAOYIWORK_PROXY_KEY。",
        );
      }
      return;
    }
    try {
      const { adapter } = createXiaoyiworkAdapter(() => resolveKey(config));
      releaseAdapter = ctx.llm.registerAdapter(["xiaoyiwork"], adapter);
      log.info("已注册小艺Work 模型代理路由「xiaoyiwork」");
    } catch (error) {
      log.warn(`注册小艺Work 路由失败：${error?.message}，30s 后重试`);
    }
  };

  tick(); // 立即尝试一次

  try {
    ctx.effect(() => () => {
      stopped = true;
      if (releaseAdapter) {
        try {
          releaseAdapter();
        } catch {
          /* ignore */
        }
      }
    });
  } catch {
    /* 无 lifecycle seam 时忽略 */
  }

  // proxyKey 可能是在 DSH 启动后才由小艺Work 写出：每 30s 重读。
  const timer = setInterval(tick, POLL_MS);
  timer.unref?.();
}

export { apply, inject, name };
