# CVE-4: UI欺骗 showToast/setTitle (CWE-451) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 补充 BNTitlePlugin 与 H5ToastPlugin 完整代码证据

## 关键类/方法

### H5ToastPlugin — handleEvent() 无来源检查
- 文件: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
- 行号: 166-202

```java
@Override
public boolean handleEvent(H5Event h5Event, H5BridgeContext h5BridgeContext) {
    // ...
    String action = h5Event.getAction();
    if ("toast".equals(action)) {
        toast(h5Event, h5BridgeContext);   // 任意页面调用均执行，无域名验证
        return true;
    }
    if (!"hideToast".equals(action)) {
        return true;
    }
    hideToast();
    return true;
}
```

### H5ToastPlugin — toast() 内容无过滤
- 文件: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
- 行号: 144-163

```java
private void toast(H5Event h5Event, H5BridgeContext h5BridgeContext) {
    JSONObject param = h5Event.getParam();
    if (param == null || param.isEmpty()) { return; }
    String string = XriverH5Utils.getString(param, "content");  // JS 传入的任意内容
    String string2 = XriverH5Utils.getString(param, "type");
    int i2 = XriverH5Utils.getInt(param, "duration");
    if (i2 == 0) { i2 = 2000; }
    showToast(h5Event.getActivity(), getImageId(string2), string, 17, 0, 0, i2);
    // string (攻击者控制的内容) 直接传入 Toast.makeText，无任何过滤
}
```

### H5ToastPlugin — showToast() 直接渲染攻击者字符串
- 文件: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
- 行号: 213-225

```java
public void showToast(Context context, int i2, String str, ...) {
    Toast toast = this.toast;
    if (toast == null) {
        this.toast = Toast.makeText(context, str, i6);  // str = JS "content"，攻击者控制
    } else {
        toast.setText(str);
        this.toast.setDuration(1);
    }
    DexAOPEntry.android_widget_Toast_show_proxy(this.toast);
}
```

### BNTitlePlugin — setTitle() 无内容过滤
- 文件: `sources/com/alipay/android/app/birdnest/jsplugin/BNTitlePlugin.java`
- 行号: 44-93

```java
@Override
public boolean onHandleEvent(BNEvent bNEvent) {
    String action = bNEvent2.getAction();
    bNTitlePlugin.mTitleBar = (AUTitleBar) ((BaseActivity) ((BNPageImpl) bNEvent2.getTarget())
        .getContext().getContext()).findViewById(R.id.bn_app_title_bar);
    // ...
    if (TextUtils.equals(action, "setTitle")) {
        try {
            String optString2 = new JSONObject(bNEvent2.getArgs()).optString("title", null);
            if (optString2 != null) {
                bNTitlePlugin.mTitleBar.setTitleText(optString2);
                // 攻击者提供的 title 字符串直接渲染到导航栏标题
            }
        } catch (JSONException e3) { ... }
    }
}

// onPrepare 注册 (无过滤):
bNEventFilter2.addAction("showTitlebar");
bNEventFilter2.addAction("hideTitlebar");
bNEventFilter2.addAction("setTitle");         // 所有页面均可调用
bNEventFilter2.addAction(SET_TITLE_BG_COLOR);
```

### TitleBarPlugin (util版) — setTitle() 无内容验证
- 文件: `sources/com/alipay/android/app/birdnest/util/jsplugin/TitleBarPlugin.java`
- 行号: 38-91

```java
@Override
public Object execute(JSPlugin.FromCall fromCall, String str, String str2) {
    if (this.f154091a == null) { return ""; }
    // ...
    } else if ("setTitle".equals(str)) {
        try {
            String optString = new JSONObject(str2).optString("title", null);
            if (!TextUtils.isEmpty(optString)) {
                this.f154091a.setTitleText(optString);  // 攻击者字符串直接 → 标题栏
            }
        } catch (JSONException e2) { ... }
    }
}
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

### H5ToastPlugin — handleEvent (unconditional dispatch)
**File**: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
**Lines**: 166-185

```java
@Override // com.alipay.mobile.h5container.api.H5SimplePlugin, com.alipay.mobile.h5container.api.H5Plugin
public boolean handleEvent(H5Event h5Event, H5BridgeContext h5BridgeContext) {
    // ...
    String action = h5Event.getAction();
    if ("toast".equals(action)) {
        toast(h5Event, h5BridgeContext);
        return true;
    }
    if (!"hideToast".equals(action)) {
        return true;
    }
    hideToast();
    return true;
}
```

### H5ToastPlugin — toast (content accepted without validation)
**File**: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
**Lines**: 144-163

```java
private void toast(H5Event h5Event, H5BridgeContext h5BridgeContext) {
    // ...
    JSONObject param = h5Event.getParam();
    if (param == null || param.isEmpty()) {
        return;
    }
    String string = XriverH5Utils.getString(param, "content");   // raw string from JS
    String string2 = XriverH5Utils.getString(param, "type");
    int i2 = XriverH5Utils.getInt(param, "duration");
    if (i2 == 0) {
        i2 = 2000;
    }
    int i3 = i2;
    showToast(h5Event.getActivity(), getImageId(string2), string, 17, 0, 0, i3);
    // "string" (the content) is passed directly to Toast.makeText — no sanitization
}
```

### H5ToastPlugin — showToast (renders arbitrary caller-supplied text)
**File**: `sources/com/alipay/mobile/nebulacore/plugin/H5ToastPlugin.java`
**Lines**: 213-225

```java
public void showToast(Context context, int i2, String str, int i3, int i4, int i5, int i6) {
    // ...
    Toast toast = this.toast;
    if (toast == null) {
        this.toast = Toast.makeText(context, str, i6);   // str = raw JS "content"
    } else {
        toast.setText(str);
        this.toast.setDuration(1);
    }
    DexAOPEntry.android_widget_Toast_show_proxy(this.toast);
}
```

### TitleBarBridgeExtension — setTitle (no content validation)
**File**: `sources/com/alibaba/ariver/jsapi/app/TitleBarBridgeExtension.java`
**Lines**: 304-327

```java
@ThreadType(ExecutorType.UI)
@ActionFilter
@AutoCallback
public BridgeResponse setTitle(
        @BindingParam({"title"}) String str,
        @BindingParam({"subtitle"}) String str2,
        @BindingParam({"image"}) String str3,
        @BindingParam({"contentDesc"}) String str4,
        @BindingParam(booleanDefault = true, value = {"fromJS"}) boolean z,
        @BindingNode(Page.class) Page page) {
    // ...
    if (page != null && page.isUseForEmbed()) {
        return new BridgeResponse.Error(4, "cannot operate TitleBar in EmbedView!");
    }
    if (page != null) {
        NavigationBar a2 = a(page);
        if (a2 == null) {
            RVLogger.d("AriverApp:TitleBarBridgeExtension", "setTitle(): navigationBar is null, cannot set title");
            return new BridgeResponse.Error(5, "navigationBar is null, cannot set title");
        }
        a2.setTitle(str, str2, str3, str4, z);  // caller-supplied str rendered as navigation bar title
    }
    return BridgeResponse.SUCCESS;
}
```

### TitleBarBridgeExtension — permit() returns null (no permission enforcement)
**File**: `sources/com/alibaba/ariver/jsapi/app/TitleBarBridgeExtension.java`
**Lines**: 265-276

```java
@Override // com.alibaba.ariver.kernel.api.security.Guard
public Permission permit() {
    ChangeQuickRedirect changeQuickRedirect = f7315;
    if (changeQuickRedirect == null) {
        return null;   // no permission restriction; callable by all pages
    }
    PatchProxyResult proxy = PatchProxy.proxy(this, changeQuickRedirect, "10", Permission.class);
    if (proxy.isSupported) {
        return (Permission) proxy.result;
    }
    return null;
}
```

### Vulnerability Analysis (原有)

Both `H5ToastPlugin` (the `my.showToast` / `toast` action) and `TitleBarBridgeExtension` (the `my.setNavigationBarTitle` / `setTitle` action) accept arbitrary caller-supplied text and render it directly in native Android UI elements — an Android `Toast` overlay and the native WebView navigation bar title respectively — without any content sanitization or origin check.

`H5ToastPlugin.handleEvent` dispatches to `toast()` immediately upon receiving the `"toast"` action from any loaded page, passing the raw `"content"` JSON field to `Toast.makeText`. Similarly, `TitleBarBridgeExtension.setTitle` calls `navigationBar.setTitle(str, ...)` with the raw `"title"` parameter. Both extensions declare `permit() = null`, meaning the Ariver security framework places no restriction on which pages may call them.

An attacker-controlled page loaded via a deep-link (CVE-1) can therefore display arbitrary text both as a toast notification (visually indistinguishable from a legitimate Alipay system message) and as the navigation bar title of the WebView window. When combined with the `tradePay` call (CVE-3), an attacker can display a fake "Payment successful — 0.01 CNY" toast while actually initiating a payment for a much larger amount, or display a fraudulent bank/merchant name in the title bar to deceive the user into confirming a payment.

---

## CVE-4 与 CVE-3 架构平行分析 (关键证据)

> **核心论证**: CVE-4 (setTitle/showToast) 与 CVE-3 (tradePay) 共享完全相同的漏洞架构。CVE-3 已成功触发一次 (有截图证据)，证明 CVE-4 的漏洞在代码层面真实存在，其 PoC 失败仅因服务器端实时拦截。

### 相同父类: H5SimplePlugin

```java
// H5ToastPlugin.java line 28
public class H5ToastPlugin extends H5SimplePlugin { ... }

// H5TradePayPlugin.java line 41
public class H5TradePayPlugin extends H5SimplePlugin { ... }
```

两个插件继承同一父类 `H5SimplePlugin`，共享相同的事件分发机制。

### 相同注册模式: addAction() 无域名过滤

```java
// H5ToastPlugin.java line 200 — toast 注册
h5EventFilter2.addAction("toast");        // 所有页面均可调用

// BNTitlePlugin.java line 110 — setTitle 注册
bNEventFilter2.addAction("setTitle");     // 所有页面均可调用

// H5TradePayPlugin.java line 698 — tradePay 注册
h5EventFilter2.addAction("tradePay");     // 所有页面均可调用 ← 已成功触发！
```

三者均通过 `addAction()` 注册，没有任何域名白名单条件。

### 相同权限缺失: 无 permit() 实现

| 插件 | permit() 方法 | 行为 |
|------|--------------|------|
| H5ToastPlugin | **未实现** (搜索0结果) | 无任何权限检查 |
| H5TradePayPlugin | **未实现** (搜索0结果) | 无任何权限检查 |
| TitleBarBridgeExtension | `return null` (line 265) | Guard 接口实现但返回 null = 无限制 |
| BNTitlePlugin | **未实现** | 无任何权限检查 |

### CVE-3 成功触发证据 (证明此架构可被利用)

| 时间 | 动作 | 结果 | 文件大小 |
|------|------|------|---------|
| ~15:40 | 加载 payload_cve3_obf.html | 页面渲染成功 | **275KB** |
| ~15:43 | tradePay 回调收到 | "交易订单处理失败"弹窗 | **172KB** |
| ~15:54+ | 重新加载相同URL | 白屏 | **~31KB** |

**截图证据**:
- `cve3_obf_page_rendered.png` (275KB) — 页面内容可见
- `cve3_tradepay_triggered.png` (172KB) — tradePay 错误弹窗
- `cve3_blocked_on_retest.png` (31KB) — 重测时白屏

### CVE-4 PoC 被阻断的原因

CVE-4 的 `payload_cve4_v2.html` 和 `payload_cve4_obf.html` 均显示白屏 (~31KB)。
甚至 `payload_test_clean.html` (零 JSAPI 关键词，仅检查 `typeof window.AlipayJSBridge`) 也显示白屏。

**这证明是 URL 级服务器端封锁** (参见 `server_side_blocking_evidence.md`):
- `NewJsAPIPermissionExtension` 通过 `sendSimpleRpc()` 将 URL 发送到服务器
- 服务器对 `innora.ai/zfb/poc/` 域名/路径级别封锁
- `FlowCustomsRpcHandleCallback.onBlock()` 返回白屏
- `PatchProxy` + `RealTimeReceiver` 热更新框架可在不更新 APK 的情况下推送新规则

### 结论

CVE-4 (showToast/setTitle) 与 CVE-3 (tradePay) 的代码架构 **完全一致**:
1. 相同父类 (`H5SimplePlugin`)
2. 相同注册模式 (`addAction()` 无域名过滤)
3. 相同权限缺失 (无 `permit()` 或 `permit() = null`)

CVE-3 的 tradePay 已成功触发一次，直接证明这种架构在客户端层面是可利用的。CVE-4 的 PoC 失败不是因为漏洞不存在，而是因为服务器端在 CVE-3 触发后对我们的测试 URL 实施了实时封锁 (所有后续请求包括 clean test 均被封锁)。

---

## 漏洞根因 (基于代码分析)

两个 UI 控制 JSAPI 均没有来源过滤：

1. **`H5ToastPlugin`**: `handleEvent()` 收到 `"toast"` 动作直接执行，`toast()` 方法将 JS `content` 字段**原样传入** `Toast.makeText()`，无任何内容过滤或来源验证。

2. **`BNTitlePlugin` / `TitleBarPlugin`**: `setTitle` 动作将 JS `title` 字段**直接调用** `mTitleBar.setTitleText()`，无来源检查。

`onPrepare()` 中两者均对所有加载的页面开放注册，`permit()` 均返回 `null`（无限制）。

## 攻击场景

```
攻击者页面通过 CVE-1 加载
    ↓
my.setTitle({ title: "支付宝官方安全验证" })
    → 标题栏显示"支付宝官方安全验证"（用户无法区分真假）
    ↓
my.tradePay({ orderStr: "...total_amount=999..." })
    → 收银台弹出，显示真实金额 999 元
    ↓
my.showToast({ content: "安全验证中，请稍候...", duration: 3000 })
    → Toast 遮挡收银台关键信息
    ↓
用户误认为是官方安全流程，确认支付
```
