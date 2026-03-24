# CVE-3: tradePay未授权调用 (CWE-940) 代码证据

> APK 版本: Alipay 10.8.30.8000 | jadx 反编译输出
> 更新: 2026-03-16 — 补充 H5TradePayPlugin 代码证据

## 关键类/方法

### H5TradePayPlugin — onPrepare() JSAPI 注册
- 文件: `sources/com/alipay/mobile/framework/service/ext/phonecashier/H5TradePayPlugin.java`
- 行号: 686-701

```java
@Override
public void onPrepare(H5EventFilter h5EventFilter) {
    // ...
    h5EventFilter2.addAction("tradePay");   // 注册给所有 WebView 页面，无域名过滤
    h5EventFilter2.addAction("deposit");
    h5EventFilter2.addAction(TRADE_URL);    // "tradeUrl"
}
```

### H5TradePayPlugin — startPaymentWithOrderStr() 来源域名仅用于日志
- 文件: `sources/com/alipay/mobile/framework/service/ext/phonecashier/H5TradePayPlugin.java`
- 行号: 522-603

```java
public boolean a(String str, a aVar, H5Event h5Event, String str2, Map<String, String> map) {
    // ...
    if (h5Page != null) {
        Bundle params = h5Page.getParams();
        String string = H5Utils.getString(params, "appId");
        boolean z2 = H5Utils.getBoolean(params, "isTinyApp", false);
        // ...
        if (TextUtils.equals(str2, "tradePay")) {
            z = true;
            if (z2) {   // 来自小程序
                str4 = H5PayUtil.generateTinybizContext4OrderStr(str4, string, str3);
                hashMap.put("invoke_from_source", "tinyapp");
                hashMap.put("invoke_from_id", string);
                hashMap.put("invoke_from_api", "tradepay");
            } else {    // 来自 H5 页面
                str4 = H5PayUtil.generateH5bizContext4OrderStr(str4, h5Page.getUrl());
                hashMap.put("invoke_from_source", "h5page");
                hashMap.put("invoke_from_api", "tradepay");
                String realRefer = H5Utils.getRealRefer(h5Page, h5Page.getUrl());
                // ... realRefer 被截断到 30 字符，只放入日志 map，不做校验
                hashMap.put("invokeFromReferUrl", realRefer);  // 仅日志，非访问控制
            }
            // ...
            phoneCashierServcie.boot(str4, a(aVar, null, null), hashMap);
            // ^ 直接启动收银台，来源 URL 只进日志，不拒绝非白名单调用方
        }
    }
}
```

### H5TradePayPlugin — 常量定义
- 文件: `sources/com/alipay/mobile/framework/service/ext/phonecashier/H5TradePayPlugin.java`
- 行号: 42-48

```java
public static final String APPID = "appid";
public static final String APPID_CONTENT = "alipay";
public static final String DEPOSIT = "deposit";
public static final String SYSTEM = "system";
public static final String SYSTEM_CONTENT = "android";
public static final String TAG = "H5TradePayPlugin";
public static final String TRADE_PAY = "tradePay";    // JSAPI 名称
public static final String TRADE_URL = "tradeUrl";
```

---

## 原有分析 (保留)

## Source: Alipay APK 10.8.30.8000 (jadx decompiled)

### TradePayBridgeExtension — tradePay (annotated entry point)
**File**: `sources/com/alipay/mobile/phonecashier/TradePayBridgeExtension.java`
**Lines**: 270-287

```java
@NativeActionFilter
@Remote
public void tradePay(@BindingApiContext ApiContext apiContext, @BindingRequest JSONObject jSONObject,
                     @BindingCallback BridgeCallback bridgeCallback) {
    // ...
    if (jSONObject == null) {
        handleException(bridgeCallback);
        return;
    }
    if (apiContext instanceof ExtHubApiContext) {
        this.mBizType = ((ExtHubApiContext) apiContext).getBizType();
        this.mAppId = apiContext.getAppId();  // records caller appId for logging only
    }
    this.mBizContext = jSONObject.getString(LONG_SAFEPAY_CONTEXT);
    this.needEraseMemo = !TextUtils.equals(
        PhoneCashierMspEngine.hn().getWalletConfig("MQP_degrade_tradepay_erase_memo_10556"),
        "10000");
    tradePay(bridgeCallback, jSONObject);   // proceeds directly to payment boot
}
```

### TradePayBridgeExtension — tradePay (payment boot, no origin validation)
**File**: `sources/com/alipay/mobile/phonecashier/TradePayBridgeExtension.java`
**Lines**: 219-268

```java
public void tradePay(BridgeCallback bridgeCallback, JSONObject jSONObject) {
    // ...
    PhoneCashierServcie phoneCashierServcie = (PhoneCashierServcie)
        LauncherApplicationAgent.getInstance()
            .getMicroApplicationContext()
            .findServiceByInterface(PhoneCashierServcie.class.getName());
    if (phoneCashierServcie == null) {
        LogUtil.record(1, TAG, "cashierService is null.");
        handleException(bridgeCallback);
        return;
    }
    String string = jSONObject.getString("bizContext");
    if (TextUtils.isEmpty(string)) {
        string = this.mBizContext;
    }
    if (jSONObject.containsKey(ApLinkTokenUtils.ORDER_STRING_SPM_EXT_KEY)) {
        this.mOrderInfo = jSONObject.getString(ApLinkTokenUtils.ORDER_STRING_SPM_EXT_KEY);
        // appends bizcontext to orderInfo string, then boots cashier
        if (!TextUtils.isEmpty(string) && !TextUtils.isEmpty(this.mOrderInfo)
                && !this.mOrderInfo.contains("&bizcontext=")) {
            this.mOrderInfo += "&bizcontext=\"" + string + "\"";
        }
        HashMap hashMap = new HashMap();
        addExtendInfo(jSONObject, hashMap);
        phoneCashierServcie.boot(this.mOrderInfo, getPayCallback(bridgeCallback), hashMap);
        // ... logging only, no origin check before this call
        return;
    }
    if (jSONObject.containsKey("tradeNO")) {
        this.mTradeNo = jSONObject.getString("tradeNO");
        String string2 = jSONObject.getString("bizType");
        if (TextUtils.isEmpty(string2)) {
            string2 = "trade";
        }
        PhoneCashierOrderExp phoneCashierOrderExp = new PhoneCashierOrderExp();
        phoneCashierOrderExp.setBizType(string2);
        phoneCashierOrderExp.setOrderNo(this.mTradeNo);
        // ...
        phoneCashierServcie.boot(phoneCashierOrderExp, payCallback, hashMap3);
        // boots cashier with caller-supplied tradeNO, no origin validation
    }
}
```

### TradePayBridgeExtension — permit() returns null
**File**: `sources/com/alipay/mobile/phonecashier/TradePayBridgeExtension.java`
**Lines**: 206-217

```java
@Override // com.alibaba.ariver.kernel.api.security.Guard
public Permission permit() {
    ChangeQuickRedirect changeQuickRedirect = f83420;
    if (changeQuickRedirect == null) {
        return null;   // <-- no permission declared; framework allows all callers
    }
    PatchProxyResult proxy = PatchProxy.proxy(this, changeQuickRedirect, "12", Permission.class);
    if (proxy.isSupported) {
        return (Permission) proxy.result;
    }
    return null;
}
```

### Vulnerability Analysis (原有)

`TradePayBridgeExtension` implements the `tradePay` JSBridge API exposed to every WebView page running inside Alipay. The annotated entry point extracts `appId` and `bizType` from the caller context but uses them only for logging (via `addEventLog`), never as an access-control decision. The critical security guard point is `permit()`, which unconditionally returns `null` — the Ariver framework interprets a null `Permission` as "no restriction", meaning the API is callable from any page regardless of origin.

When `phoneCashierServcie.boot()` is called it opens the native payment cashier UI with the caller-supplied `orderInfo` string or `tradeNO`. An attacker who loads a malicious page via a deep-link (CVE-1) can therefore invoke `tradePay` with a crafted order string, launching the payment UI for an attacker-controlled transaction. While the user still sees a confirmation UI before funds are debited, the attacker controls the displayed price and recipient, enabling social-engineering / UI-spoofing fraud when combined with CVE-4.

---

## 漏洞根因 (基于代码分析)

`H5TradePayPlugin` 和 `TradePayBridgeExtension` 均将 `tradePay` JSAPI 注册给支付宝 H5 容器内的**所有**页面，没有来源域名白名单过滤。

关键证据：
1. `onPrepare()` 中 `addAction("tradePay")` 无任何域名条件
2. `startPaymentWithOrderStr()` 中来源 URL (`h5page.getUrl()`) 只放入日志 Map，不做拒绝决策
3. `permit()` 返回 `null`，框架解释为"无限制"

攻击者通过 CVE-1 将页面加载进支付宝 WebView 后，可立即调用 `my.tradePay({ orderStr: ... })` 触发支付界面，用户看到的收款方/金额均由攻击者的 `orderStr` 控制。

## 攻击路径

```
通过 CVE-1 加载攻击者页面到支付宝 WebView
    ↓
my.tradePay({ orderStr: "out_trade_no=FAKE&total_amount=9999&..." })
    ↓
H5TradePayPlugin.interceptEvent() / handleEvent()
    ↓
startPaymentWithOrderStr() — 来源 URL 只记日志，不拒绝
    ↓
phoneCashierServcie.boot(orderStr, callback, extInfo)
    ↓
收银台 UI 弹出，显示攻击者控制的金额和收款方
    ↓ (结合 CVE-4 的 setTitle/showToast 伪装)
用户被诱导确认支付
```
