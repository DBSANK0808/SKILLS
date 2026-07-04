---
name: yakit-hot-reload
description: 生成 Yakit 热加载代码（YakLang）。当用户需要编写 Yakit MITM 或 WebFuzzer 热加载脚本时启用此 skill，涵盖请求/响应加解密、签名/时间戳生成、请求响应内容替换、越权测试、流量过滤等场景。当用户提到 yakit、热加载、hijackHTTPRequest、hijackResponse、beforeRequest、afterRequest、YakLang 等关键词时触发。
---

# Yakit 热加载代码生成

## 触发条件

当用户提出以下类型的需求时启用本 skill：
- 加解密：对请求体/响应体进行加密或解密（AES、SM4、DES 等）
- 签名/时间戳：动态计算签名、生成时间戳并注入请求
- 替换内容：自动替换请求或响应中的参数、Header、Body
- 越权测试：修改 uid/role 等参数进行越权检测
- 流量过滤：按规则丢弃/拦截某些请求，过滤静态资源
- 注入 Payload：给全站请求统一注入测试载荷
- 响应处理：解密响应体、注入脚本、屏蔽拦截 JS
- 其他需要在对 yakit 代理流量或 WebFuzzer 请求做实时处理的场景

## 执行流程

**第一步：理解知识** — 仔细阅读下方「核心知识」全部内容，理解各函数签名、使用场景及 YakLang 语法。
**第二步：分析需求** — 明确用户需求属于 MITM 场景还是 WebFuzzer 场景，选择正确的函数。
**第三步：输出代码** — 基于知识生成可直接粘贴到 Yakit 热加载编辑器中运行的完整代码。

---

## 核心知识

### 场景说明

Yakit 热加载代码在两个场景中使用：
- **MITM**（类似 Burp History）：热加载代码自动对代理到 Yakit 的流量做处理。
- **WebFuzzer**（类似 Burp Repeater）：热加载代码在手动发送请求包前对请求包进行处理。

### MITM 热加载函数

MITM 提供三个常用函数：

#### hijackHTTPRequest — 修改请求包

对流量中请求包的自动修改。常用于：自动改 Header、替换参数、越权测试（改 uid/role）、给全站请求统一注入 payload、按规则丢弃/拦截某些请求。

```go
hijackHTTPRequest = func(isHttps, url, req, forward /*func(modifiedRequest []byte)*/, drop /*func()*/) {
    // 对经过 MITM 的请求做实时处理
    if str.Contains(string(req), "/admin") {
        modified = str.ReplaceAll(string(req), "role=user", "role=admin")
        forward(poc.FixHTTPRequest(modified))  // 放行修改后的请求
    }
    // drop() 可直接丢弃该请求
}
```

#### hijackResponse — 修改响应包

自动修改返回包内容。常用于：前端越权绕过、解密响应体、给页面注入调试脚本、屏蔽拦截 JS。

```go
hijackResponse = func(isHttps, url, rsp, forward, drop) {
    modified = str.ReplaceAll(string(rsp), "\"isVip\":false", "\"isVip\":true")
    forward(poc.FixHTTPResponse(modified))
}
```

#### hijackSaveHTTPFlow — 入库前处理

对请求响应体进行解密、对命中敏感接口的流量标色、过滤掉静态资源等噪声不入库、给流量加自定义备注。

```go
hijackSaveHTTPFlow = func(flow, modify, drop) {
    rsp = str.Unquote(flow.Response)~
    // 调用解密函数
    rsp = decrypt(rsp)
    flow.Response = str.Quote(rsp)
    modify(flow)
}
```

### WebFuzzer 热加载函数

WebFuzzer 提供两个常用函数：

#### beforeRequest — 发送前处理请求

发送前统一处理每一发请求。常用于：自动加密请求体、动态计算签名/时间戳、自动补全会跟随变化的 token、对 payload 做编码或加密、给爆破的每个请求换 UA/代理特征。**这是解决目标有签名校验导致请求全部失效的核心手段。**

```go
beforeRequest = func(https /*bool*/, originReq /*[]byte*/, req /*[]byte*/) {
    // 对 WebFuzzer 即将发出的每个请求做加工，返回新的请求字节
    return poc.FixHTTPRequest(str.ReplaceAll(string(req), "OLD", "NEW"))
}
```

#### afterRequest — 处理响应

自定义对响应包的处理。常用于：对返回的响应体进行解密、从响应里抽出下一次请求需要的字段、规范化响应方便后续判断。

```go
afterRequest = func(https, originReq, req, originRsp, rsp) {
    // 对每个响应做加工，返回新的响应字节
    return rsp
}
```

---

## YakLang 常用语法

### HTTP 请求处理

```go
// raw 格式发送请求
reqStr = `GET /api/user?id=1 HTTP/1.1
Host: example.com
User-Agent: yak

`
rsp, req, err = poc.HTTP(reqStr, poc.https(true), poc.timeout(10))
if err != nil {
    die(err)
}
println(string(rsp))

// url 方式发送请求
rsp, req, err = poc.Get("https://example.com/api/user",
    poc.header("Authorization", "Bearer xxx"),
    poc.param("id", "1"),
)

// POST JSON
rsp, req, err = poc.Post("https://example.com/api/login",
    poc.jsonBody({"username": "admin", "password": "123456"}),
)
```

常用 poc 选项：

```go
poc.https(true)                          // 走 HTTPS
poc.timeout(15)                          // 超时秒数
poc.proxy("http://127.0.0.1:8080")       // 走代理
poc.header(k, v) / poc.replaceHeader(k, v)  // 设置/替换请求头
poc.redirectHandler(...)                 // 控制重定向
poc.json(He_data)                        // JSON 格式 Body
```

### HTTP 请求/响应包操作（poc 模块）

```go
// 从请求中提取信息
body = poc.GetHTTPPacketBody(req)                          // 获取 Body
url = poc.GetUrlFromHTTPRequest("https", req)              // 获取完整 URL
headerValue = poc.GetHTTPPacketHeader(rsp, "Content-Type") // 获取指定 Header
statusCode = poc.GetStatusCodeFromResponse(rsp)            // 获取状态码

// 修改请求包
req = poc.ReplaceHTTPPacketBody(req, newBody)              // 替换 Body
req = poc.ReplaceHTTPPacketHeader(req, "Key", "Value")     // 替换 Header

// 修复请求/响应格式
poc.FixHTTPRequest(modifiedStr)
poc.FixHTTPResponse(modifiedStr)
```

### 字符串处理（str 模块）

```go
str.Contains(s, "Yak")           // 包含判断
str.HasPrefix(s, "Hello")        // 前缀判断
str.ToUpper(s)                   // 转大写
str.Split(s, ", ")               // 分割
str.Replace(s, "o", "0", -1)     // 替换（-1 为全部）
str.ReplaceAll(s, "old", "new")  // 全部替换
str.TrimSpace("  abc  ")         // 去首尾空格
str.Join(["a", "b", "c"], "-")   // 拼接
str.Quote(s)                     // 加引号转义
str.Unquote(s)                   // 去引号反转义（常配合 ~ 使用）
```

### 正则处理（re 模块）

```go
results = re.FindAll(`token="(.*?)"`, string(body))  // 提取所有匹配
token = re.FindGroup(`token="(.*?)"`, string(body))  // 提取分组
if re.Match(`\d{11}`, s) { ... }                     // 判断是否匹配
```

### JSON 处理（json 模块）

```go
// 反序列化
data = json.loads(body)
println(data["username"])
println(data["roles"][0])

// 序列化
payload = {"name": "admin", "tags": ["a", "b"], "active": true}
jsonStr = json.dumps(payload)

// 有序 map（保持键顺序）
encBody = omap({"hmb": encdata})
json.dumps(encBody)
```

### 编解码（codec 模块）

```go
// Hex 编解码
codec.EncodeToHex(data)~         // 编码为 Hex 字符串
codec.DecodeHex(hexStr)~         // 从 Hex 字符串解码

// SM4 加解密（CBC 模式）
codec.Sm4Encrypt(key, plaintext, iv)~        // 加密
codec.Sm4CBCDecrypt(key, ciphertext, iv)~    // 解密
```

### 错误处理

```go
// YakLang 中 ~ 后缀表示「失败时 panic」
// 也可用 err 返回值方式
result = codec.DecodeHex(hexStr)~  // 失败时自动 panic

// 或显式处理
result, err = codec.DecodeHex(hexStr)
if err != nil {
    die(err)
}
```

### 其他常用

```go
sleep(2)                    // 延时（秒）
sprintf("Bearer %s", token) // 格式化字符串
printf("用户: %s\n", name)  // 格式化打印
die(err)                     // 抛出错误终止
```

---

## 完整示例

### 示例 1：MITM 中自动对请求体进行 SM4 解密

```go
key = codec.DecodeHex("11111111111111111111111111111111")~
iv = codec.DecodeHex("11111111111111111111111111111111")~

decfunc = func(req){
    // 先拿到请求中的 body 部分
    body = poc.GetHTTPPacketBody(req)
    // 拿到 hmb 键对应的加密后的请求体
    encdata = json.loads(body)['hmb']
    // 表示如果请求体的格式是 {"hmb":"xxx"} 的形式则进入该 if
    if(encdata){
        // 先进行 16 进制解码
        encdata = codec.DecodeHex(encdata)~
        // 使用 sm4 对数据进行解密
        decdata = codec.Sm4CBCDecrypt(key, encdata, iv)~
        // 将加密的请求体替换为解密后的数据
        req = poc.ReplaceHTTPPacketBody(req, decdata)
    }
    // 将请求返回
    return req
}

hijackSaveHTTPFlow = func(flow, modify, drop){
    req = str.Unquote(flow.Request)~
    req = decfunc(req)
    flow.Request = str.Quote(req)
    modify(flow)
}
```

### 示例 2：WebFuzzer 中自动对请求体进行 SM4 加密

```go
beforeRequest = func(req) {
    key = codec.DecodeHex("11111111111111111111111111111111")~
    iv = codec.DecodeHex("11111111111111111111111111111111")~

    // 加密请求体
    body = poc.GetHTTPPacketBody(req)
    body = str.ReplaceAll(body, "\n", "")
    body = str.ReplaceAll(body, " ", "")
    encdata = codec.EncodeToHex(codec.Sm4Encrypt(key, body, iv)~)~
    encBody = omap({"hmb": encdata})
    req = poc.ReplaceHTTPPacketBody(req, json.dumps(encBody))

    return req
}
```

### 示例 3：WebFuzzer 中加密请求体 + 通过 JSRPC 调用获取签名 Header

```go
He_e = 'xxx'
He_t = 'xxx'
He_n = 'xxx'
Ge_t = 'xxx'

beforeRequest = func(req) {
    key = codec.DecodeHex("11111111111111111111111111111111")~
    iv = codec.DecodeHex("11111111111111111111111111111111")~

    // 加密请求体
    body = poc.GetHTTPPacketBody(req)
    body = str.ReplaceAll(body, "\n", "")
    body = str.ReplaceAll(body, " ", "")
    encdata = codec.EncodeToHex(codec.Sm4Encrypt(key, body, iv)~)~
    encBody = omap({"hmb": encdata})
    req = poc.ReplaceHTTPPacketBody(req, json.dumps(encBody))

    // 替换 He_t 中的 url 和 data
    He_t = json.loads(He_t)
    He_t['url'] = poc.GetUrlFromHTTPRequest("https", req)
    He_t['data'] = json.loads(poc.GetHTTPPacketBody(req))
    He_t = json.dumps(He_t)

    // JSRPC 调用 He 函数的参数
    url = "http://127.0.0.1:5612/business-demo/invoke"
    He_data = {
        "group": "test",
        "action": "He",
        "He_e": He_e,
        "He_t": He_t,
        "He_n": He_n
    }

    // 调用 JSRPC 接口获取签名 Header
    He_rsp, He_req = poc.Post(url, poc.json(He_data), poc.proxy("http://127.0.0.1:8080"))~
    hmb_k = json.loads(He_rsp.GetBody())['HMB-AM-HEADER-K']
    hmb_i = json.loads(He_rsp.GetBody())['HMB-AM-HEADER-I']
    lock_header = json.loads(He_rsp.GetBody())['LOCK_HEADER']

    // 替换原始请求头中的签名 Header
    req = poc.ReplaceHTTPPacketHeader(req, "HMB-AM-HEADER-K", hmb_k)
    req = poc.ReplaceHTTPPacketHeader(req, "HMB-AM-HEADER-I", hmb_i)
    req = poc.ReplaceHTTPPacketHeader(req, "LOCK_HEADER", lock_header)

    // 替换 Ge_t 中的参数并调用 Ge 函数获取最终签名
    Ge_t = json.loads(Ge_t)
    Ge_t['headers']['LOCK_HEADER'] = lock_header
    Ge_t['headers']['HMB-AM-HEADER-K'] = hmb_k
    Ge_t['headers']['HMB-AM-HEADER-I'] = hmb_i
    Ge_t['url'] = poc.GetUrlFromHTTPRequest("https", req)
    Ge_t['data'] = encBody
    Ge_t = json.dumps(Ge_t)

    Ge_data = {
        "group": "test",
        "action": "Ge",
        "Ge_t": Ge_t
    }

    sleep(2)
    Ge_rsp, Ge_req = poc.Post(url, poc.json(Ge_data), poc.proxy("http://127.0.0.1:8080"))~
    hmb_d = json.loads(Ge_rsp.GetBody())['headers']['HMB-AM-HEADER-D']

    // 替换请求头中的最终签名
    req = poc.ReplaceHTTPPacketHeader(req, "HMB-AM-HEADER-D", hmb_d)

    return req
}
```

---

## 代码生成规范

1. **函数选择**：根据场景选择正确的函数
   - MITM 修改请求 → `hijackHTTPRequest`
   - MITM 修改响应 → `hijackResponse`
   - MITM 入库前处理（解密/标色/过滤） → `hijackSaveHTTPFlow`
   - WebFuzzer 发送前处理（加密/签名/替换） → `beforeRequest`
   - WebFuzzer 响应处理（解密/提取） → `afterRequest`

2. **代码质量**：
   - 使用 `poc.FixHTTPRequest()` / `poc.FixHTTPResponse()` 确保修改后的报文格式正确
   - 使用 `~` 后缀或 `err` 返回值处理可能失败的操作（如编解码、加解密）
   - 在 `hijackSaveHTTPFlow` 中使用 `str.Unquote()` / `str.Quote()` 处理 flow 中的请求/响应数据
   - 需要保持 JSON 键顺序时使用 `omap()` 而非普通 map

3. **输出格式**：直接输出完整的、可直接粘贴到 Yakit 热加载编辑器中运行的代码，使用 ```go 代码块包裹

4. **变量与常量**：密钥、IV 等固定值定义在函数外部作为全局变量；用户需要替换的值用注释标明

5. **场景适配**：如果用户未明确说明使用 MITM 还是 WebFuzzer，根据需求推断——需要对代理流量做自动化处理用 MITM，需要在 WebFuzzer 中对单个请求做加工用 WebFuzzer
