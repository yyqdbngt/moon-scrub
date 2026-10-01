# Moon Scrub 配方手册

十个常见场景的即拷即用配方。核心 API 的文档示例由 `moon test` 执行（```mbt check```
机制），永不腐烂。

## 1. 出口最后一道闸：日志落盘前脱敏

```moonbit
let safe = redact_batch(lines).lines   // 行数、顺序不变
```

## 2. 发送前自检：不干净就拒发

```moonbit
if !verify_clean(text, policy=ScanPolicy::standard()) {
  abort("refuse to ship")              // 类别统计可另行记录
}
```

## 3. 只拦凭据、放过业务标识

```moonbit
let config = ScanConfig::secrets_only()
```

## 4. 已知安全的值不脱敏（如负载均衡 IP）

```moonbit
redact_except("lb 10.0.0.1 db 10.0.0.2", ["10.0.0.1"])
```

## 5. 私有令牌形态：前缀+字符类+长度窗口

```moonbit
let config = {
  ..ScanConfig::secrets_only(),
  extra_patterns: [
    PatternRule::{ prefix: "txn_", chars: HexLower, min_length: 20, max_length: 24 },
  ],
}
```

## 6. API 响应整体处理

```moonbit
let doc = redact_json(payload)   // 敏感路径 fail-closed；坏文档降级为纯文本扫描
if !doc.parsed { /* 降级信号：按失败处理 */ }
```

## 7. 流式日志：尾随与 socket

```moonbit
let scanner = ChunkScanner::new(overlap=8192)   // ≥ 最长预期秘密
for finding in scanner.push(chunk) { /* 绝对偏移 */ }
let tail = scanner.finish()
```

## 8. 审计报告（人类可读 / 机器可读）

```moonbit
explain(text)        // 每行一条 "KIND start-end CONFIDENCE"
explain_json(text)   // JSON 数组，键序确定
```

## 9. 分类计数（不产出脱敏文本）

```moonbit
findings_summary(text)   // 按类名排序的 kind/count 行
```

## 10. 测试套件日志降噪

```moonbit
let config = {
  ..ScanConfig::standard(),
  suppress_example_domains: true,   // example.com/net/org 不再刷屏
}
```

## 幂等性承诺

三种脱敏样式重复应用结果不变（marker 感知），详见[安全模型](security-model.md)。
