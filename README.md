# Moon Scrub

纯 MoonBit 的离线敏感信息检测与脱敏引擎，面向日志、API 响应、数据导出和 AI 提示词
预处理。检测结果只保存类别、置信度和 UTF-16 区间，不把命中的秘密复制到报告中。

## 已实现能力

- 识别常见访问令牌前缀、Bearer token、JWT 和 password/token/secret/api_key 等赋值。
- 识别邮箱、IPv4，以及通过 Luhn 校验的 13–19 位支付卡号候选。
- `secrets_only` 与 `standard` 两种策略。
- 常量、带类型和保留末四位三种脱敏方式。
- 自动合并重叠命中，避免同一秘密被重复替换。
- 识别私钥块和 URL 中的用户名/密码凭据。
- 支持调用方提供精确秘密规则，规则值和标签不会进入 Finding 或输出标记。
- 支持已解析的结构化字段；password/token 等敏感路径即使值形状未知也会整体脱敏。
- 脱敏结果可重复处理；`verify_clean` 可执行二次扫描。
- 批量日志处理保持输入行数，并返回不含原值的分类统计。
- 10,000 行确定性批量测试。

## 使用

```moonbit nocheck
///|
fn main {
  let result = @scrub.redact(
    "user=demo@example.com password=hunter2 from 10.0.0.8",
  )
  println(result.text)
  // user=[REDACTED:EMAIL] password=[REDACTED:CREDENTIAL] from [REDACTED:IPV4]
}
```

```text
import {
  "yyqdbngt/moon_scrub" @scrub,
}
```

运行场景：

```sh
moon test --target js
moon run examples/log-pipeline --target js
```

## 安全边界

这是确定性的结构化检测工具，不是完整 DLP、NLP 实体识别器或合规认证产品。它可能出现
误报，也无法识别所有秘密。默认报告不含命中值，但调用方仍负责保护原始输入和脱敏后的
输出。`PreserveLast4` 会保留四个字符，不适合要求完全删除的场景；这类场景应使用
`Marker` 或 `Typed`。库不联网、不保存输入、不管理密钥，也不声称满足 PCI、GDPR 等法规。

## 工程验证

CI 在 wasm、wasm-gc、js、native 四后端执行格式检查、静态检查、构建、测试和实际日志
流水线示例。当前核心实现约 840 行 MoonBit，测试约 200 行、18 个测试块；示例与文档
不计入统计。Apache-2.0。

完整边界见 [安全模型](docs/security-model.md)，非正式申报参考稿见
[proposal.md](docs/proposal.md)。
