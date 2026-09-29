# Moon Scrub

纯 MoonBit 的离线敏感信息检测与脱敏引擎，面向日志、API 响应、数据导出和 AI 提示词
预处理。检测结果只保存类别、置信度和 UTF-16 区间，不把命中的秘密复制到报告中。

## 已实现能力

- 识别常见访问令牌前缀（GitHub ghp_/gho_/ghu_/ghs_/ghr_/gha_/github_pat_、GitLab
  glpat-、Slack xoxb-/xoxp-/xoxc-/xoxa-/xoxr-、AWS AKIA/ASIA、Google AIza、Stripe
  sk_live_/rk_live_/pk_live_、Anthropic sk-ant-、OpenAI 风格 sk-、SendGrid SG.、
  Doppler dop_v1_/dop_v2_、npm npm_ 等）、Bearer token、JWT 和
  password/token/secret/api_key 等赋值。
- 识别邮箱、IPv4，以及通过 Luhn 校验且命中主流卡组织 BIN 前缀的 13–19 位支付卡号。
- `secrets_only` 与 `standard` 两种策略，以及按检测家族逐一开关的 `ScanConfig`。
- 调用方可注册额外令牌前缀规则（`TokenPrefixRule`）与精确秘密规则
  （`CustomRule`），规则值和标签不会进入 Finding 或输出标记。
- 误报抑制：`v1.2.3.4` 等版本形态的 IPv4 不再上报，Luhn 有效但非卡组织前缀的长数字
  串按订单号处理；两类抑制都可以关闭。
- 常量、带类型和保留末四位三种脱敏方式，全部满足重复处理幂等。
- 识别私钥块和 URL 中的用户名/密码凭据。
- 支持已解析的结构化字段；password/token 等敏感路径即使值形状未知也会整体脱敏。
- JSON 文档适配：`redact_json` 解析后逐叶子扫描，敏感路径 fail-closed，输出为键序
  确定的紧凑 JSON；非法输入回退为纯文本扫描。
- 流式分块扫描：`ChunkScanner` 按块喂入，findings 带全流绝对偏移，跨块秘密依赖
  overlap 窗口保证不漏。
- 跨语言测试向量：`testvectors/vectors.json` 是行为规范源，任何语言移植都断言同一组
  kind/start/end/confidence。
- 性能基准：确定性语料的吞吐与单行成本报告，以及防二次方退化的线性守门。
- 脱敏结果可重复处理；`verify_clean` 可执行二次扫描。
- 批量日志处理保持输入行数，并返回不含原值的分类统计。
- 10,000 行确定性批量测试。

## 使用

MoonCakes 已发布并通过独立消费项目验证：

```sh
moon add yyqdbngt/moon_scrub
```

```moonbit nocheck
///|
fn main {
  let result = @scrub.redact(
    "user=demo@example.com password=hunter2 from 10.0.0.8",
  )
  println(result.text)
  // user=[REDACTED:EMAIL] password=[REDACTED:CREDENTIAL] from [REDACTED:IPV4]

  // 全量配置：家族开关 + 自定义前缀规则
  let config = {
    ..@scrub.ScanConfig::secrets_only(),
    extra_prefixes: [@scrub.TokenPrefixRule::{ prefix: "corp_", min_length: 16 }],
  }
  println(@scrub.scan_with_config("corp_abcdefgh1234", config).length())
  // 1

  // JSON 文档脱敏（键序规范化、fail-closed）
  let doc = @scrub.redact_json("{\"password\": \"hunter2\", \"n\": 42}")
  println(doc.text)
  // {"n":42,"password":"[REDACTED:CREDENTIAL]"}

  // 流式分块扫描
  let scanner = @scrub.ChunkScanner::new()
  ignore(scanner.push("token=ghp_1234567890abcdefghij\n"))
  println(scanner.finish().length())
  // 1
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
moon run examples/bench --target native   # 吞吐与线性守门报告
```

## 安全边界

这是确定性的结构化检测工具，不是完整 DLP、NLP 实体识别器或合规认证产品。它可能出现
误报，也无法识别所有秘密。默认报告不含命中值，但调用方仍负责保护原始输入和脱敏后的
输出。`PreserveLast4` 会保留四个字符，不适合要求完全删除的场景；这类场景应使用
`Marker` 或 `Typed`。流式扫描的 `overlap` 必须不小于最长预期秘密的完整跨度，更长的
秘密可能被切断漏检。JSON 输出对数字做 Double 规范化，超出安全整数范围的大数可能失
真。库不联网、不保存输入、不管理密钥，也不声称满足 PCI、GDPR 等法规。

## 工程验证

CI 在 wasm、wasm-gc、js、native 四后端执行格式检查、静态检查、构建、测试、日志流水
线示例与性能基准；另有独立步骤校验跨语言向量文件与生成的 MoonBit 断言保持同步。当
前核心实现约 1,900 行 MoonBit，10 个测试文件、106 个测试块；示例与文档不计入统计。
Apache-2.0。

完整边界见 [安全模型](docs/security-model.md)，非正式申报参考稿见
[proposal.md](docs/proposal.md)，发布证据见
[release-verification.md](docs/release-verification.md)。
