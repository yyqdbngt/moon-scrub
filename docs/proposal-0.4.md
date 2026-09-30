# Moon Scrub 项目申报书（0.4.0）

## 一、项目名称与坐标

- 项目名称：Moon Scrub——面向日志、API 与 AI 工作流的敏感信息检测与脱敏引擎
- 仓库：https://github.com/yyqdbngt/moon-scrub（自 2565d01 起 70 个提交，单一作者）
- MoonCakes：`123123213weqw/moon_scrub@0.4.0`（latest）
- 许可证：Apache-2.0；纯 MoonBit，运行时零第三方依赖（仅 `moonbitlang/core`）

## 二、项目简介

开发者把日志发往排障平台、把报错贴给 AI 助手、把接口响应导出到测试环境时，会带上
访问令牌、密码、邮箱、身份证号、支付卡号。Moon Scrub 在这些文本离开进程之前做**离线、
确定性**的检测与脱敏：检测报告只含类别、置信度与 UTF-16 区间，从不携带命中原值。

0.1.0 之后项目经历了三个大版本演进：0.2.0 落地了可配置检测、误报抑制、JSON 文档
脱敏与流式分块扫描；0.3.0 新增十三个检测家族并把向量文件升级为经过差分验证的跨语言
契约；0.4.0 加入形态规则、高熵密钥检测与机器可读报告。当前规模：核心约 2,900 行
MoonBit、32 个测试文件、163 个测试块、67 条跨语言向量、19 种检测类别。

## 三、方向与应用场景

定位为开发者安全工具与数据治理基础组件，覆盖四个通用场景：

1. **日志与可观测性**：`redact_batch` 保持行数与顺序，输出按类别计数的安全摘要；
   `changed_indices` 标出变更行供路由与归档。
2. **AI 提示词保护**：粘贴报错与配置前本地清理，全程不联网；`explain_json` 产出
   可直接进报告管线的无值审计记录。
3. **API 与数据导出**：`redact_json` 解析后逐叶子脱敏（敏感路径 fail-closed），
   输出键序规范化的确定性 JSON；坏文档按纯文本降级并显式标记。
4. **流式管道**：`ChunkScanner` 支持跨块秘密（上下文余量 + 去重，性质测试对多种
   切分验证与整扫等价），适配日志尾随与 socket 读取。

## 四、核心能力（按 0.4.0 实测）

**检测家族**（19 类，默认集合见 README 矩阵）：

- 凭据：31 种服务前缀（GitHub/GitLab/Slack/AWS/Google/Stripe/Anthropic/OpenAI/
  SendGrid/Doppler/npm/Linear/Grafana/Checkout 等）、Bearer、Basic、JWT、私钥 PEM
  七种头、URL 内嵌凭据、22 个敏感键名的赋值（含 JSON 引号键）、Slack/Discord
  webhook、高熵密钥（opt-in，Shannon 熵 ≥4.75）。
- 标识：邮箱、IPv4/IPv6、Luhn+主流 BIN 卡号（含 Amex 4-6-5 分组）、GB 11643 身份证
  （校验和 + 生日双验证）、MAC、UUID、E.164 电话（opt-in）、SSH 公钥与证书块、
  钱包地址形态。

**可配置与误报抑制**：`ScanConfig` 按家族逐一切换；版本形态 IPv4、非 BIN 数字串、
文档域名（opt-in）三类抑制，均可关闭；调用方可注册 `TokenPrefixRule`（前缀+最小长度）、
`PatternRule`（前缀+字符类+长度窗口）与 `CustomRule`（精确值）三种规则，规则元数据
不进输出。

**API 面**（662+ 行接口快照，CI 门禁保证与代码同步）：扫描/脱敏的 policy 与 config
双入口、`redact_except` 白名单、`findings_summary`/`explain`/`explain_json` 三种
无值报告、`ChunkScanner`（push/push_lines/finish）、batch/fields/JSON 各自的 rules
与 config 变体、三种脱敏样式（全部幂等，含 PreserveLast4 的 marker 感知）。

## 五、工程验证

- **CI（四后端 × 全门禁）**：wasm/wasm-gc/js/native 各自执行 fmt 检查、静态检查、
  构建、测试；另有三道独立门禁——API 快照（`moon info`）同步、向量生成器同步、
  **Python 参考实现差分**（独立实现跑全部 67 条向量，两边不一致即失败）。
- **性质测试**：流式扫描对三个种子语料 × 六种切分粒度（细到单字符）与整扫逐
  finding 等价——该测试暴露并推动修复了两个深层缺陷（见下）。
- **性能**：确定性语料基准（批量/JSON/分家族三种模式 + 线性守门防二次方退化），
  native 实测约 0.84 MB/s、wasm-gc 约 1.9 MB/s（以 docs/performance.md 为准，
  CI 不设数字门槛）。
- **发布验证**：每个版本走 dry-run（解压复检）→ publish 200 → 独立消费模块
  `moon add` 下载并跑冒烟测试，证据存 docs/release-verification.md。

## 六、技术路线与边界

纯 MoonBit 单遍字符扫描 + 家族分派 + 互斥去重（排序后贪心），无正则引擎、无网络、
无全局状态。两个被性质测试逼出来的深层修复值得一书：`StringBuilder::to_string` 在
满容量时转移底层数组导致流式缓冲被掏空；滑动窗口切到未落定命中的起点会切断触发
上下文（`password=` 键名），使赋值类永远无法落定——修复为窗口保留 32 码元上下文
余量并对回退重显的命中去重。

明确不做：自然语言实体识别、密钥管理、网络请求、依赖求解、法规合规声明。检测存在
误报与漏报，高敏感场景应使用完全标记样式并组合 `verify_clean` 二次验证；流式检测
对超过 overlap 窗口的超长秘密可能切断。

## 七、原创性与生态价值

MoonBit 生态中未发现定位相同的通用包：同时提供多家族秘密检测、结构化 Finding
（不含原值）、幂等脱敏、JSON/流式管线、跨语言向量契约与差分门禁的组合。向量文件
（testvectors/vectors.json）配合 Python 参考实现，使任何语言的移植可以用同一份契约
验证——这是"跨语言"从口号变成 CI 里的一个失败条件。

## 八、演进记录

- 0.1.0（2026-09-28）：初版检测、三种样式、批量摘要。
- 0.2.0（2026-09-29）：可配置、抑制、JSON、流式、向量、基准。
- 0.3.0（2026-09-29）：13 个新家族、报告 API、流式修复、差分门禁，累计 50+ 提交。
- 0.4.0（2026-09-30）：形态规则、高熵检测、新前缀、JSON 报告。

后续候选（未承诺）：高熵阈值调优、规则优先级、PEM 口令行、更多语言参考实现。

