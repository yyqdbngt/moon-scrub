# 版本政策

## 承诺

- 遵循语义化版本（SemVer）：MAJOR 破坏兼容、MINOR 向后兼容新增、PATCH 修复。
- `0.x` 阶段按同样精神执行：MINOR 递增可含破坏，但**必须**在 CHANGELOG 逐条列出迁移
  说明——本项目至今未引入需要迁移的破坏。
- 公开面以 `pkg.generated.mbti` 为准并由 CI 比对：任何改变公开面的提交都会体现在该
  文件的 diff 里，无例外。

## 兼容性细则

- **新增 `SensitiveKind` 枚举变体视为 MINOR**。调用方若对 `kind` 做穷尽匹配，新增
  变体需要补分支——这是有意的设计权衡（检测家族扩张是本库的主要演进方向），每次
  新增都在 CHANGELOG 显式列出。
- `ScanPolicy`（0.1.0 三字段小面）**永久冻结**：新检测家族只进 `ScanConfig`，旧入口
  行为不变。`to_config` 桥接保证两者并行。
- `BatchSummary` 新增计数字段视为 MINOR；字段构造请使用 struct update 语法以避免
  依赖完整字段清单。
- 输出格式承诺：`[REDACTED:<KIND>]`、`[REDACTED]`、`[REDACTED:<KIND>:*xxxx]` 三种
  标记的字面形态在 MAJOR 之前不变；JSON 输出的键序（字典序）与整数拼写不变。

## 发布流程

每次发布：四后端全绿 → `moon publish --dry-run` 解压复检 → `moon publish` → 独立
消费模块 `moon add` + 冒烟测试 → `docs/release-verification.md` 回填证据 → 打
`vX.Y.Z` 标签。
