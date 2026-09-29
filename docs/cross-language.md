# 跨语言移植指南

`testvectors/vectors.json` 是行为契约：任何语言的 moon-scrub 移植读同一份文件、断言同一组
(kind, start, end, confidence) 元组。仓库里的 Python 参考实现证明了这条路可行。

## 向量格式

```json
{
  "name": "github-classic-pat",
  "mode": "secrets",
  "input": "token=ghp_1234567890abcdefghij",
  "expect": [
    { "kind": "ACCESS_TOKEN", "literal": "ghp_1234567890abcdefghij", "confidence": "HIGH" }
  ]
}
```

- `literal` 是期望命中的原文片段；`start`/`end` 由 `input.find(literal)` 解析，UTF-16
  码元、半开区间。移植实现应同样由 literal 解析偏移，避免手数下标。
- `mode` 决定启用哪些家族：
  - `secrets`：仅凭据类（访问令牌、Bearer、JWT、私钥、URL 凭据、赋值、Basic）。
  - `standard`：冻结的 0.1.0 策略面——凭据类 + 邮箱、IPv4、卡号。
  - `config`：`ScanConfig::standard()` 全家族（追加身份证、MAC、UUID、IPv6、公钥、
    证书、钱包、webhook；电话默认关闭）。
  - `phone`：`config` 基础上再开电话。

## 断言规则

1. 对每个向量运行对应模式的全部检测器，收集命中。
2. 命中按 `(start, -end)` 排序后做互斥去重（保留先出现的），结果应与 `expect` 完全相等
   ——种类、顺序、区间、置信度逐项一致。
3. 期望为空的向量（抑制样本）是契约的一部分：误报抑制不是可选项。

## 参考实现

`scripts/reference_scan.py`（约 400 行，仅标准库）实现了全部 58 条向量覆盖的检测行为，
本地运行：

```sh
python3 scripts/reference_scan.py
```

CI 的 vectors job 在每次推送时执行同一脚本，作为 MoonBit 与 Python 之间的差分门禁。
新语言的移植建议：先让参考实现里同款检测逻辑跑通全部向量，再接入自己的流水线。

## 添加向量

1. 在 `testvectors/vectors.json` 追加条目（literal 必须在 input 中恰好出现一次）。
2. 运行 `python3 scripts/gen_vectors.py` 重新生成 MoonBit 断言并一并提交（CI 会校验同步）。
3. 更新 `scripts/reference_scan.py` 使 Python 侧同样通过——两边的实现差分通过才算完成。
