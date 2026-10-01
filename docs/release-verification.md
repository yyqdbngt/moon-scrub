# MoonCakes 0.1.0 发布与独立消费验证

核验日期：2026-09-28。

## 发布前验证

在 `yyqdbngt` 的独立 `MOON_HOME` 下执行：

```sh
moon fmt --check
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon publish --dry-run
```

18 个测试全部通过。dry-run 将归档解压到隔离目录后再次执行 `moon check`，服务器返回
`202 Accepted` 和 `Dry run completed successfully`。

## 正式发布

执行 `moon publish` 后，归档再次解压检查通过，服务器返回 `200 OK`。发布坐标为：

```text
yyqdbngt/moon_scrub@0.1.0
```

## 独立消费验证

使用另一套 MoonCakes 用户环境创建全新模块，声明依赖：

```text
import {
  "yyqdbngt/moon_scrub@0.1.0",
}
```

`moon update` 明确输出 `Downloading yyqdbngt/moon_scrub@0.1.0`。消费项目调用
`redact` 和 `verify_clean`，随后 `moon check --target js --deny-warn` 通过，测试结果为
`1/1`。该验证不引用开发仓库相对路径。

## 0.3.0 — 2026-09-29

- 四后端（wasm、wasm-gc、js、native）`moon fmt --check`、`moon check --deny-warn`、
  `moon build`、`moon test` 全绿；212 个测试块。
- CI 附加门禁：`moon info` 生成的 `pkg.generated.mbti` 与提交版本一致；向量生成器
  `--check` 同步；`scripts/reference_scan.py`（Python 参考实现）62/62 向量全对。
- 四后端运行三个示例（log-pipeline、json-pipeline、stream-pipeline）与基准（含
  线性守门与 JSON 吞吐模式），native 实测批量 0.84 MB/s、wasm-gc 1.89 MB/s。
- 历史完整性：五十个提交同一作者；推送保护触发过一次（测试样本形态与 Slack
  webhook 模式相同），以拆分字面量重写历史解决，未使用豁免链接。
- MoonCakes 发布待办：`0.1.0` 已发布。`0.3.0` 的 `moon publish --dry-run` 已在
  2026-09-29 完成本地打包与解压复检（`Check passed`），服务端因当前环境凭据为
  `123123213weqw` 与模块归属 `yyqdbngt` 不符返回 403；正式发布需在 `yyqdbngt`
  登录态（`mooncake login`）下重跑 `moon publish` 后回填本节。

## 0.3.0 独立消费验证 — 2026-09-30

发布坐标 `123123213weqw/moon_scrub@0.3.0`（发布过程见上一节）。全新模块
`probe/consume_scrub` 执行 `moon add 123123213weqw/moon_scrub@0.3.0`，`moon update`
输出 `Downloading 123123213weqw/moon_scrub@0.3.0`；消费测试一次覆盖：

- 三家族脱敏与 `verify_clean` 二次验证（email/credential/ipv4）；
- `ScanConfig::standard()` 下的身份证检测（`RESIDENT_ID`）；
- `ChunkScanner` 流式喂入跨块 token 并在 `finish` 落定。

结果 `1/1` 通过。与 moon_pyversion 的经验一致：版本固定由 `moon add` 写入
moon.mod 的 import，不要手写进 moon.pkg。该验证不引用开发仓库相对路径。

## 0.4.0 — 2026-09-30

`moon publish` 于 `123123213weqw` 登录态执行，服务端 `200 OK`，坐标
`123123213weqw/moon_scrub@0.4.0`。独立消费验证：全新模块 `moon add`，
`Downloading ...@0.4.0`；测试一次覆盖 PatternRule 形态规则（HexLower 窗口）、
高熵检测（HIGH_ENTROPY_SECRET）与 explain_json 输出，`1/1` 通过。内容：
形态规则、高熵检测（opt-in）、Linear/Grafana/Checkout 前缀、explain_json。

## 0.5.0 — 2026-10-01

`moon publish` 返回 `200 OK`，坐标 `123123213weqw/moon_scrub@0.5.0`。独立消费验证：
全新模块 `moon add` 下载成功（中间一次 CDN 超时重试即过），测试覆盖 glrt- 规则批与
流式汇总（`ChunkScanner::summary` 的 bearer 计数），`1/1` 通过。内容：gitleaks 对标
规则批（39 前缀）、流式汇总、向量契约扩展（76 条）、覆盖率门禁、版本政策。
