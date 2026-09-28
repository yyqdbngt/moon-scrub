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
