# PLAN：支持多种游戏

- 日期：2026-10-06
- 状态：计划（待实现）
- 目标：将当前 Dark Souls III 专用工具扩展为可由用户配置多款游戏的通用工具 **cheat-tool**；共享扫描/锁定能力，并按游戏隔离进程、指针链和持久化状态。

---

## 1. 背景与现状

当前工具是单文件 C 程序，核心实现集中在 `ds3hp.c`。扫描、候选筛选、内存读写和 TUI 流程大体可复用，但游戏身份目前写死在代码中：

- `detect_pid()` / `pid_ok()` 按 `/proc/<pid>/comm` 的 `DarkSoulsIII` 前缀识别进程。
- 指针链 CLI 和 TUI 默认使用 `DarkSoulsIII.exe` 模块；部分错误与状态提示也直接写了 DS3 名称。
- `.ds3hp_state` 是当前目录下的二进制扫描状态，没有游戏身份；切游戏可能误用此前游戏的候选地址。
- `~/.config/ds3hp/watches.json`（遵循 `XDG_CONFIG_HOME`）将所有 Watch 按名称存放，没有游戏命名空间；不同游戏的同名 Watch 会冲突，链也可能被错误解析。
- `Makefile` 只有构建/清理目标，仓库没有可复现的测试套件。
- 命令名、配置根目录、二进制名称都带有 DS3 历史命名。

本计划将游戏 profile 改为用户可扩展配置，而非只靠重新编译添加游戏；同时处理应用更名及持久化格式的兼容边界。

## 2. 已确认的决策

以下为用户已确定的要求，实施时按此执行，不再作为开放问题：

1. **默认游戏**：未指定 `--game` 时使用 `darksouls3`。
2. **用户扩展 profile**：允许用户在 `cheat-tool.json` 中定义游戏配置；内置 DS3 profile 仍作为默认项。采用建议的 schema：必需字段严格校验、仅有限默认值、未知字段拒绝，且首版默认保持当前 DS3 的进程名前缀匹配行为。
3. **Watch 隔离**：各 profile 使用独立的 Watch 文件，文件名由 profile ID 派生；禁止不同游戏的同名 Watch 或链数据互相覆盖。
4. **扫描状态**：新状态格式必须包含 profile ID，状态文件按 profile 使用独立文件名。旧格式不迁移，视为过期/不兼容并提示用户重新运行 `first`。
5. **工具更名**：对外工具及可执行文件名称直接更名为 `cheat-tool`，不保留 `ds3hp` 兼容别名，也不以脚本兼容为约束。
6. **TUI 游戏切换**：不支持运行中切换；退出后以 `--game <id>` 重新启动 TUI。
7. **进程选择**：未指定 `--pid` 时，附加到所选 profile 下找到的第一个匹配游戏进程；若显式给出 `--pid`，按所选 profile 校验该 PID。
8. **旧 Watch 数据**：旧配置只视为 DS3 数据；仅在新 DS3 Watch 文件不存在时自动迁移，成功后保留旧文件作为备份。目标已存在则不覆盖，提示用户手动处理。
9. **PID 匹配**：首版保持 DS3 当前 `/proc/<pid>/comm` 前缀匹配行为；profile schema 不支持多规则匹配。
10. **配置文件行为**：配置文件不存在时使用内置 DS3；文件存在但无效时明确报错，不静默忽略或回退。

## 3. Profile 与配置文件

采用轻量的 profile 数据模型，不引入插件/动态加载系统。profile 至少包含：

```json
{
  "games": {
    "darksouls3": {
      "display_name": "Dark Souls III",
      "process_name": "DarkSoulsIII",
      "module_name": "DarkSoulsIII.exe",
      "default_type": "float",
      "default_min": 1,
      "default_max": 10000,
      "default_maps": "anon"
    }
  }
}
```

以上字段为严格 schema 示例：必需字段均须存在且类型正确；未知字段拒绝；profile ID 必须符合安全字符集且不能包含路径分隔符。数值范围、`default_type`、`default_maps` 均须校验。进程名采用前缀匹配以保持 DS3 当前行为。自定义配置可以定义/覆盖 profile，但不能注入代码或可执行表达式；保留 `darksouls3` 作为内置 fallback，仅当配置文件完全不存在时使用。

配置路径为 `$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json`，未设置 `XDG_CONFIG_HOME` 时为 `~/.config/cheat-tool/cheat-tool.json`。缺少配置文件时不强制生成模板；如提供示例，应由 README 展示。profile ID 用作 `--game` 参数及 per-profile 状态/Watch 文件名的一部分。

## 4. 游戏选择与进程行为

CLI 增加全局 `--game <id>`，在命令分发前解析，使 `pid`、`first/next/...`、`chain` 以及 `tui` 使用同一个选择。未提供时等同 `--game darksouls3`。未知 ID 在访问进程或状态文件前明确报错。

TUI 标题显示当前游戏。自动重连、手动 `p` 重新检测和启动时链自动绑定始终沿用启动时 profile；运行期间不切换游戏。未指定 `--pid` 时，按 profile 匹配规则顺序找到第一个进程并使用；多个匹配时仍使用第一个（可提示检测到多个 PID）。指定 `--pid` 时验证它是否匹配所选 profile。

链扫描默认模块来自 profile，但显式 `--module` 仍可覆盖，且实际模块名保存在链数据中。第一版保留当前模块 substring 查找语义。

## 5. 分阶段实现

### P1：工具更名与基础配置层

- 将构建目标/可执行文件改名为 `cheat-tool`；更新 Makefile、usage、README 和清理规则，不保留 `ds3hp` 命令或兼容二进制。
- 在 `ds3hp.c` 定义 profile 结构、内置 DS3 默认项、JSON 配置加载、ID 查找和进程匹配 helper。
- 加载 `$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json`（或默认路径）；文件不存在时使用内置 DS3，存在但损坏时给出明确错误。
- 将 `detect_pid()`、`pid_ok()` 改为接受 profile/context；默认使用第一个匹配进程。
- 将 CLI 与 TUI 中 `DarkSoulsIII.exe` 硬编码默认值改为所选 profile 模块名，保留 `--module` 覆盖。
- profile 的默认数值类型、扫描范围、maps 过滤策略均作为必需字段或严格验证的配置项；DS3 默认值保持现状。

### P2：统一 CLI / TUI 游戏上下文

- 在入口统一解析 `--game <id>`，默认 `darksouls3`；未知 profile 在读取状态或接触进程前拒绝。
- 将选定 profile 贯穿进程发现/校验、普通扫描、指针链 scan/resolve/verify/load、TUI 及后台扫描线程。
- TUI 标题显示 profile；`p` 与自动重连始终使用同一 profile。
- 所有 DS3 专属错误、提示和 help 文案改为 profile 名称或泛化表述。
- 对链扫描 `--module` override 保持原语义，并将实际模块名保存在链数据中。

### P3：按 profile 拆分 Watch 与链文件

- 将 Watch 文件移至 `$XDG_CONFIG_HOME/cheat-tool/games/<profile-id>/watches.json`（默认 `$HOME/.config/cheat-tool/games/<profile-id>/watches.json`）。
- profile ID 通过安全校验，禁止路径分隔符、`.`/`..` 等路径穿越；构造路径时检查缓冲区长度。
- 同名 Watch 在不同 profile 下独立；保存一个 profile 时不得写入/覆盖其他 profile 文件。
- 链归属其所在 profile 的 Watch 文件；新增或读取链时核验所属 profile，不能仅凭模块名相同跨 profile 解析。
- 旧 `~/.config/ds3hp/watches.json` 和 `.ds3hp_watches` 仅视作 DS3 数据。仅当新 DS3 Watch 文件不存在时自动迁移；成功后保留旧文件。若目标已存在，不覆盖并提示用户手动处理。

### P4：新格式扫描状态

- 状态文件采用 profile 专属文件名，例如 `.cheat-tool_state.<profile-id>`；新格式头部包含版本和 profile ID。`first` 写入新格式，后续命令核对 profile。
- 旧固定 `.ds3hp_state` 不迁移、不作为新状态使用；检测到时提示格式过期并要求重跑 `first`。
- `reset` 仅删除当前 profile 的状态文件；Makefile `clean` 只清理构建产物，不删除用户状态。

### P5：测试与文档

- 在 `Makefile` 增加轻量 `test` 目标或脚本，不引入不必要测试框架。
- 测试严格 profile 配置解析、未知/无效 profile 拒绝、默认 DS3 行为、前缀 PID 匹配与 first-match 选择、per-profile 路径隔离、链 profile 校验以及旧状态格式拒绝。
- 覆盖 DS3 旧 Watch 数据迁移：只在新文件不存在时迁移，保留旧文件；目标已存在时不覆盖并给出提示。
- README 更新项目名、可执行文件名、`--game`、schema/配置路径、添加自定义 profile 流程、PID 选择行为、Watch/scan state 路径和旧数据处理。
- `.gitignore` 按需添加测试产物；不提交个人配置和运行时状态。

## 6. 关键文件

- `ds3hp.c`：profile 注册/配置解析、进程检测、扫描上下文、链模块默认值、per-profile Watch 存储、二进制扫描状态、TUI 重连及 CLI usage。
- `README.md`：新工具名、配置文件、支持游戏、CLI/TUI 用法、存储和迁移说明。
- `Makefile`：`cheat-tool` 构建目标、测试入口及清理规则。
- `.gitignore`：新增测试产物或本地配置忽略规则。

现有 `Search`、`Cand`、`ChainSet`、`process_vm_readv/writev` 以及 TUI Watch 扫描流程优先复用，不在本计划中大规模拆分 `ds3hp.c`。

## 7. 验证计划

- `make clean && make`：确认只生成 `cheat-tool`；运行 `make test`。
- Profile 配置：测试文件缺失时使用 DS3；有效自定义 profile 可选择；未知 profile、损坏 JSON、字段类型错误、未知字段及非法 profile ID 均明确失败。
- 进程行为：验证默认 `darksouls3`、前缀匹配、无 `--pid` 时选第一个匹配项、显式 PID 不匹配时拒绝；不对真实游戏做写入测试。
- 持久化：测试 DS3 与自定义 profile 的 Watch 文件互不覆盖、同名 Watch 独立、旧 DS3 Watch 迁移目标不存在时成功且保留源文件、目标存在时不覆盖、链跨 profile 拒绝解析。
- 扫描状态：测试新状态格式及 profile ID 校验；旧格式拒绝并提示重新扫描；`reset` 只作用于当前 profile。
- 流程回归：验证 `--module` override、TUI 启动/重连/自动绑定上下文、DS3 无 `--game` 的默认行为。
- 对 JSON、配置路径与 state 边界使用 ASan/UBSan 构建；必要时用可控假进程夹具测试 `/proc` 与模块解析。

## 8. 实施约束

- Profile JSON 使用严格 schema：必需字段缺失/类型错误、未知字段、无效数值范围或非法 ID 均报错；配置文件缺失才使用内置 DS3 fallback，配置存在但无效不得悄悄忽略。
- 不提供 `ds3hp` 兼容命令或二进制；迁移只针对明确约定的旧 Watch 数据，不自动删除任何旧文件。
- 用户配置中的 profile ID 将进入文件路径，必须经过白名单验证，避免路径穿越。
- 默认不指定 PID 时选第一个匹配进程；指定 PID 时必须验证属于所选 profile。
- TUI 生命周期内固定所选 profile；切换游戏需退出并重新启动。
- 扫描状态按 profile 分文件，新格式携带 profile ID；旧 `.ds3hp_state` 不迁移，提示重新扫描。
