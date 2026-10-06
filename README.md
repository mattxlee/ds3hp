# cheat-tool — Linux 游戏内存扫描工具

在 Linux 下通过 `process_vm_readv/writev` 读取和修改游戏进程内存，搜索数值、锁定数值，并支持把地址保存为**跨重启稳定的指针链**。

- 支持浮点/整数两种类型
- 命令行（CLI）与交互式界面（TUI，基于 ncurses）
- 指针链扫描、跨重启交集、按值验证和地址恢复
- 通过 game profile 配置游戏识别信息；内置 profile 为 Dark Souls III
- Watch 和扫描状态按 profile 隔离

> 仅用于单机、离线、你自己拥有/可修改的进程。请勿用于联机或破坏他人体验。

---

## 1. 编译

依赖：`gcc`、`ncursesw`、`pthread`。

```sh
make
```

生成可执行文件 `cheat-tool`。清理构建产物：

```sh
make clean
```

`clean` 不删除扫描状态或用户配置。

---

## 2. 游戏配置

未指定 `--game` 时使用 `darksouls3`。配置文件为 `$XDG_CONFIG_HOME/cheat-tool/cheat-tool.json`，未设置 `XDG_CONFIG_HOME` 时为 `~/.config/cheat-tool/cheat-tool.json`。配置文件不存在时使用内置 DS3 profile；文件存在但无效时程序会报错，不会静默使用默认值。

仓库根目录的 `cheat-tool.json` 是随代码保存的配置副本，包含已实测的内置游戏。程序不会自动读取该文件，需复制或软链到上面的路径才生效：

```sh
mkdir -p ~/.config/cheat-tool
cp cheat-tool.json ~/.config/cheat-tool/cheat-tool.json
# 或让仓库文件成为唯一来源
ln -sf "$PWD/cheat-tool.json" ~/.config/cheat-tool/cheat-tool.json
```

配置内容：

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
    },
    "eldenring": {
      "display_name": "Elden Ring",
      "process_name": "eldenring.exe",
      "module_name": "eldenring.exe",
      "default_type": "int",
      "default_min": 1,
      "default_max": 100000,
      "default_maps": "anon"
    }
  }
}
```

Elden Ring 的 `process_name`/`module_name` 为 Steam/Proton 环境下的实测值（进程名取自 `/proc/<pid>/comm`，模块名取自 `/proc/<pid>/maps`）；默认扫描值可在配置中自行调整。Elden Ring 带 Easy Anti-Cheat，只在离线单人模式使用，联机时不要进行内存操作。

每个游戏配置必须提供 `display_name`、`process_name`、`module_name`、`default_type`（`float` 或 `int`）、`default_min`、`default_max` 和 `default_maps`（`anon` 或 `all`）。配置采用严格校验：缺少字段、字段类型或取值错误、未知字段、非法 profile ID 均会报错。配置文件存在时它就是权威 profile 列表，若要保留某个游戏必须在该文件中列出。进程名按前缀匹配；未指定 `--pid` 时使用发现的第一个匹配进程。新增游戏时应填写目标环境的实际进程名、模块名及默认扫描值，本工具不猜测这些信息。

用 `--game <id>` 选择配置中的游戏，例如：

```sh
./cheat-tool --game darksouls3 pid
./cheat-tool --game eldenring tui
```

TUI 运行期间 profile 固定；切换游戏请退出后重新启动。

---

## 3. 快速上手（CLI，以 HP 为例，类型 float）

先在满血时扫描，再根据游戏中的数值变化逐步筛选：

```sh
./cheat-tool first
./cheat-tool next --dec
./cheat-tool list
./cheat-tool lock 0
./cheat-tool lock 0 --value 9999 --seconds 30
```

其他常用命令：

```sh
./cheat-tool peek 0
./cheat-tool set 0 --value 5000
./cheat-tool reset
./cheat-tool pid
```

### first 的选项

```
first [--type float|int] [--value V [--tol T] | --min A --max B] [--maps anon|all]
```

- `--type`：数值类型，HP 一般是 `float`；魂/数量类一般是 `int`
- `--value V`：精确匹配，最快
- `--tol T`：配合 `--value` 的容差
- `--min/--max`：范围匹配（默认 `1..10000`）
- `--maps anon|all`：只扫匿名堆区或全部可读写映射

### next 的过滤条件

```
next <--dec|--inc|--changed|--unchanged|--eq V|--lt V|--gt V> [--tol T]
```

---

## 4. 交互界面（TUI）

```sh
./cheat-tool tui
./cheat-tool --game darksouls3 tui --pid N
```

界面为一个 Watch 表格，支持扫描、筛选、锁定、指针链扫描/验证/加载。

- `a` 新建 Watch；`x` 删除；`f` 首次扫描；`d/i` 下降/上升；`c/u` 变化/不变；`e` 按值过滤
- `Enter` 打开候选列表并绑定地址；`r` 重置当前 Watch 搜索与绑定
- `v` 修改锁值；`s` 写一次；`l` 持续锁定
- `C` 扫描/交集指针链；`V` 验证；`L` 查看链；`G` 加载/绑定
- `p` 重新检测进程；`j/k` 移动；`q` 退出并保存 Watch

进程重启后，TUI 会用所选 profile 重新连接，并尝试解析稳定链。地址失效时会清除过期绑定并停止该地址的锁写入。

---

## 5. 指针链（跨重启恢复地址）

裸地址每次重启都会变化。指针链从模块静态位置出发，经固定偏移解引用到目标。默认模块取自所选 profile；`chain scan --module` 可覆盖。

```sh
./cheat-tool chain scan HP --addr 0xADDR --type int
# 重启游戏并重新定位地址后再次扫描，以候选交集收敛
./cheat-tool chain scan HP --addr 0xADDR2
./cheat-tool chain verify HP --value 1733
./cheat-tool chain load HP
./cheat-tool lock 0
```

### 分享和导入指针链

可将单条指针链导出为一行文本，便于复制分享：

```sh
./cheat-tool chain export-text HP
# 多候选时指定序号
./cheat-tool chain export-text HP --index 0
```

格式示例：`cheat-tool-chain:v1 module="DarkSoulsIII.exe" type=float rva=0x123456 offsets=[0x10,0x20,0x8]`。module 是模块文件名，RVA 和 offsets 为十六进制；文本不包含进程 PID 或绝对地址。导入时指定本地 Watch 名称：

```sh
./cheat-tool chain import-text HP 'cheat-tool-chain:v1 module="DarkSoulsIII.exe" type=float rva=0x123456 offsets=[0x10,0x20,0x8]'
```

已有同名 Watch 默认报错；加 `--replace` 才替换。TUI 中按 `I`，输入 Watch 名称后粘贴整行链文本（单行）。导入只保存链，不会对进程写内存；若当前进程可解析该模块/RVA，TUI 会尝试绑定地址。

常用管理：

```sh
./cheat-tool chain list
./cheat-tool chain list HP --pid N
./cheat-tool chain resolve HP --value V
./cheat-tool chain clear HP
./cheat-tool chain rm HP
```

指针链保存模块名、RVA 和偏移，不保存绝对地址。只有目标确有从模块静态指针可达的路径时，才能稳定恢复。

---

## 6. 数据存储与迁移

Watch（含锁值、类型和指针链）按 profile 保存：

```
$XDG_CONFIG_HOME/cheat-tool/games/<profile-id>/watches.json
~/.config/cheat-tool/games/<profile-id>/watches.json  # 未设置 XDG_CONFIG_HOME 时
```

扫描状态保存在当前目录的 `.cheat-tool_state.<profile-id>`，包含格式版本和 profile ID；不同游戏状态相互独立。旧格式 `.ds3hp_state` 不迁移，检测到时需重新运行 `first`。

旧 Watch 数据只作为 DS3 数据迁移：旧 `~/.config/ds3hp/watches.json`（若存在）和当前目录 `.ds3hp_watches` 只在新的 DS3 Watch 文件不存在时导入。迁移后保留旧文件；目标已存在时不会覆盖，并提示手动处理。

---

## 7. 命令总览

```text
cheat-tool [--game ID] tui [--pid N]
cheat-tool [--game ID] first [--type float|int] [--value V | --min A --max B] [--maps anon|all]
cheat-tool [--game ID] next <--dec|--inc|--changed|--unchanged|--eq V|--lt V|--gt V>
cheat-tool [--game ID] list [--limit N]
cheat-tool [--game ID] peek <index>
cheat-tool [--game ID] lock <index|a-b|all> ... [--value V] [--interval-ms N] [--seconds N]
cheat-tool [--game ID] set <index|a-b|all> --value V
cheat-tool [--game ID] chain scan <watch> --addr 0xADDR [--module S] [--pid P]
cheat-tool [--game ID] chain list [<watch>] [--pid P]
cheat-tool [--game ID] chain resolve|verify|load|clear|rm ...
cheat-tool [--game ID] reset
cheat-tool [--game ID] pid
```

---

## 8. 注意事项

- 进程检测按 profile 中的 `process_name` 前缀匹配；若多个进程匹配，使用第一个。可通过 `--pid` 指定并校验进程。
- 首次扫描较慢；指针链扫描可能需要数秒到数分钟。
- `lock`、`set` 和 TUI 写入操作会修改进程内存。仅对自己拥有或获准修改的离线进程使用，并先确认地址正确。
- 使用 `list`、TUI 实时值列或 `chain resolve --value` 验证目标值。
