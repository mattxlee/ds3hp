# ds3hp — Dark Souls III 内存HP工具

在 Linux 下通过 `process_vm_readv/writev` 读取和修改《Dark Souls III》进程内存，用来
搜索数值（如 HP、MP、魂等）、锁定数值，并支持把地址保存为**跨重启稳定的指针链**。

- 支持浮点/整数两种类型
- 命令行（CLI）与交互式界面（TUI，基于 ncurses）两种用法
- 指针链扫描 + 跨重启交集 + 按值验证，重启后自动恢复地址
- 所有 Watch（名称/类型/锁值/指针链）集中保存为一个 JSON 文件

> 仅用于单机、离线、你自己拥有/可修改的进程。请勿用于联机或破坏他人体验。

---

## 1. 编译

依赖：`gcc`、`ncursesw`、`pthread`（大多数发行版自带）。本机为 Arch/Omarchy，
`ncurses` 已随系统安装。

```sh
make
```

生成可执行文件 `ds3hp`。清理：

```sh
make clean
```

---

## 2. 快速上手（CLI，以 HP 为例，类型 float）

经典"改值筛选"流程：先在满血时快照，再让数值变化，逐步缩小候选。

```sh
# 1) 满血时扫描（范围默认 1..10000；也可用 --value 精确值大幅缩小）
./ds3hp first

# 2) 回游戏受一点伤，然后过滤"下降"的候选
./ds3hp next --dec

# 3) 反复受伤/回血并重复 next --inc / next --dec，直到只剩几条
./ds3hp list

# 4) 锁定 0 号候选（锁当前值）或指定值
./ds3hp lock 0
./ds3hp lock 0 --value 9999 --seconds 30
```

其他常用：

```sh
./ds3hp peek 0                 # 重新读一次某候选的值
./ds3hp set 0 --value 5000     # 只写一次
./ds3hp reset                  # 清除扫描状态（.ds3hp_state）
./ds3hp pid                    # 打印检测到的游戏进程 pid
```

### first 的选项

```
first [--type float|int] [--value V [--tol T] | --min A --max B] [--maps anon|all]
```

- `--type`：数值类型，HP 一般是 `float`；魂/数量类一般是 `int`
- `--value V`：精确匹配，最快（满血时用满血值）
- `--tol T`：配合 `--value` 的容差
- `--min/--max`：范围匹配（默认 `1..10000`）
- `--maps anon|all`：只扫匿名堆区（默认）或全部可读写映射

### next 的过滤条件

```
next <--dec|--inc|--changed|--unchanged|--eq V|--lt V|--gt V> [--tol T]
```

- `--dec` / `--inc`：数值下降 / 上升（最精确）
- `--changed` / `--unchanged`：数值变化 / 未变化（不知道方向时用）
- `--eq V` / `--lt V` / `--gt V`：等于 / 小于 / 大于某值
- `--tol T`：容差

---

## 3. 交互界面（TUI）

```sh
./ds3hp tui            # 自动检测游戏进程
./ds3hp tui --pid N    # 指定进程
```

界面为一个圆角表格，每行一个 Watch：`NAME | TYPE | ADDR | VALUE | LCK | LOCKVAL | CHAIN | STATUS`。

底部提示分四行：

```
addr : a add  x del  f first  d/i dec/inc  c/u changed/unchanged  e eq  Enter cand  r reset
value: v lockval  s once  l hold
chain: C scan/intersect  V verify  L list  G load/bind
misc : j/k move  p pid  q quit
```

### 键位说明

**addr（追地址）**

- `a` 新建 Watch（输入名称、类型 float/int）
- `x` 删除当前 Watch
- `f` 首次扫描（输入 `1234` 精确值、`100-2000` 范围、或 `V:tol` 带容差）
- `d` / `i` 过滤"下降 / 上升"
- `c` / `u` 过滤"变化 / 未变化"
- `e` 过滤"等于某值"
- `Enter` 打开候选列表，`j/k` 选择，`Enter` 绑定为地址
- `r` 重置当前 Watch 的搜索与绑定

**value（锁值）**

- `v` 修改锁值（**不写内存**）
- `s` 把锁值**写一次**（不持续锁）
- `l` 开/关**持续锁定**（按固定频率循环写）

**chain（指针链）**

- `C` 扫描/交集指针链（后台进行，显示进度，可取消）
- `V` 用当前数值验证并裁剪候选链（无需目标地址）
- `L` 查看链列表（显示每条链解析到的地址与当前值），`Enter` 绑定所选链
- `G` 解析已保存的链并绑定地址（链已验证后，重启游戏即可一键恢复）

**misc**

- `j/k` 或方向键移动选择
- `p` 重新检测游戏进程
- `q` 退出（退出时保存所有 Watch）

### 自动行为

- **进程自动重连**：每 0.5 秒检测游戏进程是否存活；若游戏重启，自动重连新 pid、
  清空过期地址，并自动解析已稳定的链；标题短暂显示 `reconnected to new pid`。
- **启动恢复**：启动时读取 JSON 里的 Watch 列表；若某个链已"稳定"，自动解析并绑定地址；
  未稳定的显示候选数，需要你重新追地址后按 `C` 或按 `V` 验证。
- **退出保存**：所有 Watch 及其链写回 JSON。

---

## 4. 指针链（跨重启恢复地址）

裸地址（堆上的绝对地址）每次重启都会变，无法保存。能跨重启复用的是"指针链"：
从游戏模块（`DarkSoulsIII.exe`）里的一个静态指针出发，按固定偏移逐级解引用到目标。

### 4.1 学习（前 2–3 次重启）

先用上面的 CLI/TUI 流程找到一次目标地址 `T`，然后：

```sh
# 第一次：建立候选链集合
./ds3hp chain scan HP --addr 0xADDR --type int

# 重启游戏后，用同样流程重新找到地址 T2
./ds3hp chain scan HP --addr 0xADDR2      # 与上次求交集，假阳性被剔除
```

对应 TUI：绑定地址后按 `C`。**注意：两次 `C` 之间必须重启游戏**（同一次进程内重复扫描
不计入交集，会提示 `no new scan; restart game`）。

### 4.2 用数值直接验证（不必重找地址）

拿到候选链后，其实不必每次都重新扫地址，只要知道当前数值即可裁剪：

```sh
./ds3hp chain verify HP --value 1733
```

对应 TUI 按 `V` 输入当前数值。它会解析每条候选链、读值，只保留等于该值的。
建议用**受点伤后的独特数值**（满血值往往在内存里有多份副本，容易碰撞）。
跨重启的 verify 才计入统计；同一进程内 verify 无区分度（所有链本就都指向目标）。

### 4.3 使用

链稳定后（只剩 1 条且经过跨重启验证），每次启动游戏：

```sh
./ds3hp chain load HP          # 解析链并载入为当前目标
./ds3hp lock 0                 # 锁定
```

TUI 则直接按 `G`（或什么都不做——启动时会自动绑定已稳定的链）。

### 4.4 链的查看与管理

```sh
./ds3hp chain list                 # 列出所有 Watch 及其链状态
./ds3hp chain list HP --pid N      # 列出某 Watch 的链，并显示解析地址与当前值
./ds3hp chain resolve HP           # 解析并打印地址（--value V 可校验）
./ds3hp chain clear HP             # 删除该 Watch 的链
./ds3hp chain rm HP                # 删除整个 Watch
```

### 4.5 参数与"稳定"判定

- `chain scan` 的 `--depth`（默认 4）、`--max-offset`（默认 `0x1000`）、`--module`（默认 `DarkSoulsIII.exe`）
  - `--max-offset` 越小，捷径假链越少，但可能找不到真链
- 稳定（stable）判定：`(scan 轮数 >= 2 或 verify 次数 >= 1) 且 只剩 1 条链`
- 单次扫描可能得到很多候选，需要靠**跨重启交集**和**按值验证**逐步收敛

### 4.6 什么时候追不到

指针链并非万能，以下情况可能没有可用链，此时只能每次按值重扫：

- 目标没有任何从模块静态指针可达的路径
- 指针被加密/混淆，或目标不是"存着的指针"而是运行时计算的地址
- 真实那一跳的偏移超过 `--max-offset`，或层数超过 `--depth`
- 扫描时机不对（对象尚未分配）
- 游戏更新导致模块偏移全部失效

---

## 5. 数据存储

所有 Watch（含各自指针链）保存在单个 JSON 文件：

```
~/.config/ds3hp/watches.json     # 遵循 XDG_CONFIG_HOME
```

结构（顶层键即 Watch 名称）：

```json
{
  "_version": 1,
  "HP": {
    "type": "int",
    "lock_value": 1733,
    "lock_on": false,
    "chain": {
      "module": "DarkSoulsIII.exe",
      "scans": 2,
      "verifies": 1,
      "token": 123456,
      "list": [
        { "rva": 512, "offs": [48, 0] }
      ]
    }
  }
}
```

- `rva` / `offs` 都是相对量，是链的稳定身份；不保存绝对地址
- `lock_value`：int 存整数，float 存 `%.9g`
- 旧的文本文件 `.ds3hp_watches`（若存在）会在首次启动、JSON 为空时**自动迁移**

扫描会话状态（`first`/`next` 用）另存于当前目录的 `.ds3hp_state`。

---

## 6. 命令总览

```
ds3hp tui [--pid N]
ds3hp first [--type float|int] [--value V [--tol T] | --min A --max B] [--maps anon|all]
ds3hp next  <--dec|--inc|--changed|--unchanged|--eq V|--lt V|--gt V> [--tol T]
ds3hp list  [--limit N]
ds3hp peek  <index>
ds3hp lock  <index|a-b|all> ... [--value V] [--interval-ms N] [--seconds N]
ds3hp set   <index|a-b|all> --value V
ds3hp chain scan    <watch> --addr 0xADDR [--depth N] [--max-offset M] [--module S] [--pid P] [--type float|int] [--reset]
ds3hp chain list    [<watch>] [--pid P]
ds3hp chain resolve <watch> [--index K] [--value V] [--pid P]
ds3hp chain verify  <watch> --value V [--pid P]
ds3hp chain load    <watch> [--index K] [--value V] [--pid P]
ds3hp chain clear   <watch>
ds3hp chain rm      <watch>
ds3hp reset
ds3hp pid
```

`watch` 指 JSON 里的 Watch 名称（TUI 里 `a` 新建时的名字）；`chain scan` 若该名字不存在会自动创建。

---

## 7. 注意事项

- **进程检测**：按进程名 `DarkSoulsIII` 匹配。若同时存在多个同名进程，可能选错；
  必要时用 `--pid` 指定。
- **首次扫描较慢**：会遍历数 GB 匿名内存；指针链扫描更慢（整数秒到数分钟）。
- **写入有风险**：`lock`/`set`/TUI 的 `s`/`l` 会写游戏内存。请先确认地址正确，
  避免误写无关数值或破坏内存。
- **正确性自检**：不确定时用 `list`/`TUI 实时值列`/`chain resolve --value` 观察数值是否与游戏内一致。
