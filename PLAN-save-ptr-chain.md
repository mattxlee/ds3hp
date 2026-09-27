# PLAN: 指针链扫描与跨重启自动恢复（save-ptr-chain）

- 日期：2026-09-28
- 状态：计划（待实现）
- 目标：给定一个已确认的目标地址，自动扫描出**跨重启稳定**的指针链；通过**多次重启的交集**自动去伪，最终无需重扫即可恢复地址。

---

## 1. 背景与动机

裸地址跨重启无效（ASLR + 堆布局变化）。唯一可持久化的是"从模块静态位置出发、经固定偏移逐级解引用到目标"的**指针链**（见对话中的原理说明）。

之前的 `save --ptr` 尝试过，但被删除，原因是 REVIEW.md 记录的缺陷：

- **D1（高）**：默认 `--max-offset 0x8000` 太宽 → 产出"偏移捷径链"（假阳性），保存时能通过校验，重启后指向无关内存；`load` 又不校验读回值，静默报成功。
- **D2（高）**：SV1 条目数未校验 → 整数回绕 → 堆越界写。
- **D3/D4/D5**：索引重排、基线语义不一致、成功计数虚高。

本计划重新实现，并在设计上直接消除上述问题，核心新增是**跨重启交集验证**。

---

## 2. 设计原则

1. **宁小勿宽**：默认 `max-offset` 收紧到 `0x1000`（可调），并要求链根落在模块静态 rw 段。
2. **收集全部，而非首个**：不再"找到一条就停"，而是收集所有候选，交给跨重启交集去伪。
3. **可验证**：每条候选链必须能解析回目标地址；加载时读回值与存档参考值比对，不一致显式警告。
4. **自动收敛**：单次扫描不保证唯一；用 2–3 次重启的链集合求交集，假阳性按布局随机性被自然剔除。
5. **文件安全**：所有长度/计数做上界与乘法溢出检查（修 D2）；畸形文件干净报错不崩溃。

---

## 3. 数据结构

```c
#define CHAIN_MAGIC "DS3CHAIN"
#define CHAIN_MAX_DEPTH   6
#define CHAIN_MAX_OFF     (1u << 20)   /* 单跳偏移硬上限 */

typedef struct {
    uint64_t rva;          /* 根位置相对模块基址的偏移 */
    uint8_t  n;            /* 解引用层数（1..MAX_CHAIN） */
    uint64_t offs[MAX_CHAIN];
} Chain;

typedef struct {
    char     module[256];  /* 模块名（保存时映射路径的 basename） */
    Chain   *chains;
    uint32_t n;
    uint32_t scans;        /* 已参与的扫描轮数（交集次数） */
} ChainSet;
```

链的身份 key = `(rva, n, offs[])`，**不含绝对地址**，因此可直接跨进程比较与求交集。

---

## 4. 反向指针扫描算法

输入：目标地址 `T`、模块 `mod` 及其基址 `modbase`、最大深度 `D`、单跳最大偏移 `M`。

1. 读取 `/proc/pid/maps`，建立可读区域表；标记模块静态 rw 区域与模块文件名。
2. 反向 BFS（从目标向上游找）：
   - 当前"要找的地址"集合 `frontier`，初始 `{T}`；每个元素携带其父探针（用于回溯成链）。
   - 对 `depth = 1..D`：
     - 扫描所有可读区域，逐个 8 字节字 `W`（位于 `loc`）：
       - `W` 必须落在已映射的可读区域内；
       - 存在 `A ∈ frontier` 且 `0 ≤ A - W ≤ M` → `loc` 可作为 `A` 的前驱，边偏移 `d = A - W`；
       - 生成探针 `(loc, d, parent=A, root=T)`；
     - 若 `loc` 位于模块静态 rw 段 → 回溯出 `Chain`，解析验证 `== T` 后加入结果集；
     - 探针作为下一层 `frontier`。
   - 深度上限 `D` 与总探针上限（如 8e6）控制成本；超限则告警并返回已有结果。
3. 结果按启发式排序：**深度大、总偏移小、偏移对齐、根在 `.data/.bss`** 者优先。
4. 去重：相同 `(rva,n,offs)` 只保留一条。

### 与旧实现的差异
- 默认 `M = 0x1000`（旧为 `0x8000`）。
- 遍历完所有深度并收集全部结果（旧为 `found == nt` 即停）。
- 不匹配"只取最浅链"。

---

## 5. 跨重启交集（核心创新）

单次扫描的候选集合记 `C`。流程：

```
run1: 找到目标地址 T1 → scan → C1（保存）
重启游戏
run2: 找到目标地址 T2 → scan → C2
      save  = C1 ∩ C2          # 按 (rva,n,offs) 求交
      scans = C1.scans + 1
```

- 真链在 T1、T2 两次进程中都会出现（结构不变），故落入交集。
- 假阳性依赖当次随机布局，极难在两次独立进程中同时成立，被交集剔除。
- 通常 2 次交集即可收敛到 1 条；可继续第 3 次增强置信度。
- 若交集为空 → 明确报告"未找到稳定链"（目标可能没有静态可达路径），此时只能每次重扫。

### 加载时验证
- 解析链得到地址 `A`；要求 `A` 落在可读映射内（否则 fail）。
- 可选 `--value V`：读回 `4` 字节与 `V` 比较，不一致则**警告**并列出（不静默接受）。
- 多链时默认取排序第一；`--index K` 可指定。

---

## 6. 文件格式（版本化 + 边界校验）

```
u8   magic[8]        "DS3CHAIN"
u32  version         1
u32  scans           # 已参与扫描轮数
u16  module_len
u8   module[module_len]
u32  count
count × {
    u64 rva
    u8  n                        (n <= MAX_CHAIN，否则拒绝)
    u64 offsets[n]
}
```

读取时：校验 magic/version；`module_len`、`count`、`n` 均设上界；用文件剩余长度校验 `count * (9 + n*8)` 不越界；全部通过再分配（修 D2）。

---

## 7. CLI 接口

新增 `chain` 子命令：

```
ds3hp chain scan   <file> --addr 0xADDR [--depth N] [--max-offset M] [--module S] [--reset]
      # file 不存在 → 建立候选集；存在 → 与新扫描结果求交集后覆盖保存
      # --reset 丢弃旧集合，重新开始
ds3hp chain list   <file>            # 列出候选链（深度/总偏移/启发式评分）
ds3hp chain resolve <file> [--index K] [--value V]
      # 解析并打印地址；--value 触发读回校验
ds3hp chain load   <file> [--index K] [--value V]
      # resolve 成功后将地址作为唯一候选写入 .ds3hp_state，供 list/lock 使用
ds3hp chain clear  <file>
```

行为示例：

```
# 第一次（满血，已通过 first/next 得到 HP 地址 T1）
ds3hp chain scan hp.chain --addr 0x561617eda020
#  → candidates: 137 (saved)

# 重启游戏，重新定位得到 T2
ds3hp chain scan hp.chain --addr 0x5600abcd2020
#  → intersected: 1 chain
#    [0] DarkSoulsIII.exe+0x2A1B3C8 -> 0x10 -> 0x18 -> 0x0   (3 derefs)

# 以后每次启动
ds3hp chain load hp.chain --value 1234
ds3hp lock 0
```

---

## 8. TUI 集成

在现有 Watch 模型上扩展：

- Watch 增加：`chain_file[PATH]`、`has_chain`、`chain`（内存中的链）。
- 绑定地址后（`has_addr == 1`）：
  - `c`：对当前 Watch 的目标地址执行 **chain scan**（后台线程 + 进度，复用扫描线程框架），
    保存/交集到 `file`（默认 `chains/<watch>.chain`，可提示文件名）。
    - 首次：建立候选集，状态显示 `chain: N candidates (scan 1)`。
    - 再次（新进程，地址重新绑定后）：交集，状态显示 `chain: M chains (scan k)`；M 收敛后提示"stable"。
  - `g`：加载/解析已保存链，自动绑定地址（下次启动后的主要入口）。
  - 主界面增加一列 `CHAIN`：`-` / `N cand` / `stable`。
- 启动时自动尝试：对所有存在 `chains/<name>.chain` 且标记 stable 的 Watch 解析并绑定（可选）。

键位（在主界面已有基础上新增）：
```
c = 扫描/交集当前 Watch 的指针链
g = 加载已保存链并绑定地址
```

---

## 9. 错误处理与边界

- 进程不在/模块未映射：明确报错，不继续。
- 目标地址不可读：报错。
- 扫描探针超限：告警"结果可能不完整"。
- 文件畸形：版本/长度/计数校验失败 → `error: ...` 且 exit 1（不崩溃）。
- 链解析失败（某一跳不可读）：该链在本次加载中标记 failed，计入统计；`--value` 校验给出警告。
- `chain scan` 时若进程换了（pid 不同）：自动视为新一轮交集（由 `T` 不同体现）。

---

## 10. 性能

- 每层需全量扫描可读内存。DS3 约 5.4GB 匿名区 + 模块，单层约数秒到数十秒，`D=4` 累计可能数分钟。
- 优化手段（按需）：
  - 扫描范围默认限制为 `anon + module`；
  - 只把落在"已映射可读区"的 `W` 当指针，减少 frontier 膨胀；
  - 探针上限 + 提前剪枝（偏移必须对齐、`M` 小）；
  - TUI 放后台线程，UI 不阻塞，可取消。

---

## 11. 测试计划

复用 `.review-tmp/fake.c`（构造真实两级链）：

1. **扫描正确性**：对 fake 的 HP 地址 `T` 运行 scan，应包含真链 `mod+0x200 -> 0x30 -> 0x0`。
2. **假阳性剔除**：用 `fake ... pad/gap` 改变布局重启两次，两次 scan 求交，假阳性消失、真链保留。
3. **解析正确性**：新进程 `resolve` 得到的地址 == 真实 HP 地址。
4. **值校验**：`--value` 不匹配时给出警告而非静默成功。
5. **畸形文件**：空/错 magic/截断/超大 count/超大 n → 干净 exit 1，无 ASan 报错。
6. **CLI 回归**：`first/next/list/lock/set/reset/tui` 不受影响。
7. **TUI**：`c` 后台扫描 + 进度 + 取消；`g` 自动绑定；退出时线程 join 无泄漏。

建议用 `-fsanitize=address,undefined` 跑单元测试。

---

## 12. 分阶段实施

- **P1 核心扫描**：`Chain`/`ChainSet` 结构、反向 BFS、启发式排序、候选去重；CLI `chain scan`（新建 + 覆盖保存）。
- **P2 交集与解析**：`chain list/resolve/load/clear`；跨重启交集；`--value` 校验。
- **P3 文件安全**：版本化格式、长度/溢出校验、畸形文件测试。
- **P4 TUI**：Watch 扩展、`c`/`g` 绑定、CHAIN 列、后台线程与进度。
- **P5 测试与收尾**：fake 端到端、ASan、CLI 回归、README/usage 更新。

---

## 13. 风险与未决问题

- **无静态路径**：目标可能根本不存在稳定链，交集为空是合法结果，需在 UX 上解释清楚。
- **游戏更新**：模块 RVA 变化导致链失效，需重扫。
- **交集收敛速度**：某些结构在两次重启后仍可能有少量共享假阳性；提供第 3 次交集与 `list` 人工确认。
- **性能**：全量扫描耗时；是否需要"仅扫描 heap+module"或缓存可读区，待实测。
- **自动再定位**：v1 要求用户每次提供新地址（或 TUI 重新绑定）；是否要支持"按已知满血值自动再定位目标"作为后续增强。
- **假阳性的形式化**：能否用"链在两次进程中解析到同一**结构**（如都指向含 HP 的对象）"进一步筛选，待研究。

---

## 14. 实现记录（2026-09-28）

已按 P1–P5 实现并测试：

- **核心扫描** `chain_scan()`：反向 BFS，默认 `depth=4`、`max-offset=0x1000`（可用 `--max-offset` 调，硬上限 `CHAIN_MAX_OFF=0x100000`），探针上限 8e6，候选上限 1e6；跳过 `[stack]/[vvar]/[vdso]`；根必须落在模块 rw 段；逐条解析验证。
- **交集** `chainset_intersect()`：按 `(rva,n,offs)` 身份求交，每次 scan 递增 `scans`。
- **文件格式**：`DS3CHAIN` + version 1，含 `type`（float/int，实现时新增，便于 `chain load` 写回 state）、`scans`、模块名、链列表；读取做 magic/version/长度/count/n 校验。
- **CLI**：`chain scan|list|resolve|load|clear`，见第 7 节。`resolve/load` 在 `scans<2` 时打印"未跨重启验证"警告；`--value` 校验不匹配只警告。
- **TUI**：Watch 新增 `chain_file`/`cs`；`C` = 扫描并交集（后台线程、进度、可取消），`G` = 解析已保存链并绑定地址；主界面新增 `CHAIN` 列（`-` / `Nc` / `stable`）。**注意：因 `c` 已用于"变化"过滤，链操作用大写 `C`/`G`。** 链文件默认存到 `chains/<name>.chain`（已加入 `.gitignore`）。
- **测试**：用 `.review-tmp/fake.c` 验证了单次扫描命中真链、跨 3 次重启交集剔除深层巧合链、`resolve`/`load` 精确恢复到新地址、`--value` 校验、5 类畸形文件干净报错、ASan/UBSan 下 scan+交集无报错。

与计划的两处偏差：文件格式新增 `type` 字段；TUI 键位用 `C`/`G` 而非 `c`/`g`。

补充（同日）：链文件新增 `token` 字段（进程标识 = `/proc/pid/stat` 的 starttime 混合 pid）。若再次扫描与上次同一进程，则不递增交集计数、不改变已存集合，并提示"restart game first"；只有真正重启（token 变化）才计入交集。CLI 与 TUI 均已接入。
