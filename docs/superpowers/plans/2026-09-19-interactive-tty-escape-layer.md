# M5:`Ctrl-]` 本地命令层

日期:2026-09-19
依据:[设计](../specs/2026-09-19-interactive-tty-attach-design.md) 第 6 节
前置:M1/M2 已验收,M4 已落地待实际使用验收

## Done When

1. 会话中 `Ctrl-]` 后接一个键触发本地动作,远端收不到这两个字节。
2. 连按两下 `Ctrl-]` 给远端送**一个字面** 0x1D。
3. 未知命令:本地响铃,**两个字节都不转发**。
4. `d` detach、`.` 强制断开、`?` 帮助、`p` 推文件、`g` 拉文件。
5. 菜单画在备用屏,退出后 `vim`/`htop` 的画面完好。

## 关键事实(实现前必读)

1. **`active_execution` 是单槽进程级全局**([cli.zig:259](../../../src/cli/cli.zig#L259))。
   所以**不能在会话里直接调 `cmd_transfer.run`** —— 它会 `registerExecution`
   覆盖掉 attach 自己的登记,再在 defer 里 `clearExecution`,于是此后任何
   `fatal` 都不会结清 attach 那条行。这正是 M1/M2 花了四轮修的那类 bug。
   `p`/`g` 走**子进程**:`terminus push <server> <local> <remote>`。它自带
   操作行和收据,和人在另一个窗口敲的完全一样 —— 这也正是 spec 要的。

2. **`std.fs.selfExePath` 在 Zig 0.16 里整个被删了**(0.14 还有)。找自己的
   路径要手写 `GetModuleFileNameW`,风格照 `Console.zig` 的 extern 块。

3. `std.process.spawn(io, .{ .argv, .stdin/.stdout/.stderr = .inherit })` 还在,
   `child.wait(io)` 取退出码。

4. **菜单期间不读远端,也不需要环形缓冲。** spec 第 6 节写了一个 1 MiB 环形区
   加"丢弃了 N 字节"的提示 —— 那是在解决一个不存在的问题。SSH 通道自带窗口
   流控:我们不读,窗口耗尽,远端就阻塞在写上。**一个字节都不会丢**,比丢弃
   最旧的那段好,而且少一个缓冲区和一条提示。

5. **菜单和提示期间必须照调 tick。** 租约 TTL 是 120s,一个开着菜单去接电话
   的人会让它过期 —— 和 M4 停摆期间同一个问题,同一个解法。

## 任务

| # | 内容 | 文件 |
|---|---|---|
| 1 | 纯状态机:字节 → 转发/吞掉/响铃/动作;纯行编辑器 | `src/core/tty/escape.zig`(新) |
| 2 | 泵的输入路径过一遍状态机;`pending` 缓冲;`Outcome.escape` | `src/core/tty/Pump.zig` |
| 3 | `readKey`:菜单用的取键原语(照调 tick) | `src/core/tty/Pump.zig` |
| 4 | 菜单渲染、帮助屏、路径提示行 | `src/cli/cmd_attach.zig` |
| 5 | `d`/`.` 两种结束方式的账本收尾 | `src/cli/cmd_attach.zig` |
| 6 | `p`/`g` 子进程;`GetModuleFileNameW` | `src/cli/cmd_attach.zig` |
| 7 | 门禁 | `src/cli/cmd_attach_test.zig` |

## 与 spec 的两处有意偏离

**状态机只有两个状态,不是三个。** spec 把 `menu` 也算成一个状态,但那会让
这个模块必须自己拿着行缓冲和输出环 —— 它就不再是一个 `字节 → 步骤` 的纯
函数了。菜单是调用方的模态子循环,那期间根本不往状态机喂字节,所以
"menu 态不转发"是构造上成立的,不需要一条状态转移去保证。

**不做 1 MiB 环形缓冲**,理由见上面第 4 条。

## 不在本次范围

**`s` 切换会话。** 租约和操作行**都**以 `begin` 时选定的会话名为键,切换
意味着结清一条操作再开一条 —— 那是账本上的决定,不是 UI 上的。单独做。

M3 内嵌 tmux。

## 验证

- `zig build test --summary all`
- 手验:`vim` 里按 `Ctrl-]` `?` → 帮助出现 → 返回后 vim 画面完好
- 手验:`Ctrl-]` `Ctrl-]` → 远端收到一个字面 0x1D
- 手验:`Ctrl-]` `x` → 响铃,远端什么也没收到
- 手验:`Ctrl-]` `p` → 路径提示 → 传输跑完 → 回到会话

---

## 执行记录

7 个任务全部落地,`zig build test --summary all` → **11/11 步,650/650 测试**
(此前 633,新增 17 条:`escape.zig` 15、`Pump.zig` 1、`cmd_attach_test.zig` 1,
另有两条既有门禁被改写)。

### 计划之外的三件事

**1. 泵的输入路径需要第二段缓冲。** 状态机会吃掉字节,于是"从队列消耗了
多少"和"该往通道写多少"不再相等;而通道是非阻塞的,一次只肯收一部分。
`pending` 就是这两个数字之间的缓冲。**动作要等 `pending` 排空才交出去** ——
否则一次 detach 会顺手吞掉人在按 `Ctrl-]` 之前打的最后半行命令。

**2. `Ending` 多了第三支 `local`。** `d` 和 `.` 的区别就是要不要等远端确认,
而那正好是"关不关通道"。它排在 `switch` 的最前面是被门禁逼的:不赶时间的
关闭必须待在中止分支之前。

**3. `LineEdit.Step` 和文件级的 `Step` 撞名**,Zig 不允许遮蔽外层容器声明。
内层改叫 `Edit`。

### 扫描器自证有罪的第九次

新写的"传输必须走子进程"门禁,第一次运行就被我自己解释这条决定的注释
绊倒了 —— 那段话里写着被检查的模块名。M4 那次(第八次)刚记过同一条规则。

另有一条既有门禁因为新代码而失去锚点:`reenterOrDie` 里也有一次进入 raw
模式,而它排在 `run` 前面,于是"raw 模式期间不许画"那条门禁从一个与它
无关的锚点开始量。收敛到 `run` 的函数体后恢复。

### 待手工验收

- `vim` 里 `Ctrl-]` `?` → 返回后画面完好
- `Ctrl-]` `Ctrl-]` → 远端收到一个字面 0x1D
- `Ctrl-]` `x` → 响铃,远端什么也没收到
- `Ctrl-]` `p` → 提示两个路径 → 传输跑完 → 回到会话
- `Ctrl-]` `d` → 已 detach,`terminus session ls` 里会话还在

