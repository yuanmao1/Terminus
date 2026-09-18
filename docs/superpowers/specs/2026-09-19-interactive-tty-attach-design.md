# Terminus 交互式终端:`attach` 与 `shell`

日期:2026-09-19
状态:已批准,待实现

## 1. 目标

人类通过 Terminus 连上已注册的服务器,把当前终端变成远端的真 TTY;并且提供裸 `ssh` 给不了的便利。

### Done When

以下五条事实同时成立:

1. `terminus shell <server>` 打开远端 PTY 登录 shell。`vim` 的方向键、`htop` 的刷新、`Ctrl-C` 中断远端进程、中文显示、窗口拉伸后远端重排 —— 全部正确;退出后本地终端完好如初。
2. `terminus attach <server>[:<session>]` 接入 tmux 会话。detach 之后会话在远端存活,`terminus read` 能读到这段交互期间的输出。
3. `terminus server tmux <name> --allow-tmux-install` 把内嵌的静态 tmux 装进 `$HOME/.terminus/bin`,**不需要 root,不需要远端联网**;装完 `terminus session new` 能正常工作。
4. `attach` 期间拔网线,恢复后自动重连并恢复画面,tmux 会话内容不丢。
5. 会话内按 `Ctrl-]` 唤出本地命令层,能 detach / push / pull / 切会话。

### Non-Goals

本次明确不做:

- POSIX(Linux/macOS)本地端。本地控制台层是 Windows-only,和这棵树其余部分一致。
- 端口转发、X11 转发、agent 转发。
- 会话录制与回放(`asciinema` 那类)。
- 多人同时 attach 同一会话的协同编辑。
- 改动既有的 `pipe-pane` 日志行为或既有的 secrets 处理(见第 11 节)。
- 让 `attach` 复用 daemon 连接池(见决策一)。

---

## 2. 三个已决策

### 决策一:`attach` 与 `shell` 不走 daemon,直连

daemon 的热连接省下的是一次 SSH 握手(约 300ms),而交互式会话是**一次连接用几十分钟**,不是每次按键都连。要让它走 daemon,得把长度前缀 JSON 帧协议加一个 v6 流模式,并在 server 侧写一条裸字节泵 —— 为 300ms 付这个代价不划算。

两个动词内部按 `--no-daemon` 语义取直连。

### 决策二:转义键是 `Ctrl-]`,菜单画在备用屏

`Ctrl-]`(0x1D)是 telnet 的既有约定;`bash`、`vim`、`tmux`、`htop`、`emacs` 默认都不绑定它;它是**单字节**,状态机只需两个状态。连按两下发送一个字面 0x1D。

菜单用 `ESC[?1049h` 切到备用屏再绘制,退出时 `ESC[?1049l`。这样它在物理上不可能污染远端全屏程序的画面,也不需要保存/恢复光标。

### 决策三:控制台还原挂在 `refusalCleanup` 同一条链路上

[src/cli/cli.zig:253](../../../src/cli/cli.zig#L253) 的 `active_execution` 已经是为这个问题存在的,其注释写明:`std.process.exit` 跳过 defer,所以必须用进程级全局。控制台状态同构地挂一个 `active_console`。

**本地终端被搞到卡死是这个功能唯一不可接受的故障**,所以它与"收据必须落盘"共用同一条纪律。

---

## 3. 命令面

```
terminus attach <server>[:<session>] [--allow-tmux-install] [--no-lease] [--json]
terminus shell  <server> [--json]
terminus server tmux <name> --allow-tmux-install [--json]
terminus server tmux <name>            # 只报告状态,不装
```

- `attach <server>` 不带会话名 → 列出该服务器现有会话,选择或新建(会话选择器)。
- `attach <server>:<session>` 会话不存在 → 询问后创建。
- `attach` 发现远端没有 tmux → 报告并提议安装;带 `--allow-tmux-install` 则免询问直接装。
- `--json` 对这两个动词只作用于**失败路径和退出摘要**;会话本身是字节流,不可能是 JSON。stdin 不是 TTY 时 `--json` 是唯一有意义的输出形态(见第 8 节:直接拒绝)。

---

## 4. 模块划分

```
src/core/tty/
  modes.zig        纯函数:已存控制台模式 -> 目标模式
  escape.zig       纯状态机:输入字节 -> (转发 | 动作)
  reconnect.zig    纯策略:(第几次尝试, 已过时间) -> 决定
  Console.zig      Win32 绑定:进出 raw、查尺寸、判断是否 TTY
  InputQueue.zig   从 Client.zig 抽出的输入队列 + 取消原语
  Pump.zig         会话循环,装配以上各件
src/core/ssh/Client.zig    新增 openPty / resizePty / ptyIo
src/core/tmux_dist.zig     内嵌 tmux 的安装脚本、摘要、fact key
src/cli/cmd_attach.zig     attach 与 shell 两个动词
src/cli/cmd_server.zig     新增 server tmux 子命令
vendor/tmux, vendor/libevent, vendor/ncurses
```

把 `modes` / `escape` / `reconnect` 抽成纯函数不是洁癖:**本地控制台 raw 模式无法自动化测试**,所以要把不可测的面积压缩到只剩几个 Win32 调用,其余全部拿进测试。

### 各模块的职责、接口、依赖

| 模块 | 做什么 | 对外接口 | 依赖 |
|---|---|---|---|
| `modes.zig` | 计算目标控制台模式 | `fn desired(saved: Modes) Modes` | 无(纯) |
| `escape.zig` | 判定每个输入字节是转发还是动作 | `fn feed(self: *State, byte: u8) Step` | 无(纯) |
| `reconnect.zig` | 决定是否重试、等多久 | `fn decide(attempt: u32, elapsed_ms: i64) Decision` | 无(纯) |
| `Console.zig` | 真正改控制台状态并保证还原 | `enter() !Saved`、`Saved.restore()`、`size()`、`isTerminal()` | `modes.zig`, Win32 |
| `InputQueue.zig` | 后台线程读本地 stdin,主循环取走 | `init`/`peek`/`consume`/`snapshot`/`requestStop` | Win32 取消原语 |
| `Pump.zig` | 双向泵 + 尺寸轮询 + 转义分流 + 重连 | `fn run(cfg: Config) !Outcome` | 以上全部 + `Client.zig` |
| `tmux_dist.zig` | 内嵌 tmux 的安装脚本与摘要 | `executable`、`install_script`、`fact_key` | `build.zig` 注入 |

`InputQueue` 从 [Client.zig](../../../src/core/ssh/Client.zig) 抽出,`tunnel` 改为引用同一份。**只搬移,不改行为** —— `tunnel` 的循环本身不动。

---

## 5. 控制台层规格

### 保存与设置

保存四项:输入模式、输出模式、输入代码页、输出代码页。

输入句柄(`CONIN$`):

- 清除 `ENABLE_LINE_INPUT`(0x0002)、`ENABLE_ECHO_INPUT`(0x0004)、`ENABLE_PROCESSED_INPUT`(0x0001)
- 设置 `ENABLE_VIRTUAL_TERMINAL_INPUT`(0x0200)

清除 `ENABLE_PROCESSED_INPUT` 是"`Ctrl-C` 打断远端进程而不是杀死 terminus"的**全部机制** —— 它让 `Ctrl-C` 以字节 0x03 进入输入流,而不是在本地触发 `CTRL_C_EVENT`。`modes.zig` 对这一条有独立断言。

**不设置** `ENABLE_WINDOW_INPUT`:输入线程用阻塞 `ReadFile` 读字节流,窗口事件记录会被丢弃而不是投递,设了也读不到。尺寸改用轮询(见下)。

输出句柄(`CONOUT$`):

- 设置 `ENABLE_VIRTUAL_TERMINAL_PROCESSING`(0x0004)、`DISABLE_NEWLINE_AUTO_RETURN`(0x0008)
- 保留 `ENABLE_PROCESSED_OUTPUT`(0x0001)

代码页:`SetConsoleCP(65001)`、`SetConsoleOutputCP(65001)`。

### 还原保证

`active_console: ?Console.Saved` 是进程级全局,与 `active_execution` 同构。还原在四处发生:

1. 正常返回路径的 `defer`
2. `refusalCleanup()` —— 覆盖所有 `fail` / `failWithCode` / `failReportingClaim` 路径
3. `SetConsoleCtrlHandler` 回调 —— `CTRL_BREAK_EVENT` / `CTRL_CLOSE_EVENT` / `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT` 不经过输入流,必须单独接
4. panic 处理器

这四处会重叠,所以 `restore()` **必须幂等**:重复调用无害,且在没有保存状态时是空操作。

### 尺寸

主循环每 200ms 调用 `GetConsoleScreenBufferInfo`,取 `srWindow.Right - Left + 1` 与 `Bottom - Top + 1`。变化时调用 `libssh2_channel_request_pty_size_ex`。200ms 的延迟对人类不可感知,换来的是不必把事件读取和字节读取混在一起。

---

## 6. 转义层规格

### 状态机(`escape.zig`)

三个状态:`passthrough` / `armed` / `menu`。

**passthrough**
- 0x1D → 转入 `armed`,**不转发**
- 其他 → 转发

**armed**(收到 0x1D 之后的下一个字节)

| 字节 | 动作 |
|---|---|
| 0x1D | 转发一个字面 0x1D,回 `passthrough` |
| `d` | detach |
| `.` | 强制断开(`ssh` 的 `~.` 约定) |
| `p` | 打开菜单:push |
| `g` | 打开菜单:pull |
| `s` | 切换/新建会话(仅 `attach`) |
| `?` | 帮助 |
| 其他 | 本地响铃,回 `passthrough`,**两个字节都不转发** |

最后一行是明确决定:`ssh` 在无效命令时会把两个字符都发出去,我们不。理由是不转发可预测;转发会让一次误触变成远端收到两个随机字节,而那两个字节可能落在一个正在等待确认的提示符上。

**menu**
- 不转发任何输入到远端
- 远端输出**继续读取并缓冲**,菜单退出后一次性刷出。缓冲区是 1 MiB 环形区:溢出时丢弃最旧的字节(它是滚动区,最旧的那段正是已经滚出屏幕的),并在退出菜单时提示 `菜单期间丢弃了 N 字节`。不设上限会让一个开着菜单去泡咖啡的人把内存吃光。

### 菜单渲染与行编辑

进入 `ESC[?1049h`,退出 `ESC[?1049l`。行编辑只支持:回显、退格(0x08 与 0x7F)、Enter 提交、ESC 取消。**不做**历史、补全、光标移动。

`p` / `g` 的参数行格式:`<本地路径> <远端路径>`,复用既有的 `cmd_transfer` 代码路径,包括它的操作行与收据。

---

## 7. 重连策略

**仅 `attach`。** `shell` 不重连 —— 裸登录 shell 的远端进程已经随连接死了,重连只会得到一个全新的 shell,假装它是原来那个是在撒谎。

触发条件:PTY 通道读或写返回非 `EAGAIN` 的错误,或会话断开。**用户主动 detach 不触发。**

退避序列:1s、2s、4s、8s、15s,其后恒定 15s。总上限 5 分钟,超出则放弃,退出码 1,消息中带上会话名以便稍后手动重连。

重连期间在备用屏显示:`重连中…(第 N 次,下次 8s 后) Ctrl-C 放弃`。

此处的 `Ctrl-C` **是本地解释的**:控制台已清除 `ENABLE_PROCESSED_INPUT`,所以它到达时是字节 0x03 而不是信号。重连状态下泵不转发任何输入(没有通道可转发),把 0x03 读作"放弃"。这是 0x03 在整个会话期间唯一一次不被送往远端。

重连成功后重新 `request_pty` 并执行 `tmux attach -t =<tname>`;tmux 自己会重绘整屏,所以本地不需要保存画面。

**重连成功但 tmux 会话已消失**:不静默新建。报告"会话 X 在断线期间消失了"并退出。静默新建会让人对着一个空 shell 以为自己回到了原来的工作现场。

---

## 8. 错误处理

| 情况 | 行为 |
|---|---|
| stdin/stdout 不是 TTY | **直接拒绝**,不降级。降级只会吐出控制序列乱码。`--json` 下给结构化拒绝。 |
| 远端没有 tmux(`attach`) | 报告 + 提议安装;`--allow-tmux-install` 时直接装 |
| 远端没有 tmux(`shell`) | 不受影响,照常 |
| host key 不匹配 | 沿用既有拒绝,连都不连 |
| 传输中断(`attach`) | 进重连状态机 |
| 传输中断(`shell`) | 退出,并明说"裸 shell 不持久,远端进程已经结束" |
| 控制台还原失败 | **唯一一个失败也必须继续的路径**,写 stderr 并继续退出流程 |
| 远端不是 x86_64 Linux(装 tmux 时) | 拒绝,exit 78,与 helper 安装同形 |
| 安装目录挂载为 `noexec` | 拒绝,exit 77,与 helper 安装同形 |
| 上传的 tmux 摘要不匹配 | 拒绝,exit 74,与 helper 安装同形 |

---

## 9. tmux 分发

### 构建

`vendor/tmux`、`vendor/libevent`、`vendor/ncurses`,在 `build.zig` 中以 `addExecutable` 交叉编译到 `x86_64-linux-musl`,`linkLibC`,手写 `config.h` 与源文件清单 —— 与树中既有的 libssh2 / sqlite 处理方式相同,绕开 autoconf。产物经 `addAnonymousImport("terminus_tmux", ...)` 内嵌,与 [build.zig:155](../../../build.zig#L155) 处理 helper 的方式一致。

**最尖的一根刺是 terminfo。** ncurses 运行时要查 terminfo 数据库,远端若没有对应条目,tmux 直接起不来。解法是**预生成并 vendored 一份 `fallback.c`**,烧入以下条目:

`xterm-256color`、`xterm`、`screen`、`screen-256color`、`tmux`、`tmux-256color`、`vt100`、`ansi`、`dumb`

这条单独设一个验收门禁:在一个**没有 `/usr/share/terminfo`** 的容器里,`TERM=xterm-256color` 下能起 tmux 会话。

预计 exe 体积从约 2 MB 增至约 4 MB。

### 安装

照 [cmd_server.zig](../../../src/cli/cmd_server.zig) 中 `helper_install_script` 的形状:

- 目标 `$HOME/.terminus/bin/tmux`
- `umask 077`,`chmod 700`
- 预检 `uname -m` 与 `noexec` 挂载
- `mktemp` + `sha256sum` 自校验 + 原子 `mv`,旧版留 `.previous`
- 全程走 execution ledger,有 request id 与收据
- 摘要记入 per-server fact,key 为 `tmux_sha256`
- 必须显式 `--allow-tmux-install`

### 调用路径

[Tmux.zig:97](../../../src/core/session/Tmux.zig#L97) 的 `run` 是该文件**唯一**的 exec 出口,32 处 `tmux` 字面量全部经过它。在 `run` 中给脚本加上前缀:

```sh
PATH="$HOME/.terminus/bin:$PATH"
```

这样 32 处字面量一处都不必修改,`command -v tmux` 也会优先命中自带的那份。

配一个门禁:断言 `Tmux.zig` 中不存在绕过 `run` 的 `executor.exec` 调用 —— 否则新增的脚本会在 PATH 前缀之外静默失效。

### 新增布尔 flag

`--allow-tmux-install` 与 `--no-lease` 两个都必须同时进入 [args.zig](../../../src/cli/args.zig) 的 `bool_flags` **并**被生产代码读取;该文件的双向门禁会强制这一点。漏登记不是编译错误 —— 它会让这个读取永远为 `false`,并把后面那个参数当成它的值吞掉。

---

## 10. 账本集成

新增 operation kind `.attach`。

**不需要 schema 迁移。** [operations.zig:29](../../../src/core/store/operations.zig#L29) 中 `control` 变体的注释已经记录了这一点:`operations.kind` 是裸 `TEXT NOT NULL`,不像 `status` 和 `resolved_status` 带 CHECK 约束。真正的代价在别处 —— [receipts.zig](../../../src/core/store/receipts.zig) 中两张**双向穷举**的可采纳性矩阵会停住构建,直到新 kind 的每一格都被有意地回答。这是编译器强制的,漏不掉。

- `argv_redacted`:`attach` 为 `"interactive session"`,`shell` 为 `"interactive login shell"`
- `attach` 取会话的争用范围租约。**那个范围是 `.job`,不是 `.session`** —— [cmd_session.zig:1774](../../../src/cli/cmd_session.zig#L1774) 的 `contentionScope` 把 `job-deploy` 映射成 `.{ .kind = .job, .key = "deploy" }`,其测试写明理由:"the session a running job lives in contends with the job, because it *is* the job's shell"。照抄这个映射,`attach` 就天然与 `job kill` 争同一个东西,不需要第二套机制。TTL 用既有的 `Control.Claim.ttl_secs`(120s,全树共用,本次不改),**每 30s 续一次** —— 续租是一次 store 写,挂在 200ms 的空闲 tick 上会变成每秒五次写。**效果是人在会话里时 `session rm` 与 `job kill` 会被拒绝 —— 这是有意的。** `--no-lease` 可退出这个行为。
- `shell` 走 `.server` scope,`mutating = false`,**不取租约** —— 裸登录 shell 不声明任何东西,也不该挡住别人。但仍记 operation 行。

终态取值受 [op_state.zig:458](../../../src/core/store/op_state.zig#L458) 的 `canSettle` 约束,已逐条核对:

| 情况 | 从 | 终态 |
|---|---|---|
| 正常 detach / shell 正常退出 | `remote_started` | `.exited{exit_code}` |
| 连接建立前用户放弃 | `created` / `connecting` | `.local_abandon{reason}` |
| 重连耗尽上限后放弃(`attach`) | `remote_started` | `.indeterminate` |
| 传输丢失且不重连(`shell`) | `remote_started` | `.indeterminate` |

后两行不能用 `local_abandon`:`canSettle` 只允许它从 `created`/`connecting` 落,因为"放弃"只在尚未交出任何东西时才成立。而这正是语义上对的结果 —— 我们并不知道那个 tmux 会话或那个登录 shell 现在怎么样了,只知道**自己不再看着它了**。`reason` 写明这一点,`last_observed` 记 `remote_started`。

不给新动词任何权威,会重演 [cmd_session.zig](../../../src/cli/cmd_session.zig) 文件头自己记录的那个错误 —— 那里明确写了 `session rm` 曾是"树里唯一一个没有任何权威的破坏性远端动词"。

---

## 11. 一条必须说出口的事

tmux 的 `pipe-pane` 日志是**远端明文转录**。人在 `attach` 里敲的东西,其**回显**会进入该日志 —— 命令行上的密码(如 `mysql -pxxx`)会被记下来,而 `sudo` 提示符下输入的密码因为不回显所以不会。

这不是本次引入的洞(它是既有的 secrets 阻断项之一),但 `attach` 会显著放大它:以前只有 agent 发的命令进日志,现在人类的每一次手敲也进。

**v1 不改 `pipe-pane` 行为**,但 `attach` 首次连接时打印一行:

```
本会话输出会写入远端 pane 日志(agent 可读)
```

---

## 12. 测试策略

### 可自动化

- `modes.zig`:给定已存模式算出目标模式;对"`ENABLE_PROCESSED_INPUT` 被清除"单独断言
- `escape.zig`:字节序列 → 动作序列;覆盖双击发字面量、未知命令两字节都不转发、menu 态不转发
- `reconnect.zig`:退避序列、5 分钟上限、detach 不触发
- 安装脚本:blackbox,与 helper install 同形(摘要不匹配 → exit 74)
- tmux 二进制:在 WSL 中真实运行 —— 起会话、attach、**并在无系统 terminfo 的环境下**验证 fallback 生效
- PTY 通道:blackbox 对 WSL 中的 sshd
- `Tmux.run` 唯一出口门禁

### 不可自动化(必须手验,写进 M1 验收)

本地控制台 raw 模式的实际观感:`vim` 方向键、`htop` 刷新、`Ctrl-C`、中文显示、窗口拉伸、以及**异常退出(关窗口 / Ctrl-Break / 杀进程)后终端完好**。

---

## 13. 里程碑

| | 内容 | 验收 |
|---|---|---|
| **M1** | PTY + raw 模式 + 泵 → `terminus shell` 可用 | 第 12 节全部手验项通过 |
| **M2** | `terminus attach` + 会话选择器 | detach 后会话存活,`terminus read` 读得到这段输出 |
| **M3** | vendored tmux 构建 + 安装 | 无 terminfo 容器里能起会话;摘要门禁通过 |
| **M4** | 断线重连 | 拔网线恢复后画面不丢;会话消失时不静默新建 |
| **M5** | 转义键命令层 | `Ctrl-]` 各命令;备用屏不污染 `vim` 画面 |

M1 先做 `shell` 而不是 `attach`,尽管 `attach` 才是主线 —— 因为 raw 模式与 tmux 构建是两个独立的未知数,先把它们分开,不要让"终端花屏了"和"tmux 编不出来"同时发生。M3 与 M1/M2 无依赖,可并行。

---

## 14. 非阻塞既有发现(不在本次范围)

- 五条漂移的 mutation 锚点:`W6-undeclared-kind-declares-nothing`、`M18-redaction-fast-path`、`G17d-pool-ignores-the-authority` 匹配不到;`M16-phase-status-image`、`G13-argv-word-separator` 匹配两次。在 HEAD 上即已漂移。
- `cmd_sync` 双向都把整个 tar 留在内存里。
- 机械对账只覆盖 11 种 operation kind 中的 1 种;本次新增第 12 种(`.attach`)同样不带对账。
- 卡在 `submitted` 的 `exec` 没有逃生舱(`--override` 说去用 `--from-log`,`--from-log` 说需要一个 job)。
