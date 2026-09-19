# M4:`attach` 断线重连

日期:2026-09-19
依据:[设计](../specs/2026-09-19-interactive-tty-attach-design.md) 第 7 节
前置:M1/M2 已验收(`shell` 与 `attach` 均可用,退出即时)

## Done When

1. `attach` 期间传输中断,本地自动重连并恢复画面,tmux 会话内容不丢。
2. 重连期间画面上有横幅说明第几次、下次多久后;`Ctrl-C` 放弃。
3. 重连成功但会话已消失时**不静默新建**,报告并退出。
4. 5 分钟上限用尽后放弃,退出码 1,消息里带会话名。
5. `shell` **不**重连 —— 裸登录 shell 的远端进程已随连接死了。

## 关键事实(实现前必读)

1. **`Pump.run` 当前自己拥有输入线程,这与重连不相容。** 它 `init` 进程级
   `session_queue` 并在收尾时 `detach` 那个线程(M1 的退出延迟修复)。第二次
   调用 `run` 会在一个仍被 detach 线程写着的队列上重新 `init` —— 数据竞争。
   所以输入线程的生命周期要提到会话级:**本地终端和它的读者跨重连只有一份,
   churn 的是 PTY 通道。**

2. **租约在停摆期间会过期,而这条设计漏了。** `Claim.ttl_secs = 120`,而重连
   预算是 300 秒。泵没在跑 → tick 没被调 → 没人续租 → 一次三分钟的断线之后
   别人可以合法接管这个会话,而我们会带着一个失效的租约重连回去。
   **所以 `waitForRetry` 必须照调 tick**,并在它返回 false 时放弃重连。

3. `Tmux.isAlive`([Tmux.zig:1605](../../../src/core/session/Tmux.zig#L1605))
   就是"会话还在不在"的现成问法,且它已经把 `tmux` 缺失与会话缺失分开
   (`exit 41` → `error.TmuxMissing`)。不要自己拼 `has-session`。

4. **重连尝试失败时不能往 stderr 写。** `Cli.sshOpen` 现有的
   `.report_and_continue` 用 `std.debug.print` 报告失败 —— 那会画到横幅上。
   需要第四个 `OnConnectFailure` 变体。

5. `openPty` 把 session 置为非阻塞并留在那里。`Tmux.isAlive` 走的是普通 exec
   通道,**必须在 `openPty` 之前**问,那时新 client 还是阻塞的。

6. 传输已经没了的时候**不要关通道**。`Pty.close` 会 `wait_closed`,对一个死
   连接就是干等到超时 —— M1 的收尾注释已经记了这件事。直接 `client.deinit()`。

## 任务

| # | 内容 | 文件 |
|---|---|---|
| 1 | 纯策略:退避序列、5 分钟上限 | `src/core/tty/reconnect.zig`(新) |
| 2 | 输入线程生命周期提到会话级:`startLocal`/`stopLocal`,`run` 收参数 | `src/core/tty/Pump.zig` |
| 3 | `waitForRetry`:等待中排空输入、认 0x03、照调 tick | `src/core/tty/Pump.zig` |
| 4 | 备用屏序列常量 + 绕开 `ctx.out` 的直写 | `src/core/tty/Console.zig` |
| 5 | `OnConnectFailure.silent` + `sshReconnect` | `src/cli/cli.zig` |
| 6 | 会话循环:失败 → 重连 → 验会话 → 换 PTY → 继续 | `src/cli/cmd_attach.zig` |
| 7 | 导出 `reconnect`;非递归 `refAllDecls` 要显式引用 | `src/core/core.zig` |
| 8 | 门禁 | `src/cli/cmd_attach_test.zig` |

## 验证

- `zig build test --summary all`
- 手验:`attach` 期间断网 → 横幅出现 → 恢复网络 → 画面回来、会话内容在
- 手验:`attach` 期间在别处 `tmux kill-session` 再恢复 → 报告"会话消失",不新建
- 手验:横幅期间按 `Ctrl-C` → 立即放弃

## 非目标

`shell` 的重连;M3 内嵌 tmux;M5 转义命令层。

---

## 执行记录

8 个任务全部落地,`zig build test --summary all` → **11/11 步,633/633 测试**
(此前 623,新增 10 条:`reconnect.zig` 5、`Pump.zig` 1、`cmd_attach_test.zig` 4)。

### 计划之外的两件事

**1. `Ending` 分成了两支,因为类型该替收尾记住"还有没有通道"。**
初版让 `Ending` 平铺所有结局,于是 `.local_eof` 既可能来自泵(通道活着)也
可能来自退避期间(连接早释放了),而收尾里那条 `pty.close()` 对后者是访问
已释放内存。改成 `pump` / `outage` 两支之后,关通道那条路径在**结构上**就
够不着停摆结局 —— 这比一个 `pty_live` 布尔可靠,布尔要靠人记得看。

**2. 一条既有缺陷顺手修好(一行,在被重写的代码里)。**
`duration` 原先在 `Pump.run` **之前**求值,所以每条交互收据的时长都是 0。
重排收尾时它必须移动,移到正确位置就是修好。

### 扫描器自证有罪的第八次

新写的顺序门禁("存活检查必须排在拿 PTY 之前")**第一次运行就失败了**,
而代码是对的:我为解释这条约束写的注释里出现了被检查的名字,位置(1601)
排在真正的调用(1776)之前。规则还是那条,现在又贵了一次:

> 被检查的标识符不许出现在被扫描区域的任何散文里,且扫描范围必须收敛到
> 函数体并带一条"边界真的收住了"的断言。

### 待手工验收

- 断网 → 横幅出现 → 恢复 → 画面与会话内容都回来
- 断线期间在别处 `tmux kill-session` → 报告消失,**不新建**
- 横幅期间 `Ctrl-C` → 立即放弃

