# lhm 代码库评审：架构 / 可靠性 / 安全

- 初次评审：2026-11-23（v1）
- 复审 1：2026-11-23（v2，针对修复提交 `7093f83`）
- 复审 2：2026-11-23（v3，针对 `7093f83` 之上的**工作区重构**，+1316/−450，新增 `core/mutations.py`、`core/userkeys.py`）
- 范围：`src/lhm/**`、`templates/**`（对照 `DESIGN.md` / `README.md`）
- 当前状态：**543 单测全绿（v1 时 244），ruff 干净**。初版/复审 1 的全部确认发现——含高/中/低危与结构性架构项——**已基本全部修复**；唯一实质残留为 Ed25519 公钥的子群点校验（stdlib 限制）。

安全关键工具（以 root 运行，承担 SSH/防火墙/审计等变更）。经三轮迭代，代码已从"高于同类脚本一个档次"提升到**结构性安全**：
dry-run、密钥、原子性、锁定恢复均下沉为可复用的核心机制而非逐模块自觉。

---

## 一、复审 2（v3）：结构性重构验证

本轮引入两个新核心并重写 `ssh.py`（601→1030）、`files.py`、`backup.py`、`runner.py`、`checks.py`：

### 1. 集中式 dry-run 守卫（解决架构 #1）
- `core/mutations.py`：`ContextVar` 守卫，`mutation_mode(dry_run=...)` 嵌套不可放宽外层（`mutations.py:17`）。
- `cli.py:988` `with mutation_mode(...)` 包裹整个 dispatch，内部 `Runner(dry_run=not mutations_allowed())`。
- `files.py` 全部写函数（`write_dropin`/`append_marked`/`ensure_dir`/`set_mode`/`remove_file`/`restrict`）、
  `backup.py`、`runner.py` 均以 `mutations_allowed()` 为准。**dry-run"零写入"从此是结构性保证**。

### 2. 超时杀进程组 + dry-run 不再伪装成功（解决两条遗留）
- `runner.py`：`Popen(start_new_session=True)` + 超时/异常时 `_kill_tree` → `os.killpg(SIGKILL)` + 有界回收 +
  关闭读端避免 `communicate()` 挂死（`runner.py:55-76`）。`apt-get` 等孙进程不再在超时后继续写系统。
- dry-run 返回 `returncode=None`（非合成 0），`ok` 为 False → verify 步骤不再"成功于从未观测"（`runner.py:32,131-134`）。
- 新增 `redact` 参数隐藏命令参数中的密钥（`runner.py:126,131`）。

### 3. 文件层加固
- `render_template` 现在也校验引号/控制字符（`_validate_value`，解决架构 #2，含 fail2ban `${hostname}` 注入面）（`files.py:269-279`）。
- `append_marked` 解析 begin/end 边界并**原地更新陈旧块**（解决 marker 幂等陈旧）；拒绝畸形/重复/未闭合标记（`files.py:197-266`）。
- `_reject_symlink`：`write_dropin`/`append_marked` 拒绝经符号链接覆盖（`files.py:36-38,182,234`）。
- `locked_target`：强健 advisory 文件锁（O_NOFOLLOW/O_DIRECTORY、校验父目录属主与非组/他人可写、拒符号链接锁文件、
  flock 非阻塞、重 stat 检测替换），用于 `ssh.py:837` 与 rollback（`cli.py:821`）。

### 4. 备份/回滚原子化（解决 TOCTOU / 非原子 / 权限窗口）
- `os.link` 原子占用 `.bak.N`（EEXIST 重试，无 exists-then-copy 竞态）；私有暂存目录复制+fsync 后硬链接发布，
  部分副本不会成为 `.bak`；回滚经 `os.replace` 原子替换；秘密备份发布前设权限，无 world-readable 窗口（`backup.py:107-159,204-206`）。

### 5. SSH 锁定恢复全面化（解决回滚缺口）
- `recover()` 现在覆盖**所有**失败路径：`sshd -t`、`-T` 门禁、reload/restart、最终 verify、
  `KeyboardInterrupt`、以及 `(CommandError,OSError,ValueError)`（`ssh.py:870-982`）。
- `SshError(ValueError)` → 被 `except` 捕获 → 确保 line 954 的 enablement 失败路径也走恢复（已核对继承链）。
- 状态感知恢复：socket 转换走 `_recover_socket`（回滚 drop-in→重启用 socket→验监听→否则 `start` service+控制台指引），
  纯 service 走 `_recover_service`（`ssh.py:507-576`）。
- `_managed_rollback_path`：rollback 仅接受**精确的 lhm 托管路径白名单**并拒绝路径中的符号链接
  （解决"rollback 任意 FILE.bak"）（`cli.py:763-786`）。

### 6. 公钥校验强化
- RSA 要求 ≥1024-bit 模数；ECDSA 校验曲线名、点长度、坐标在曲线上（`ssh.py:97-151`）。
- `checks.py`：直接监听端口仅计入进程名精确为 `sshd` 的记录；`ss` 不可用时 `live_ssh_ports` 返回 `None` → 验证 `SKIPPED`。

### 7. 其余 v2 小项全部收口
- `services.py:183,198` 中止 → `ABORTED`；rollback 中止 → `EXIT_ABORT`（`cli.py:818`）。
- `fail2ban` `_time_value`/`_retry_value` **拒绝 0**（解决 bantime/maxretry fail-open）。
- `firewall`：socket 状态/监听证据不全时返回 `current is None` → FAIL 带控制台排查指引（`firewall.py:55-66`）。
- `sandbox`：用本次运行的 `on_backup` 备份做精确回滚（替代 `newest_backup` 竞态），恢复重启失败再提示（`sandbox.py:188-250`）。

**修复质量评价**：很高。新增约 268 个单测（含 `test_userkeys.py` 51 个）。未发现本轮引入的新高/中危问题或回归。

## 二、复审 2 剩余 / 遗留项（均为低～中，诚实记录）

- **Ed25519 公钥仅结构校验（中，stdlib 限制）**：`ssh.py:135-138` 对 ed25519 只验"32 个非零字节 + 帧格式 + 声明类型==内层类型"，
  **未做曲线子群/点在曲线上校验**（纯 stdlib 无法在不自行实现域运算的前提下完成）。一个帧格式正确但无效的 32 字节 blob 仍可通过，
  从而被计为"登录 key"并允许关闭密码认证。实际锁定风险低（运维提供的是自己的真实公钥，且 `sshd -T` 门禁 + "保持会话 + 先测 key 登录"仍在）。
  建议：README 明确此为已知限制，或在 ed25519 上增加轻量子群检查。RSA/ECDSA 已强化，不受影响。
- `userkeys.py:61` — `except OSError, ValueError:` 写法罕见。**已实测**：在本 Python 3.15 环境等价于 `except (OSError, ValueError):`
  （两者都捕获、`ValueError` 名字未被遮蔽），非缺陷；建议加括号以求清晰与跨版本可移植。
- `recover()` 不捕获 `(CommandError,OSError,ValueError)` 之外的异常（如 `KeyError`/`TypeError` 等编程错误）→ 这类 bug 不触发恢复。
  属合理取舍（非运行期失败模式），仅备案。
- `checks.py` — `current_ssh_ports` 在 `sshd -T` 无结果分支把不可用折叠为 `[]`（而非 `None`）。低；firewall 的 `current is None`
  守卫 + 空集 fail-closed 已覆盖主要锁定风险。
- socket 转换只重启其 trigger 指向的单个 service（不再"先 ssh 后 sshd"）——通常更正确，建议确认 trigger 解析在各发行版取到正确单元。低。

## 三、架构结论

初版提出的四项结构性隐患：**#1（dry-run 集中守卫）、#2（模板取值校验）已彻底解决**；#4（失败自动回滚一致性）SSH/sandbox 已大幅改善；
#3（root 门禁只在 CLI）仍为设计取舍（可接受）。核心抽象（`mutations`/`runner`/`files`/`backup`）职责清晰、可测试、可复用。

## 四、仍值得肯定的设计（延续）

- 全仓无 `shell=True`/`os.system`/`eval`；命令走列表参数；超时结构性强制且超时杀进程组。
- 原子写 `mkstemp`(0600)+fsync+`os.replace`；秘密文件无 world-readable 窗口。
- `render_shell_template`/`render_template` 均校验引号/控制字符。
- 幂等优先 + 双确认 + 非 TTY fail-closed + `ABORTED`/`EXIT_ABORT=3` + 结构性 dry-run。
- 审计不可变性按 DESIGN 规则 8 精确实现；fail2ban 激活/加载顺序正确。

## 五、后续建议（可选）

1. ed25519 增加轻量子群/点校验，或在文档标注为已知限制。
2. `userkeys.py:61` 的 `except` 加括号。
3. `checks.py` 的 `current_ssh_ports` 在不可用时返回 `None` 而非 `[]`，与 `live_ssh_ports` 一致。
4. （可选）对本轮 SSH socket 转换 + 恢复状态机做一次独立 oracle 评审，作为高风险 auth 路径的第二道签核。

---

## 验证记录（v3）

- `uv run pytest -q` → **543 passed**；`uv run ruff check` → All checks passed。
- 亲自通读核心：`mutations.py`、`runner.py`(diff)、`files.py`（全文）、并追踪 `ssh.py` 的 `recover()` 异常链
  （确认 `SshError(ValueError)` 被捕获、所有失败路径入恢复）。
- **实测** `except OSError, ValueError:` 在本环境的真实语义（捕获二者、不遮蔽名字），排除 agent 关于"语法错误/漏捕"的误判。
- 三路 explore agent 分别审查 `userkeys.py`、`ssh.py` 重写、`backup.py`/`checks.py`；结论已交叉核对，修正 agent 的两处误报。
- 全仓 `grep` 确认无 `shell=True`/`os.system`/`eval`/`exec`。

---

## 六、复审 2 附录：oracle 独立评审 —— SSH socket 转换 + 恢复状态机

对高风险 auth/锁定路径（`_apply_confirmed_hardening` 及 `_recover_socket`/`_recover_service`）做了一次独立 oracle 审计
（只读，未运行服务）。我已逐条与源码交叉核对，并对严重度做了校准（oracle 倾向把"远程加固工具固有、已被 DESIGN
运维措施缓解的设计局限"也标为高）。核心洞察：**本工具验证的是"存在监听端口"，而非"管理员真能用 key 登录"**——
`sshd -T` 门禁 + `ss` 端口探测都是本机监听证据，不是登录证明。

### 代码级可修（建议修复）
- **中 · `ssh.py:870-889`**：`recover()` 中 `_rollback_dropin()`(874) 在 `try` 内，**若文件回滚抛错则 `_recover_socket`
  被整体跳过** → socket 已停、监听未恢复、仅打印一行提示。监听恢复不应依赖文件回滚成功。建议：文件回滚与监听恢复各自
  独立 try，监听恢复优先且总是尝试。（已核实）
- **中 · `ssh.py:630-647`**：生效值门禁校验 port/root/password/AllowUsers，但**不校验 `AuthorizedKeysFile`**（亦不计
  管理员相关的 `Match` 块）。若更早配置把 `AuthorizedKeysFile` 指向别处，装好的 key 不被采用 → 关闭密码认证后锁定，
  而门禁报 OK。建议：把 `authorizedkeysfile` 纳入 `_effective_problems`，或在门禁后要求二次连接实测登录。（已核实）
- **低 · `ssh.py:896-897`**：`write_dropin`(896) 落盘后、`written=...`(897) 赋值前若收到 `KeyboardInterrupt`，
  `written=False` → `recover()` 于 871 直接返回、**不回滚**，未门禁的配置留在磁盘，下次 sshd 重启/重启机生效。
  建议：改用已存在的 `_dropin_snapshot()`(714) 按"写前快照 vs 当前文件"在锁内判断是否需回滚。（已核实）
- **低 · `ssh.py:537-565`**：`_recover_socket` 在 `stop`/`daemon-reload` 失败分支只修复开机 enablement，不实际拉起 socket
  → 该子路径下无活动监听（虽 daemon-reload 少见失败）。建议保留一个不依赖前序成功的"已知可用"恢复入口。

### 设计级局限（建议文档化 / 后续增强）
- **中 · `ssh.py:928-958`**：停旧 socket(936) 与起新服务(958) 是两步；其间若 lhm 进程被杀（`SIGTERM`/`SIGKILL`，
  `KeyboardInterrupt` 已处理），`recover()` 不会运行——若原本仅 socket 在监听，主机可直接失联。健壮做法：停 socket
  之前用 `systemd-run`/at 安排一个**不依赖 CLI 存活**的定时自动回滚（登录确认后再取消），这是成熟远程加固工具的常规手段。
- **中（固有）**：工具无法代替真实登录验证。现有缓解仍有效且必须依赖——DESIGN/README 的"保持当前会话、先在新端口用
  key 登录成功再继续"、`apply all` 默认跳过 ssh-hardening、firewall 先放行端口。**建议在 README 用更强措辞标注**：
  verify PASS 仅证明监听存在，不证明可登录。
- **低 · `ssh.py:896-923`**：写入候选 drop-in 后、门禁完成前，socket 仍活动，期间入站连接会由 socket 拉起的
  **每连接临时 sshd** 读到候选配置；但这些实例短暂且独立，监听者（PID1 socket）不受影响，回滚后新连接即读回原配置。影响低。

### oracle 确认无误的点
- `954` 的 `SshError`（`class SshError(ValueError)`）确由 `980-982` 捕获；`service_enable_attempted`/`restart_completed`
  在提交 systemd job 前置位；变更用的 `check=True` 调用都在 `try` 内，无绕开恢复的普通 `return`。
- 正常 socket 恢复会用 `ss -tlnp` 子集校验原端口；所有恢复失败都以 `FAIL` + 控制台精确命令大声暴露，CLI 非零退出。

### 结论与建议
状态机在"命令级失败"（restart 失败、enablement 不匹配、门禁冲突）上恢复是健全的；**真正的残留在于"监听≠登录"
与"恢复依赖 CLI 存活/文件回滚成功"**。优先级：① `recover()` 拆分（监听恢复独立于文件回滚）；② 门禁纳入
`authorizedkeysfile`；③ README 强化"先测登录"措辞；④（增强）CLI 无关的定时自动回滚。前两项为低成本高收益，
可交 fixer 实现、oracle 复核改动。

---

## 七、复审 3（针对 oracle 发现的修复）—— 2026-11-24

本轮新增 `src/lhm/modules/ssh_auth.py`（180）+ `tests/test_ssh_auth.py`（357），再次重写 `ssh.py`（→1295）、
`checks.py`（→412），并加强 `templates/ssh-hardening.conf.tmpl`。测试 **543→773 全绿，ruff 干净**。
逐条核对第六节 oracle 发现：

| oracle 发现（原严重度） | 现状 | 证据 |
|---|---|---|
| ① `recover()` 监听恢复依赖文件回滚成功（中/高） | **已修** | `_apply_confirmed_hardening` 改为 `try/except/finally`；文件回滚在 `finally` 内 `try`，监听恢复在**嵌套 `finally`**，文件回滚抛错仍执行（`ssh.py:1234-1247`） |
| ② 生效值门禁不校验 `AuthorizedKeysFile` / 监听≠登录（中 + 固有） | **已修（超出要求）** | 新增 `ssh_auth.py` + `_admin_key_gate`：对每个管理员用 `sshd -T -C user=…,addr=…`（`ssh_auth.py:118-180`）按**连接上下文**（含 `Match` 块）求值，校验 `PubkeyAuthentication=yes`、`AuthenticationMethods` 为含 publickey 的有效链、`AuthorizedKeysFile` 精确指向托管 key（`ssh_auth.py:40-95`）；接入 pre-reload 门禁（`ssh.py:1178-1181`）与 final verify（`ssh.py:901-903`）；模板显式 `AuthorizedKeysFile .ssh/authorized_keys`（并加 `Protocol 2`/`PermitEmptyPasswords no`/`ChallengeResponseAuthentication no`/`MaxStartups`） |
| ③ `written` 标志竞态（低） | **已修** | 锁内 `_dropin_snapshot` 快照传入；`write_attempted` 写前置位；`_rollback_dropin(snapshot,candidate,backup)` 以快照 vs 当前盘面决定是否回滚（`ssh.py:413-435,1108-1157,1234-1247`） |
| ④ 恢复依赖 CLI 存活（停 socket→起服务窗口被 SIGKILL）（中/设计） | **未实现（窗口收紧）** | 仍无 `systemd-run`/`at`/watchdog，恢复靠进程 `finally`；但新增 `--job-mode=fail`、停 socket 后与重启前两次确认 `inactive`、`_require_idle_ssh_units`（`ssh.py:1185,1191-1217`） |

**`_admin_key_gate` 评价（关键进展）**：它把"仅验证存在监听端口"提升为"按管理员连接上下文验证其有效配置允许公钥登录且 key 路径正确"。
仍无法做真实密码学登录（无私钥，不可能），并诚实标注 scope "not a login test"；缺 `SSH_CONNECTION`（本地控制台）优雅降级为
loopback 上下文而非误伤 FAIL；门禁失败即 fail-closed（不关密码认证）。这是对"监听≠登录"最务实的强化。

### 本轮剩余 / 残留项
- **中（设计，未实现）· oracle ④**：CLI 无关的定时自动回滚仍缺。建议停 socket 前用 `systemd-run --on-active` 安排一个
  "登录确认后取消、否则自动 `rollback`+起 socket" 的分离任务，彻底消除"进程被杀即失联"窗口。
- **低 · `checks.py:312-323`**：`current_ssh_ports` 仍把 `ss` 不可用折叠为空集并回退 `sshd -T`（测试明确接受此回退）。
  锁定风险已被 firewall 层覆盖（空集 fail-closed、socket 状态未知 `current is None` 亦 FAIL）；残留仅"可能多放行一个
  配置了但实际未监听的端口"（无害）。`_verify_hardening` 用的是 `live_ssh_ports`（不可用→None→SKIPPED/FAIL），不受影响。
- **低 · Ed25519 子群校验（延续）**：`userkeys`/`ssh.py` 的密钥校验未再变动，ed25519 仍为结构+非零校验（stdlib 限制）。
- **低 · 代码风格**：`userkeys.py:61`、`ssh_auth.py:150` 的 `except OSError, ValueError:` 写法罕见；**已实测**在本环境
  等价于 `except (OSError, ValueError):`（捕获二者、不遮蔽名字），非缺陷，建议加括号以求标准化。

### 结论
oracle 的三条代码级发现（①②③）均已高质量修复，②的实现（连接上下文有效配置校验）超出预期；唯一仍开放的是设计级的
"CLI 无关定时回滚"（④），属较大增强，当前以收紧窗口 + 全路径 `finally` 恢复 + fail-closed 门禁缓解。未见本轮引入的新高/中危或回归。

### 验证记录（v4）
- `uv run pytest -q` → **773 passed**；`uv run ruff check` → All checks passed。
- 亲自通读 `_apply_confirmed_hardening`（`try/except/finally` 逐边界核验：成功/skip/异常/KeyboardInterrupt 均正确）、
  `_admin_key_gate`/`_effective_problems`、`ssh_auth.py`（全文）；确认 `finally` 保证全路径回滚 + 监听恢复。
- 1 路 explore agent 复审 `ssh_auth.py`/`ssh.py`/`checks.py`，结论已交叉核对。
- 确认无 `systemd-run`/`at` 调度（④未实现）。

---

## 八、复审 4 —— CLI 无关 SSH 回滚看门狗（oracle ④ 已实现）—— 2026-11-24

新增 `src/lhm/modules/ssh_watchdog.py`（538）、`ssh_session.py`（144）+ 对应测试，`ssh.py`→1775，新增 `lhm ssh-confirm TXID`
子命令；DESIGN.md/README.md 大幅补充。测试 **773→899 全绿，ruff 干净**。这实现了上一节的 ④。

### 机制（纵深防御，工程质量很高）
停 `ssh.socket` 之前，`arm()` 用 `systemd-run --on-active=600s` 调度一个**独立瞬态单元**，由 `/opt/lhm-ssh-rollback` 下
**单独安装的 CPython + 源码副本**（`-I -S -B`、源码树完整性/属主/符号链接校验）运行 `expire_watchdog` —— 不依赖原 CLI 进程/venv。
10 分钟内未确认则自动回滚 drop-in + 恢复监听。确认须 `lhm ssh-confirm TXID` **从一个可证明的新 SSH 会话**运行
（`ssh_session.py` 走 `/proc` 祖先链证明存在 cutoff tick 之后启动的 root 特权 `sshd` monitor，env 不可伪造）。状态 `/run/.../pending.json`
（tmpfs、0700/0600、root、nlink==1、O_NOFOLLOW/dir_fd、monotonic 截止时间），`systemd-run` 后用 **busctl 逐属性核验**该单元的
ExecStart/User/deadline 完全符合预期（防篡改）。

### oracle 独立裁决确认稳健的点
- **写前日志（WAL）**：`arm` 在任何变更前；每步变更前先 `record(action=…)`（`ssh.py:1606,1660,1689`），进程中途死亡可精确重建。
- **confirm 防重放/防同会话**：`/proc` 祖先链 + CLOCK_BOOTTIME cutoff（不可用 env 伪造）；root+TTY+单次确认、无 bypass；删 marker 在前、停 timer 在后 → 迟到 worker 成 no-op；未发现"确认成功后又被撤销"竞态。
- **强制依赖安全**：`arm` 前实跑独立解释器比对协议/schema/源码指纹，缺失或旧版安全 fail-closed（非锁定缺陷）。

### oracle 新发现的恢复路径缺陷（中 · 窄但可致锁定 · 建议修）
- **service-only 误报回滚成功**（`ssh.py:1256,1290-1294`）：`action=="none"` 的纯 service 模式恢复时只还原文件、不重载；
  若 sshd 在窗口内因无关原因自动重启读入了候选配置，旧认证策略未恢复而事务已清。**修复**：只要写过候选配置，恢复就重载旧配置，
  不能以"CLI 未发 reload"推断"daemon 未读候选"。
- **恢复被缺失 `/run/sshd` 卡住**（`ssh.py:682-690,807-820,918-925`）：带 `RuntimeDirectory=sshd` 的 unit 停止后 `/run/sshd` 被删，
  恢复里的 `sshd -t`/`sshd -T -C` 会失败，worker 反而不提交能重建该目录的 `start`。**修复**：恢复路径先 `ensure_privsep_dir` 再验配置。
- **一次性恢复，可恢复类失败不重试**（`ssh.py:1295-1301`、`ssh_watchdog.py:410-412`）：仅 `_RETRY`/exit 75 触发 systemd 强制重试；
  非超时的恢复失败返回 1、留 `failed` marker、一次性 timer 耗尽 → 无后续自动尝试；socket 激活且已读候选配置时即便重试也只会"拒绝操作"。
  **修复**：对查询/IO/验证等可恢复失败退避重试，并提供安全的 daemon 恢复路径。另：失败恢复的单测是**测试代码手动二次调用** expiry，
  并未证明 systemd 真会重试（`tests/test_ssh.py:2855-2862`）。

### 已文档化的设计边界（非缺陷，已在 DESIGN/README 明示）
- **reboot/掉电丢网**：`/run` + 瞬态单元不过重启；持久的 drop-in 仍在 → 重启后无自动回滚。DESIGN:114「scope is the current boot only」、
  README:208-210 已明示；如需"无带外控制台也安全"，须持久化事务 + 开机恢复单元（当前刻意不做）。
- **监听≠登录 / 端口非程序证明**：`ssh_session` 证明的是"获准账户有新 transport"，不证明它连的是目标端口（依据传入的 `SSH_CONNECTION`，
  `ssh.py:1372-1383`）。DESIGN:139-140 明示"apply 输出与 SSH_CONNECTION 都不证明公钥登录发生"。增强方向：核对该连接的内核 socket 端点而非 env。属运维责任/root 自伤，非越权绕过。
- **强制 `/opt/lhm-ssh-rollback` 依赖**：ssh-hardening 无该运行时即 fail-closed 拒绝（刻意：绝不在无独立回滚网时加固 SSH）。
  已在 DESIGN:122-130、README「Provision the SSH watchdog」、integration/Dockerfile:50-61 provision 并 probe。剩余风险仅"武装后原地升级 /opt"。

### 结论
看门狗的**核心时序（先武装后改、WAL）、确认真实性证明、共享锁语义**经 oracle 独立裁决为稳健，未发现"确认后被撤销"或"成功即锁定"的结构性漏洞。
真正的开放项集中在**自动恢复的健壮性**（上述三条中危：误报、`/run/sshd`、一次性）——它们都落在"自动网尽力而为 + 保留会话/控制台兜底"
（DESIGN 已声明）之内，不影响谨慎运维者，但建议修复以让自动网在这几类窄场景下也可靠。

### 验证记录（v5）
- `uv run pytest -q` → **899 passed**；`uv run ruff check` → All checks passed。
- 亲自通读 `ssh_watchdog.py`（全文）、`ssh_session.py`（全文）、`ssh.py` 的 `arm/record/_recover_watchdog/expire_watchdog/apply_hardening`
  时序；确认 WAL 顺序与 flock 语义。
- 1 路 explore agent 画出 arm/confirm/expire 全流程；1 次 oracle 独立裁决看门狗锁定安全。
- 核实强制 `/opt` 依赖已在 DESIGN/README/integration 文档化且无 opt-out（刻意 fail-closed）。

---

## 九、复审 5 —— 修复 oracle 的三条恢复路径缺陷 —— 2026-11-24

本轮针对第八节 oracle 的三条中危恢复缺陷做了精准修复：`ssh.py`→1907，新增 `integration/check-watchdog-retry.sh`。
测试 **899→929 全绿，ruff 干净**。逐条已逐行核实：

| 第八节 oracle 发现 | 现状 | 证据 |
|---|---|---|
| ① service-only 误报回滚成功（候选配置被无关重启读入后旧策略未恢复） | **已修** | `_recover_service`：disk 未还原→`_RecoveryDeferred`；`verify_unit`+`_validate_restored_sshd`+对 **active 服务 `reload`**（让已读候选的 sshd 重读还原后的旧配置），reload 前 `_require_original_dropin(snapshot)` 确认盘面为原快照（`ssh.py:921-960`）。socket 路径对"连接在候选期间激活 sshd"同样处理（`ssh.py:864-891`） |
| ② 恢复被缺失 `/run/sshd` 卡住 | **已修** | `_validate_restored_sshd` 先 `ensure_privsep_dir()` 重建目录，再 `sshd -t`；且因"sshd 退出码不区分语法错误与临时缺前置条件"，失败按 `_RecoveryDeferred`（重试）处理而非误 reload 或放弃（`ssh.py:655-662`） |
| ③ 一次性恢复，可恢复失败不重试 | **已修** | 新增 `_RecoveryDeferred`（待定/未验证统一走此）与 `_retryable_recovery_error`（`_RecoveryDeferred` 或非结构性 `OSError` 可重试；`EACCES/EPERM/ELOOP/ENOTDIR/EISDIR/EINVAL/EROFS` 等不重试）；`_recover_socket`/`_recover_service` 对可重试失败返回 `_RETRY`(=75)→systemd `RestartForceExitStatus=75` 每 5s 重跑 worker；`_recover_watchdog` 正确传播 disk/runtime 的 `_RETRY`/1/0；`expire_watchdog` 对锁竞争(`BlockingIOError`)、未到期、可重试异常均 `_RETRY`（`ssh.py:918,959,1367-1456`）。新增 opt-in `integration/check-watchdog-retry.sh` 用隔离 user-manager + stub **实证 systemd 在 exit 75 时真的重跑**（回应 oracle"单测仅手动二次调用、未证明重试"） |

**重试语义评价**：分类合理（结构性/权限错误不重试避免空转；瞬态/未验证重试）；`StartLimitIntervalSec=0` 允许无限 5s 重试——
作为"尽力恢复 SSH"的安全网可接受（运维可从 journal 察觉），返回 1 的硬失败则停止等待人工。未见本轮引入的新高/中危或回归。

### 当前开放项（均为已文档化的设计边界或已知 stdlib 限制，无代码级锁定缺陷）
- reboot/掉电丢网（DESIGN:114「current boot only」）；SSH_CONNECTION 不证明目标端口（DESIGN:139-140，增强方向=校验连接的内核 socket）；
  强制 `/opt` 依赖（已 provision 文档化）。
- Ed25519 仅结构+非零校验，无子群点校验（stdlib 限制；RSA≥1024-bit、ECDSA on-curve 已校验，见 `_ecdsa_point_ok`）。
- 代码风格：`userkeys.py:61`、`ssh_auth.py:150` 的 `except OSError, ValueError:`（实测本环境等价标准元组写法，建议加括号）。

### 结论
至此，**初版 v1 → 复审 5（v6）七轮迭代中提出的全部可修代码级发现（含两次 oracle 裁决的恢复路径缺陷）均已修复**；
看门狗自动恢复网在 oracle 指出的几类窄场景下也已健壮（重建 privsep 目录、reload 已读候选的 daemon、可重试退避）。
剩余项仅为 DESIGN/README 明示的设计边界与 stdlib 限制。代码库在"失败路径恢复、密钥、原子性、锁定防护"上达到了很高的成熟度与自洽度。

### 验证记录（v6）
- `uv run pytest -q` → **929 passed**；`uv run ruff check` → All checks passed。
- 亲自通读 `_recover_socket`/`_recover_service`/`_validate_restored_sshd`/`_retryable_recovery_error`/`_recover_watchdog`/`expire_watchdog`
  的重试与恢复状态机；核对 `_RETRY`(75) 与 systemd `RestartForceExitStatus` 的闭环、`_RecoveryDeferred` 分类、reload-active-service 的快照前置校验。
- 核实 `integration/check-watchdog-retry.sh` 为 opt-in、非 root、隔离 user-manager、永不触碰系统 manager 或真实看门狗。
- 确认本批 `checks.py`/`files.py`/`runner.py`/模板为累计 diff（前几轮已审），本轮增量集中在 `ssh.py` 恢复路径。

---

## 十、最新核验补记：第八节三项已解决

1. **service-only 误报回滚成功：已解决。** 一旦尝试写入候选 drop-in，恢复就不以 CLI 是否已提交 reload 为准；验证旧快照后 reload 活跃服务或 start 非活跃服务，再检查原监听端点。
   见 [`ssh.py:1382–1426`](../../src/lhm/modules/ssh.py#L1382-L1426)、[`ssh.py:937–953`](../../src/lhm/modules/ssh.py#L937-L953) 和 [写入后中断回归测试](../../tests/test_ssh.py#L2787-L2859)。
   socket 分支也会在守卫通过后 reload 已激活的服务（[`ssh.py:856–892`](../../src/lhm/modules/ssh.py#L856-L892)）。
2. **缺失 `/run/sshd` 阻断恢复：已解决。** 恢复在运行 `sshd -t` 前重建缺失目录，拒绝不安全的目录。`sshd -t` 非零（含 `255`）不区分语法错误与临时前置条件缺失，因此该次验证返回待重试，不操作 daemon。
   见 [`ssh.py:655–662`](../../src/lhm/modules/ssh.py#L655-L662)、[`ssh.py:1041–1070`](../../src/lhm/modules/ssh.py#L1041-L1070) 和 [注入 255 的回归测试](../../tests/test_ssh.py#L3186-L3224)。
3. **可恢复失败不重试：已解决。** 暂态 `EIO`（如 journal 读取、drop-in 恢复或 privsep 权限调整）保留事务、返回 `75`；权限类 `OSError` 或确认的外部冲突等硬失败返回 `1`。仅 `75` 配置为 5 秒后重试。
   见 [`ssh.py:97–111`](../../src/lhm/modules/ssh.py#L97-L111)、[`ssh.py:1385–1453`](../../src/lhm/modules/ssh.py#L1385-L1453) 和 [单元属性](../../src/lhm/modules/ssh_watchdog.py#L409-L412)；
   回归覆盖 [journal EIO](../../tests/test_ssh_watchdog_process.py#L153-L170)、[drop-in EIO](../../tests/test_ssh.py#L3042-L3078) 和 [privsep EIO/EPERM](../../tests/test_ssh.py#L2911-L2936)。

**最新验证基线：929 个测试通过，Ruff 通过。** 单测验证 worker 状态及配置，不证明 systemd 实际调度或恢复 SSH。
第九节的「实证」指 [可选 stub 检查](../../integration/check-watchdog-retry.sh#L42-L58) 的用途，不是本轮运行结果；
脚本不能证实 user manager 已隔离。本轮未运行该检查、真实 systemd 看门狗或 Docker 集成。
