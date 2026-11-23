# lhm 代码库评审：架构 / 可靠性 / 安全

- 日期：2026-11-23
- 范围：`src/lhm/**`、`templates/**`（对照 `DESIGN.md` / `README.md`）
- 方法：静态审查 + 244 单测复跑（全绿）；无真实系统调用

安全关键工具（以 root 运行，承担 SSH/防火墙/审计等变更）。整体工程质量**高于同类脚本一个档次**：
清晰的 DESIGN.md、244 个单测全绿、统一的 Runner/确认/备份抽象。但在"失败路径恢复"和
"非 shell 模板的取值校验"上存在系统性缺口，其中几条可导致生产服务器 SSH 失联。

---

## 一、值得肯定的设计

- **命令执行安全**：全仓无 `shell=True`/`os.system`/`eval`；所有命令走列表参数；超时结构性强制（`runner.py:69-75`）。
- **原子写 + 无密钥泄露窗口**：`mkstemp`(0600)+fsync+`os.replace`，密钥文件内容不经过 world-readable 中间态（`files.py:29-45`）。
- **Shell 模板注入防护到位**：`render_shell_template` 只替换 `${lower}` 占位符、保留 shell `$VAR`/`$(...)`，并拒绝含单引号/控制字符的值（`files.py:126-148`）。
- **幂等优先 + 双确认 + 非 TTY fail-closed + dry-run**，且 `LHM_CONFIRM_BYPASS` 仅跳过两次 y/N、不绕过幂等与 dry-run（已在 11 个模块核对）。
- **审计不可变性按 DESIGN 规则 8 精确实现**（`audit.py:143-163`：仅当文件一致且 `auditctl -s` 确认 `enabled 2` 时才降级为 warning）。
- **fail2ban 激活/加载顺序正确**，nftables 显式安装（补上仅 Recommends 的坑），`jail.local` 从不写入（`fail2ban.py:18,237-241`）。
- **SSH 公钥做真实 wire-format 校验**（解 base64、比对 blob 内算法名，非前缀匹配，`ssh.py:48-66`）。

## 二、架构层面的结构性隐患

1. **dry-run"零写入"不是结构性保证**。`Runner` 集中拦截 subprocess，但文件写入
   （`write_dropin`/`append_marked`/`restrict`/`chmod`/`mkdir`）完全没有集中守卫，靠每个模块手写
   `if runner.dry_run: return` 早返回（如 `sysctl.py:99`）。漏写一处即在 dry-run 中真实落盘。
   目前有每模块磁盘级测试兜底（`not dropin.exists()`），但新增模块/新写点会静默回归。
   **建议**：让写入层感知 dry-run（无写 + 记录 planned），把保证下沉到 `files.py`。

2. **`render_template`（非 shell 路径）对取值零校验**（`files.py:117`）。与 `render_shell_template` 不同，
   流入 systemd unit / 配置文件的值（backup target、fail2ban `${hostname}`、`keep`）只靠各模块临时校验，
   而这些校验不完整（见下）。这是一整类注入面，建议统一在该函数做引号/控制字符/换行校验。

3. **root/dry-run 门禁只在 CLI handler**（`cli.py:801,851`），`module.apply()` 自身无校验——被库/直接调用时绕过。
   对 CLI 工具可接受，但应在文档/类型上标注"模块信任调用方"。

4. **"自动回滚"不一致**。部分失败自动回滚（ssh `-t`/`-T` 门禁、sandbox restart），但更多失败只打印
   `rollback hint` 不回滚（ssh reload/restart/最终 verify、firewall enable 后 verify、audit load）。
   README 给人的"验证后失败即回滚"印象强于实现。

## 三、可靠性 / 锁定风险（按严重度）

### 高

- `ssh.py:529-548` — socket 禁用成功后 `_restart` 两单元均失败 → socket 已禁、服务未起、drop-in 仍在、
  无回滚无重启 = **SSH 彻底失联且无自动恢复**。
- `ssh.py:337-345` — 生效值门禁遗漏 `AllowUsers`/`AuthenticationMethods`/`KbdInteractiveAuthentication`；
  模板写入 `AllowUsers`，若更早 drop-in 的 `AllowUsers` 生效且不含管理员，门禁报 OK 后 reload →
  **锁定且"verify OK"**。
- `firewall.py:50-56` — 当 `ss` 与 `sshd -T` 都探不到端口时，只放行 22345 便继续 `default deny`+`enable`，
  仍在 22 端口的主机被锁，仅打印 warning，**未 fail-closed**。

### 中

- `ssh.py:540-555` / `:550-553` — `-T` 门禁通过后的 reload/restart/最终 verify/异常路径均不回滚 drop-in（仅提示）。
- `cli.py:808` + `confirm.py:32` — 非 TTY 中止返回 `Status.SKIPPED`，而 `_run_module` 只有 `FAIL` 才非零 →
  **非 TTY 下 `apply`/`apply all` 什么都不做却退出 0**，自动化无法区分"已加固"与"因非 TTY 被拒"。
  建议中止用非零退出码。
- `ssh.py:54-63` — 公钥校验只验类型名与 `len>=32`，伪造 blob（正确类型名+随机字节）可通过 →
  在一把无法登录的 key 上关闭密码认证 → 锁定。
- `runner.py:46-52` — 超时只杀直接子进程，未用进程组；`apt-get` 等孙进程在超时后继续写入。

### 低

- `files.py:87` — marked-block 幂等键只看 marker 是否存在：端口/webhook 变更后旧块内容永不更新
  （drop-in 走内容比对无此问题）。
- `backup.py(core):44,75` — `.bak.N` 选名 TOCTOU（并发 apply 互相覆盖备份）；rollback 原地覆盖非 temp+rename
  （崩溃可截断 sshd drop-in）；拷贝中途崩溃留下残缺 `.bak` 会被 `newest_backup` 选中。
- `runner.py:79` — dry-run 合成 rc=0，使 verify 步骤"成功"从未真正观测。
- `ssh.py:394`（`checks.py:133`）— `ss` 不可用时报 FAIL 而非 SKIPPED（与 DESIGN:86 矛盾）；
  且不确认监听进程确为 sshd。
- `firewall.py:37,161` — `startswith("ALLOW")` 误配 `ALLOW FWD`，verify 可能假 OK。

## 四、安全问题（按严重度）

### 中

- **webhook 密钥泄露**：`validate_webhook` 的多处错误消息用 `{url!r}` 内嵌完整 URL（含 token），
  经 StepResult 打到 stderr/日志（`alert.py:31-41`）；且 `--verbose` 下 `colors.file_change(new=content)`
  把含 `WEBHOOK_URL=...` 的整脚本打到 stdout（`files.py:71`）。unit 文件本身干净。
  建议错误消息只回显 host、verbose 对密钥脚本脱敏。
- **backup target 校验不挡空格/`%`**：`validate_target` 拒 `..`/`/`/`/home`/`/etc`/单引号/控制字符，
  但**允许空格和 `%`**（`backup.py:29-47`）。含空格 → systemd `ReadWritePaths=` 被拆成两条路径、
  shell 轮转 glob 失配；含 `%` → systemd specifier 展开。沙箱可指向别处。

### 低

- `backup.py:35-42` — `//etc/backup`（`Path("//")≠Path("/")`）及符号链接父目录（未 `resolve()`）
  可绕过 `/etc`//`home` 保护。
- `fail2ban.py` — `bantime=0`/`maxretry=0` 被接受 → 零时长封禁/无限重试（fail-open），无下限校验；
  `maxretry=3h` 经 `TIME_RE` 后 `int()` 抛未友好处理的 `ValueError`。
- `cli.py:755-790` — rollback 无路径白名单，`LHM_CONFIRM_BYPASS=1`+root 可把任意 `FILE.bak`
  还原到 `FILE`（`..` 已挡）。
- `confirm.py:22` — `.strip()=="1"` 接受 `" 1 "`/`"1\n"`，比文档"精确 1"宽松。
- `backup.py(core):31` — 0600/0700 密钥的 `.bak` 在 `copy2` 期间有短暂 ~0644 窗口
  （受父目录权限约束，影响小）。

## 五、建议修复优先级

1. **SSH 失败恢复（最高）**：socket 禁用后 restart 失败要重新 `enable --now` socket 或回滚 drop-in；
   `-T` 门禁通过后的所有失败路径统一 `_rollback_dropin()`（`ssh.py:529-555`）。
2. **门禁覆盖 AllowUsers**：把 `allowusers`（及 authenticationmethods）纳入 `_effective_problems`，
   并校验管理员在 allowusers 内（`ssh.py:337-345`）。
3. **firewall 未知端口时 fail-closed**：探不到任何 SSH 端口时中止 `deny+enable`（`firewall.py:50-56`）。
4. **停止泄露 webhook URL**（错误消息/verbose）；**校验 backup target**（拒空格/`%`），
   最好在 `render_template` 层统一取值校验。
5. **非 TTY 中止用非零退出码**；公钥校验增强或在 README 更强调"先另开会话测 key 登录"。

---

## 验证说明

- `uv run pytest -q` → 244 passed。
- 全仓 `grep` 确认无 `shell=True`/`os.system`/`eval`/`exec`。
- 头号 SSH 锁定风险（`ssh.py:337-345`、`:529-555`）、`files.py`、`runner.py`、`backup.py`、
  `alert.py`、`audit.py` 均经人工逐行核对；其余模块经分区侦察定位到 file:line。
