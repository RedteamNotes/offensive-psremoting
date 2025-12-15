# Offensive PSRemoting

一个基于 **PSRP/WSMan（WinRM）** 的交互式 PowerShell Remoting REPL 客户端，提供 `raw / struct / auto` 三种执行模式，便于在不同受限环境下进行更稳定的远程交互、命令枚举与排错。

> 合法合规声明：本项目仅用于**你拥有明确授权**的系统管理、竞赛环境、实验室与安全测试。禁止用于任何未授权访问。

## 特性

- **三种执行模式**
  - `raw`：将整行作为 PSRP 脚本文本发送（体验更接近原生）
  - `struct`：按 Cmdlet + Parameters 结构化下发（对受限环境更友好）
  - `auto`：先 raw，遇到 NoLanguage 语法受限自动回退 struct
- **本地辅助命令**
  - `:cmds` 列出允许命令（支持过滤）
  - `:info / :dump` 获取 `Get-Command <name>` 并在客户端侧格式化展示
  - `:endpoint` 切换 Session Configuration（JEA endpoint）并重连
  - `:reconnect` 重连
  - `:ver` 查看当前连接/模式状态
- **版本与横幅**
  - `opsr -v` / `opsr --version` 查看版本
  - 启动时显示 `opsr` ASCII 横幅（可用于比赛截图/报告）

## 安装

推荐使用 `pipx`（隔离环境、命令全局可用）：

```bash
pipx install offensive-psremoting
# 或在仓库目录中安装
pipx install .

# 卸载
pipx uninstall offensive-psremoting
```

也可以使用 venv：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## 运行

```bash
opsr -h
opsr -v

# 示例：Negotiate（行为更接近 PowerShell 的 -Authentication Negotiate）
opsr -t 192.168.24.155 -a negotiate -u 'WORKGROUP\administrator' -p -

# 进入后输入 :help 查看本地命令
```

## 工具脚本

```bash
python3 tools/print_versions.py
```

输出当前 Python 与依赖版本，便于在比赛/演练报告中记录环境。

## License

MIT
