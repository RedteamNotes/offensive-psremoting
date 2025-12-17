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

## 帮助菜单

```zsh
┌──(kali㉿kali)-[~/RedteamNotes/offensive-psremoting]
└─$ opsr -h
usage: opsr [-h] [-v] [-t TARGET] [-u USERNAME] [-p PASSWORD] [--password-stdin] [--password-file PASSWORD_FILE] [--no-pass] [--ccache CCACHE] [-H NTLM_HASH]
            [-endpoint ENDPOINT] [-a {negotiate,ntlm,kerberos,basic,credssp,certificate}] [--ssl] [--port PORT] [--path PATH] [--cert-validation CERT_VALIDATION]
            [--connection-timeout CONNECTION_TIMEOUT] [--op-timeout OP_TIMEOUT] [--rd-timeout RD_TIMEOUT] [--proxy PROXY] [--no-proxy] [--encryption {auto,always,never}]
            [--locale LOCALE] [--data-locale DATA_LOCALE] [--reconnection-retries RECONNECTION_RETRIES] [--reconnection-backoff RECONNECTION_BACKOFF] [--negotiate-delegate]
            [--negotiate-hostname-override NEGOTIATE_HOSTNAME_OVERRIDE] [--negotiate-service NEGOTIATE_SERVICE] [--negotiate-send-cbt] [--no-negotiate-send-cbt]
            [--certificate-pem CERTIFICATE_PEM] [--certificate-key-pem CERTIFICATE_KEY_PEM] [--credssp-auth-mechanism {auto,ntlm,kerberos}]
            [--credssp-minimum-version CREDSSP_MINIMUM_VERSION] [--credssp-disable-tlsv1-2] [-verbose] [-debug]

PSRP/WSMan (WinRM) interactive PowerShell Remoting REPL client (raw/struct/auto).

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -t, --target TARGET   Target host/IP (default: env SERVER)
  -u, --username USERNAME
                        Username, e.g. 'DOMAIN\user' or 'user@domain' (default: env USER)
  -p, --password PASSWORD
                        Password. Use '-' to prompt. (default: env PASS)
  --password-stdin      Read password from stdin (first line). Overrides -p.
  --password-file PASSWORD_FILE
                        Read password from file (first line). Overrides -p.
  --no-pass             Do not supply password (meaningful with kerberos/negotiate/certificate).
  --ccache CCACHE       Kerberos ccache path (export as KRB5CCNAME).
  -H, --hash NTLM_HASH  Not supported in this tool (placeholder only).
  -endpoint, --endpoint ENDPOINT
                        Session configuration name (JEA endpoint). (default: env ENDPOINT)
  -a, --auth {negotiate,ntlm,kerberos,basic,credssp,certificate}
                        Auth protocol. (default: env AUTH or negotiate)
  --ssl                 Use SSL/TLS (default: env SSL=1)
  --port PORT           Port override (default: 5986 if --ssl else 5985).
  --path PATH           WinRM path (default: wsman).
  --cert-validation CERT_VALIDATION
                        validate|ignore|/path/to/ca.pem (default: validate)
  --connection-timeout CONNECTION_TIMEOUT
                        HTTP connection timeout seconds (default: 30)
  --op-timeout OP_TIMEOUT
                        WSMan operation timeout seconds (default: 15)
  --rd-timeout RD_TIMEOUT
                        Read timeout seconds (default: 30)
  --proxy PROXY         Proxy URL (e.g. http://127.0.0.1:8080).
  --no-proxy            Ignore environment proxy and connect directly.
  --encryption {auto,always,never}
                        Message encryption policy (default: auto).
  --locale LOCALE       WSMan Locale (default: en-US)
  --data-locale DATA_LOCALE
                        WSMan DataLocale (default: same as locale)
  --reconnection-retries RECONNECTION_RETRIES
                        Retries on connection problem (default: 0)
  --reconnection-backoff RECONNECTION_BACKOFF
                        Backoff seconds base (default: 2.0)
  --negotiate-delegate  Negotiate delegation (Kerberos only).
  --negotiate-hostname-override NEGOTIATE_HOSTNAME_OVERRIDE
                        Override hostname used for SPN calculation.
  --negotiate-service NEGOTIATE_SERVICE
                        Override service part of SPN (default: WSMAN).
  --negotiate-send-cbt  Bind CBT on HTTPS (default: True).
  --no-negotiate-send-cbt
                        Disable CBT binding.
  --certificate-pem CERTIFICATE_PEM
                        Certificate PEM (for -auth certificate).
  --certificate-key-pem CERTIFICATE_KEY_PEM
                        Certificate key PEM (for -auth certificate).
  --credssp-auth-mechanism {auto,ntlm,kerberos}
                        CredSSP sub-auth mechanism (default: auto).
  --credssp-minimum-version CREDSSP_MINIMUM_VERSION
                        CredSSP minimum server version (default: 2).
  --credssp-disable-tlsv1-2
                        Allow insecure TLSv1.0 for CredSSP (default: False).
  -verbose, --verbose   Verbose client-side logs.
  -debug, --debug       Debug mode: print traceback on errors.

Examples:
  opsr -t 192.168.24.155 -a negotiate -u 'WORKGROUP\administrator' -p -
  opsr -t 192.168.24.155 -a ntlm -u 'DOMAIN\user' -p -
  opsr -t server04.megabank.local --ssl --cert-validation ignore -a negotiate -u 'MEGABANK\s.helmer' -p -
  opsr -t server04.megabank.local -a kerberos -u 'MEGABANK\s.helmer' --ccache /tmp/krb5cc_1000 --no-pass
```

## 示例

```zsh
┌──(kali㉿kali)-[~/RedteamNotes/aptlabs]
└─$ opsr -t 192.168.20.15 -u adfs_svc -p 'S3cur!ty' -a negotiate

      ,pW"Wq.  ,pP"Ybd `7MMpdMAo.`7Mb,od8 
     6W'   `Wb 8I   `"   MM   `Wb  MM' "' 
     RE     DT `EAMNo.   TE    S8  MM     
     YA.   ,A9 L.   I8   MM   ,AP  MM     
      `Ybmd9'  M9mmmP'   MMbmmd' .JMML.   
                         MM               
                       .JMML.  
                  
        Offensive PSRemoting  v0.1.4

https://github.com/RedteamNotes/offensive-psremoting
By @RedteamNotes

opsr started. Input :help for help.
[INFO] mode=auto raw_disabled_by_nolang=False allow_external=True
[INFO] verbose=False debug=False
opsr(auto)> :help
opsr local commands:
  :help
  :mode auto|raw|struct
  :cmds [pattern]         list allowed commands
  :info <name>            show command info (client-side formatting)
  :dump <name>            dump all properties from Get-Command <name>
  :endpoint <name>        set endpoint and reconnect
  :reconnect              reconnect
  :external on|off         struct-mode .exe shortcut
  :ver
  :quit
opsr(auto)> get-command
[ERROR] The syntax is not supported by this runspace. This can occur if the runspace is in no-language mode.
[INFO] raw/script-text is blocked by NoLanguage JEA runspace; fallback to struct (Command+Parameters).
Clear-Host
Exit-PSSession
Get-AsciiArt
get-childitem
Get-Command
Get-FormatData
Get-Help
Get-NetIPAddress
Get-ProcessID
Get-ProcessName
Invoke-CommandCMD
Measure-Object
Out-Default
Select-Object
Get-Member
Select-Object
opsr(auto)> :info Get-AsciiArt
Name: Get-AsciiArt
Type: Function
Source/Module: 
Definition:

    param([string]$type='coffee')
$coffeebreak=@"
         {
      {   }
       }_{ __{
    .-{   }   }-.
   (   }     {   )
   |`-.._____..-'|
   |             ;--.
   |            (__  \
   |             | )  )
   |             |/  /
   |             /  /   
   |            (  /
   \             y'
    `-.._____..-'
"@
$smokebreak=@"
                   (  )/  
                    )(/
 ________________  ( /)
()__)____________))))) 
"@
    $art=switch($type){
        coffee {$coffeebreak}
        smoke {$smokebreak}
    }
    if(!$art){$art=$type}
    $ExecutionContext.InvokeCommand.ExpandString($art)
--------------------------------------------------
opsr(auto)> 
```

## 工具脚本

```bash
python3 tools/print_versions.py
```

输出当前 Python 与依赖版本，便于在比赛/演练报告中记录环境。

## License

MIT
