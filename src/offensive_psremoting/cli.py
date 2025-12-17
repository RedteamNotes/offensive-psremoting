#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Offensive PSRemoting (opsr)
PSRP/WSMan (WinRM) interactive PowerShell Remoting REPL client.

Modes:
  - auto  : try raw first; if NoLanguage blocks script syntax -> fallback to struct automatically
  - raw   : send whole line as PSRP script text (best "Windows-like" when language is allowed)
  - struct: cmdlet-level pipeline (Command + Parameters), most compatible with JEA/NoLanguage

Local commands:
  :help
  :mode auto|raw|struct
  :cmds [pattern]
  :info <name>
  :dump <name>
  :endpoint <name>
  :reconnect
  :ver
  :quit

Env (preferred; legacy RTN_* also supported as fallback):
  SERVER, USER, PASS, ENDPOINT, AUTH, SSL(0|1), OP_TIMEOUT, RD_TIMEOUT
"""

from __future__ import annotations

import argparse
import getpass
import inspect
import os
import re
import shlex
import sys
import traceback
from typing import Any, Dict, List, Optional, Tuple

try:
    import readline  # optional
except Exception:
    readline = None

from pypsrp.wsman import WSMan
from pypsrp.powershell import RunspacePool, PowerShell

from . import __version__

APP_NAME = "Offensive PSRemoting"
CMD_NAME = "opsr"

BANNER = r"""

      ,pW"Wq.  ,pP"Ybd `7MMpdMAo.`7Mb,od8 
     6W'   `Wb 8I   `"   MM   `Wb  MM' "' 
     8M     M8 `YMMMa.   MM    M8  MM     
     YA.   ,A9 L.   I8   MM   ,AP  MM     
      `Ybmd9'  M9mmmP'   MMbmmd' .JMML.   
                         MM               
                       .JMML.  
                  
        Offensive PSRemoting  v0.1.4
     
"""

def getenv2(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key)
    if v is not None:
        return v
    v2 = os.getenv(f"RTN_{key}")
    if v2 is not None:
        return v2
    return default

def env_bool(key: str, default: bool = False) -> bool:
    v = getenv2(key, None)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "$true")

def build_parser() -> argparse.ArgumentParser:
    epilog = r"""
Examples:
  opsr -t 192.168.24.155 -a negotiate -u 'WORKGROUP\administrator' -p -
  opsr -t 192.168.24.155 -a ntlm -u 'DOMAIN\user' -p -
  opsr -t server04.megabank.local --ssl --cert-validation ignore -a negotiate -u 'MEGABANK\s.helmer' -p -
  opsr -t server04.megabank.local -a kerberos -u 'MEGABANK\s.helmer' --ccache /tmp/krb5cc_1000 --no-pass
"""
    p = argparse.ArgumentParser(
        prog=CMD_NAME,
        description="PSRP/WSMan (WinRM) interactive PowerShell Remoting REPL client (raw/struct/auto).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog.strip(),
    )
    p.add_argument("-v", "--version", action="version", version=f"%(prog)s 0.1.4")

    p.add_argument("-t", "--target", dest="target", default=getenv2("SERVER", "127.0.0.1"),
                   help="Target host/IP (default: env SERVER)")
    p.add_argument("-u", "--username", dest="username", default=getenv2("USER", r"WORKGROUP\administrator"),
                   help=r"Username, e.g. 'DOMAIN\user' or 'user@domain' (default: env USER)")

    p.add_argument("-p", "--password", dest="password", default=getenv2("PASS", None),
                   help="Password. Use '-' to prompt. (default: env PASS)")
    p.add_argument("--password-stdin", action="store_true", default=False,
                   help="Read password from stdin (first line). Overrides -p.")
    p.add_argument("--password-file", default=None,
                   help="Read password from file (first line). Overrides -p.")
    p.add_argument("--no-pass", action="store_true", default=env_bool("NO_PASS", False),
                   help="Do not supply password (meaningful with kerberos/negotiate/certificate).")
    p.add_argument("--ccache", default=getenv2("CCACHE", None),
                   help="Kerberos ccache path (export as KRB5CCNAME).")

    # Placeholder ONLY (not supported)
    p.add_argument("-H", "--hash", dest="ntlm_hash", default=None,
                   help="Not supported in this tool (placeholder only).")

    p.add_argument("-endpoint", "--endpoint", default=(getenv2("ENDPOINT", "") or "").strip() or None,
                   help="Session configuration name (JEA endpoint). (default: env ENDPOINT)")

    p.add_argument("-a", "--auth", default=getenv2("AUTH", "negotiate"),
                   choices=["negotiate", "ntlm", "kerberos", "basic", "credssp", "certificate"],
                   help="Auth protocol. (default: env AUTH or negotiate)")
    p.add_argument("--ssl", action="store_true", default=env_bool("SSL", False),
                   help="Use SSL/TLS (default: env SSL=1)")
    p.add_argument("--port", type=int, default=None,
                   help="Port override (default: 5986 if --ssl else 5985).")
    p.add_argument("--path", default=getenv2("WSMAN_PATH", "wsman"),
                   help="WinRM path (default: wsman).")

    p.add_argument("--cert-validation", default=getenv2("CERT_VALIDATION", "validate"),
                   help="validate|ignore|/path/to/ca.pem (default: validate)")
    p.add_argument("--connection-timeout", type=int, default=int(getenv2("CONNECTION_TIMEOUT", "30")),
                   help="HTTP connection timeout seconds (default: 30)")
    p.add_argument("--op-timeout", type=int, default=int(getenv2("OP_TIMEOUT", "15")),
                   help="WSMan operation timeout seconds (default: 15)")
    p.add_argument("--rd-timeout", type=int, default=int(getenv2("RD_TIMEOUT", "30")),
                   help="Read timeout seconds (default: 30)")
    p.add_argument("--proxy", default=getenv2("PROXY", None),
                   help="Proxy URL (e.g. http://127.0.0.1:8080).")
    p.add_argument("--no-proxy", action="store_true", default=env_bool("NO_PROXY", False),
                   help="Ignore environment proxy and connect directly.")
    p.add_argument("--encryption", choices=["auto", "always", "never"], default=getenv2("ENCRYPTION", "auto"),
                   help="Message encryption policy (default: auto).")

    p.add_argument("--locale", default=getenv2("LOCALE", "en-US"),
                   help="WSMan Locale (default: en-US)")
    p.add_argument("--data-locale", default=getenv2("DATA_LOCALE", None),
                   help="WSMan DataLocale (default: same as locale)")

    p.add_argument("--reconnection-retries", type=int, default=int(getenv2("RECONNECTION_RETRIES", "0")),
                   help="Retries on connection problem (default: 0)")
    p.add_argument("--reconnection-backoff", type=float, default=float(getenv2("RECONNECTION_BACKOFF", "2.0")),
                   help="Backoff seconds base (default: 2.0)")

    p.add_argument("--negotiate-delegate", action="store_true", default=env_bool("NEGOTIATE_DELEGATE", False),
                   help="Negotiate delegation (Kerberos only).")
    p.add_argument("--negotiate-hostname-override", default=getenv2("NEGOTIATE_HOSTNAME_OVERRIDE", None),
                   help="Override hostname used for SPN calculation.")
    p.add_argument("--negotiate-service", default=getenv2("NEGOTIATE_SERVICE", None),
                   help="Override service part of SPN (default: WSMAN).")
    p.add_argument("--negotiate-send-cbt", dest="negotiate_send_cbt", action="store_true",
                   default=env_bool("NEGOTIATE_SEND_CBT", True),
                   help="Bind CBT on HTTPS (default: True).")
    p.add_argument("--no-negotiate-send-cbt", dest="negotiate_send_cbt", action="store_false",
                   help="Disable CBT binding.")

    p.add_argument("--certificate-pem", default=getenv2("CERTIFICATE_PEM", None),
                   help="Certificate PEM (for -auth certificate).")
    p.add_argument("--certificate-key-pem", default=getenv2("CERTIFICATE_KEY_PEM", None),
                   help="Certificate key PEM (for -auth certificate).")

    p.add_argument("--credssp-auth-mechanism", choices=["auto", "ntlm", "kerberos"],
                   default=getenv2("CREDSSP_AUTH_MECHANISM", "auto"),
                   help="CredSSP sub-auth mechanism (default: auto).")
    p.add_argument("--credssp-minimum-version", type=int, default=int(getenv2("CREDSSP_MINIMUM_VERSION", "2")),
                   help="CredSSP minimum server version (default: 2).")
    p.add_argument("--credssp-disable-tlsv1-2", action="store_true", default=env_bool("CREDSSP_DISABLE_TLSV1_2", False),
                   help="Allow insecure TLSv1.0 for CredSSP (default: False).")

    p.add_argument("-verbose", "--verbose", action="store_true", default=env_bool("VERBOSE", False),
                   help="Verbose client-side logs.")
    p.add_argument("-debug", "--debug", action="store_true", default=env_bool("DEBUG", False),
                   help="Debug mode: print traceback on errors.")
    return p

MAX_STR = int(getenv2("MAX_STR", "3000"))
MAX_ITEMS = int(getenv2("MAX_ITEMS", "300"))
MAX_DEPTH = int(getenv2("MAX_DEPTH", "5"))

SWITCH_HINTS = {
    "get-command": {"all", "listimported", "showcommandinfo", "syntax"},
    "get-help": {"full", "online", "examples", "detailed", "showwindow"},
    "select-object": {"unique"},
    "measure-object": {"average", "sum", "maximum", "minimum"},
}

SAFE_EXTERNAL_RE = re.compile(r'^[A-Za-z0-9_\-./:\\ ]+$')

def norm(s: str) -> str:
    return (s or "").strip().lower()

def to_bool(v: str):
    if v is None:
        return None
    vv = v.strip().lower()
    if vv in ("$true", "true", "1", "yes", "y"):
        return True
    if vv in ("$false", "false", "0", "no", "n"):
        return False
    return None

def parse_value(v: str):
    if v is None:
        return None
    b = to_bool(v)
    if b is not None:
        return b
    if "," in v and not (v.startswith('"') or v.startswith("'")):
        parts = [p for p in (x.strip() for x in v.split(",")) if p]
        if len(parts) > 1:
            return parts
    return v

def split_by_top_level(s: str, sep: str) -> List[str]:
    parts, buf = [], []
    in_squote = False
    in_dquote = False
    for ch in s:
        if ch == "'" and not in_dquote:
            in_squote = not in_squote
        elif ch == '"' and not in_squote:
            in_dquote = not in_dquote

        if ch == sep and not in_squote and not in_dquote:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
        else:
            buf.append(ch)

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts

def parse_stage(stage: str) -> Tuple[Optional[str], Dict[str, Any], List[str]]:
    tokens = shlex.split(stage)
    if not tokens:
        return None, {}, []

    cmd = tokens[0]
    cmd_n = norm(cmd)
    switch_set = SWITCH_HINTS.get(cmd_n, set())

    params: Dict[str, Any] = {}
    args: List[str] = []

    i = 1
    while i < len(tokens):
        t = tokens[i]

        if "=" in t and not t.startswith("-"):
            k, v = t.split("=", 1)
            params[k] = parse_value(v)
            i += 1
            continue

        if t.startswith("-") and (("=" in t) or (":" in t)):
            if "=" in t:
                k, v = t.lstrip("-").split("=", 1)
            else:
                k, v = t.lstrip("-").split(":", 1)
            params[k] = parse_value(v)
            i += 1
            continue

        if t.startswith("-"):
            k = t.lstrip("-")
            k_n = norm(k)

            if k_n in switch_set:
                params[k] = True
                i += 1
                continue

            if i + 1 >= len(tokens):
                params[k] = True
                i += 1
                continue

            nxt = tokens[i + 1]
            if nxt.startswith("-") or ("=" in nxt and not nxt.startswith("-")):
                params[k] = True
                i += 1
                continue

            params[k] = parse_value(nxt)
            i += 2
            continue

        args.append(t)
        i += 1

    return cmd, params, args

def shorten(s: str) -> str:
    if len(s) <= MAX_STR:
        return s
    return s[:MAX_STR] + " ... (truncated)"

def is_psrp_object(obj: Any) -> bool:
    return hasattr(obj, "adapted_properties") or hasattr(obj, "extended_properties")

def extract_props(obj: Any) -> Dict[str, Any]:
    props: Dict[str, Any] = {}
    ap = getattr(obj, "adapted_properties", None)
    if isinstance(ap, dict):
        props.update(ap)
    ep = getattr(obj, "extended_properties", None)
    if isinstance(ep, dict):
        for k, v in ep.items():
            if k not in props:
                props[k] = v
    if not props:
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict):
            for k, v in d.items():
                if k.startswith("_"):
                    continue
                props[k] = v
    return props

def stringify(v: Any, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        return "<max-depth>"

    if v is None:
        return "None"

    if is_psrp_object(v):
        p = extract_props(v)
        name = p.get("Name") or p.get("name")
        if name is not None and len(p) <= 3:
            return f"<PSObject Name={name}>"
        return f"<PSObject keys={list(p.keys())[:25]}>"

    if isinstance(v, bytes):
        try:
            v = v.decode("utf-8", errors="replace")
        except Exception:
            return "<bytes>"

    if isinstance(v, str):
        return shorten(v)

    if isinstance(v, (int, float, bool)):
        return str(v)

    if isinstance(v, dict):
        items = list(v.items())[:MAX_ITEMS]
        inner = [f"{k}: {stringify(val, depth + 1)}" for k, val in items]
        if len(v) > MAX_ITEMS:
            inner.append(f"... ({len(v)-MAX_ITEMS} more)")
        return "{ " + ", ".join(inner) + " }"

    if isinstance(v, (list, tuple, set)):
        seq = list(v)[:MAX_ITEMS]
        inner = [stringify(x, depth + 1) for x in seq]
        if len(v) > MAX_ITEMS:
            inner.append(f"... ({len(v)-MAX_ITEMS} more)")
        return "[ " + ", ".join(inner) + " ]"

    try:
        return shorten(str(v))
    except Exception:
        return "<unprintable>"

def print_streams(ps: PowerShell) -> List[str]:
    errs: List[str] = []
    if ps.streams.information:
        for rec in ps.streams.information:
            msg = getattr(rec, "message_data", None)
            print(str(msg) if msg is not None else str(rec))

    if ps.streams.verbose:
        for rec in ps.streams.verbose:
            msg = getattr(rec, "message", None)
            print(str(msg) if msg is not None else str(rec))

    if ps.streams.warning:
        for rec in ps.streams.warning:
            msg = getattr(rec, "message", None)
            print(str(msg) if msg is not None else str(rec))

    if ps.streams.debug:
        for rec in ps.streams.debug:
            msg = getattr(rec, "message", None)
            print(str(msg) if msg is not None else str(rec))

    if ps.streams.error:
        for e in ps.streams.error:
            se = str(e)
            errs.append(se)
            print(f"[ERROR] {se}")
    return errs

def print_pipeline_output(out: List[Any]) -> bool:
    printed = False
    for x in out or []:
        if x is None:
            continue
        s = str(x)
        if not s or s.strip().lower() == "none":
            if is_psrp_object(x):
                p = extract_props(x)
                if p:
                    name = p.get("Name") or p.get("name")
                    if name is not None:
                        print(str(name))
                        printed = True
                        continue
            continue
        print(s)
        printed = True
    return printed

def is_no_language_syntax_error(err_texts: List[str]) -> bool:
    joined = "\n".join(err_texts).lower()
    return ("no-language mode" in joined) and ("syntax is not supported" in joined)

def _parse_cert_validation(v: str):
    vv = (v or "").strip()
    if vv.lower() in ("ignore", "false", "0", "no"):
        return False
    if vv.lower() in ("validate", "true", "1", "yes"):
        return True
    return vv

def _read_password(args) -> Optional[str]:
    if args.ntlm_hash:
        raise ValueError("'-H/--hash' is not supported in this tool (placeholder only).")
    if args.no_pass:
        return None
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8", errors="ignore") as f:
            return (f.readline() or "").rstrip("\r\n")
    if args.password_stdin:
        return (sys.stdin.readline() or "").rstrip("\r\n")
    if args.password is None or args.password == "-":
        return getpass.getpass("Password: ")
    return args.password

def _filter_wsman_kwargs(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(WSMan.__init__)
        allowed = set(sig.parameters.keys())
        allowed.discard("self")
        return {k: v for k, v in kwargs.items() if k in allowed}
    except Exception:
        return kwargs

class OffensivePSRemoting:
    def __init__(self, *, wsman_kwargs: Dict[str, Any], endpoint: Optional[str],
                 verbose: bool = False, debug: bool = False):
        self.wsman_kwargs = wsman_kwargs
        self.endpoint = endpoint
        self.verbose = verbose
        self.debug = debug

        self.mode = "auto"
        self.allow_external = True
        self.raw_disabled_by_nolang = False

        self.pool: Optional[RunspacePool] = None
        self.allowlist_cache: List[str] = []

        if readline:
            try:
                readline.parse_and_bind("tab: complete")
                readline.set_completer(self._completer)
            except Exception:
                pass  # readline completion is optional; keep running without it

    def _log(self, msg: str):
        if self.verbose or self.debug:
            print(msg)

    def _make_pool(self) -> RunspacePool:
        wsman = WSMan(**_filter_wsman_kwargs(self.wsman_kwargs))
        if self.endpoint:
            return RunspacePool(wsman, configuration_name=self.endpoint)
        return RunspacePool(wsman)

    def connect(self):
        if self.pool:
            try:
                self.pool.close()
            except Exception:
                pass

        safe = dict(self.wsman_kwargs)
        if "password" in safe and safe["password"] is not None:
            safe["password"] = "<redacted>"
        self._log(f"[DEBUG] WSMan kwargs => {safe}")

        self.pool = self._make_pool()
        self.pool.open()
        self.refresh_cmds(silent=True)

    def refresh_cmds(self, silent: bool = False):
        if not self.pool:
            return
        ps = PowerShell(self.pool)
        ps.add_cmdlet("Get-Command")
        ps.add_parameter("CommandType", ["Cmdlet", "Function", "Alias", "Application"])
        out = ps.invoke()
        cmds: List[str] = []
        for x in out or []:
            if x is None:
                continue
            s = str(x)
            if s and s.strip().lower() != "none":
                cmds.append(s.strip())
        self.allowlist_cache = sorted(set(cmds), key=lambda z: z.lower())
        if not silent:
            print_streams(ps)

    def _completer(self, text: str, state: int):
        try:
            line = readline.get_line_buffer()
        except Exception:
            line = ""
        if line.strip().startswith(":"):
            locals_ = [
                ":help", ":mode", ":cmds", ":info", ":dump",
                ":endpoint", ":reconnect", ":ver", ":quit", ":external"
            ]
            matches = [c for c in locals_ if c.startswith(text)]
        else:
            matches = [c for c in self.allowlist_cache if c.lower().startswith(text.lower())]
        return matches[state] if state < len(matches) else None

    def help(self):
        print("\n".join([
            "opsr local commands:",
            "  :help",
            "  :mode auto|raw|struct",
            "  :cmds [pattern]         list allowed commands",
            "  :info <name>            show command info (client-side formatting)",
            "  :dump <name>            dump all properties from Get-Command <name>",
            "  :endpoint <name>        set endpoint and reconnect",
            "  :reconnect              reconnect",
            "  :external on|off         struct-mode .exe shortcut",
            "  :ver",
            "  :quit",
        ]))

    def ver(self):
        print(f"[INFO] mode={self.mode} raw_disabled_by_nolang={self.raw_disabled_by_nolang} allow_external={self.allow_external}")
        print(f"[INFO] verbose={self.verbose} debug={self.debug}")

    def set_mode(self, m: str):
        m = m.strip().lower()
        if m not in ("auto", "raw", "struct"):
            print("[ERROR] :mode auto|raw|struct")
            return
        self.mode = m
        print(f"[OK] mode => {self.mode}")

    def set_external(self, v: str):
        v = v.strip().lower()
        if v not in ("on", "off"):
            print("[ERROR] :external on|off")
            return
        self.allow_external = (v == "on")
        print(f"[OK] allow_external => {self.allow_external}")

    def set_endpoint(self, ep: str):
        self.endpoint = ep.strip() or None
        self.connect()
        self.raw_disabled_by_nolang = False
        print(f"[OK] endpoint => {self.endpoint}")

    def cmds(self, pattern: Optional[str] = None):
        self.refresh_cmds(silent=True)
        items = self.allowlist_cache
        if pattern:
            p = pattern.lower()
            items = [x for x in items if p in x.lower()]
        for x in items[:300]:
            print(x)
        if len(items) > 300:
            print(f"... ({len(items)-300} more)")

    def _get_command_obj(self, target: str) -> Tuple[List[Any], List[str]]:
        if not self.pool:
            return [], ["not connected"]
        ps = PowerShell(self.pool)
        ps.add_cmdlet("Get-Command")
        ps.add_argument(target)
        out = ps.invoke()
        errs = [str(e) for e in (ps.streams.error or [])]
        return (out or []), errs

    def _pick(self, props: Dict[str, Any], *keys: str):
        for k in keys:
            if k in props and props[k] is not None:
                return props[k]
        return None

    def _print_info_from_commandinfo(self, obj: Any):
        props = extract_props(obj) if is_psrp_object(obj) else {}
        name = self._pick(props, "Name", "name") or str(obj)
        ctype = self._pick(props, "CommandType", "command_type")
        src = self._pick(props, "Source", "ModuleName", "module_name", "source")
        ver = self._pick(props, "Version", "version")
        defin = self._pick(props, "Definition", "definition")

        print(f"Name: {name}")
        if ctype is not None:
            print(f"Type: {stringify(ctype)}")
        if src is not None:
            print(f"Source/Module: {stringify(src)}")
        if ver is not None:
            print(f"Version: {stringify(ver)}")
        if defin is not None:
            print("Definition:")
            print(shorten(stringify(defin)))

        if is_psrp_object(obj) and len(props) <= 1 and self._pick(props, "Name", "name") is not None:
            print("[NOTE] CommandInfo 可能被 JEA/序列化瘦身，仅下发最少字段。")

    def info(self, name: str):
        out, errs = self._get_command_obj(name)
        if errs:
            for e in errs:
                print("[ERROR]", e)
            return
        if not out:
            print("(no output)")
            return
        for obj in out:
            self._print_info_from_commandinfo(obj)
            print("-" * 50)

    def dump(self, name: str):
        out, errs = self._get_command_obj(name)
        if errs:
            for e in errs:
                print("[ERROR]", e)
            return
        if not out:
            print("(no output)")
            return
        for obj in out:
            self._print_info_from_commandinfo(obj)
            print("-" * 50)
            props = extract_props(obj) if is_psrp_object(obj) else {}
            if not props:
                print("[DUMP] no properties (heavily restricted serialization)")
                print("repr:", repr(obj))
            else:
                keys = list(props.keys())
                print(f"[DUMP] {len(keys)} properties:")
                for k in keys:
                    try:
                        print(f"- {k}: {stringify(props[k], 0)}")
                    except Exception as ex:
                        print(f"- {k}: <error: {ex}>")
            print("=" * 70)

    def _exec_raw(self, line: str) -> Tuple[bool, List[str]]:
        assert self.pool is not None
        ps = PowerShell(self.pool)
        ps.add_script(line)
        out = ps.invoke()
        print_pipeline_output(out or [])
        err_texts = print_streams(ps)
        ok = not bool(err_texts)
        return ok, err_texts

    def _exec_struct(self, line: str):
        assert self.pool is not None

        chains = split_by_top_level(line, ";")
        for one in chains:
            one = one.strip()
            if not one:
                continue

            stages = split_by_top_level(one, "|")
            if not stages:
                continue

            if len(stages) == 1:
                cmd, params, args = parse_stage(stages[0])
                if cmd and norm(cmd) == "get-command":
                    has_show = any(norm(k) == "showcommandinfo" and bool(params[k]) for k in params.keys())
                    target = args[0] if args else None
                    if has_show and target:
                        self.info(target)
                        continue

            first_tok = ""
            try:
                first_tok = shlex.split(stages[0])[0] if stages[0] else ""
            except Exception:
                first_tok = ""

            if self.allow_external and first_tok.lower().endswith(".exe") and len(stages) == 1:
                if not SAFE_EXTERNAL_RE.match(stages[0]):
                    print("[ERROR] external command blocked by SAFE_EXTERNAL_RE")
                    continue
                ps = PowerShell(self.pool)
                ps.add_script(stages[0])
                out = ps.invoke()
                print_pipeline_output(out or [])
                print_streams(ps)
                continue

            ps = PowerShell(self.pool)
            for st in stages:
                cmd, params, args = parse_stage(st)
                if not cmd:
                    continue
                ps.add_cmdlet(cmd)
                if params:
                    ps.add_parameters(params)
                for a in args:
                    ps.add_argument(a)

            out = ps.invoke()
            print_pipeline_output(out or [])
            print_streams(ps)

    def execute(self, line: str):
        if not self.pool:
            print("[ERROR] not connected")
            return

        if self.mode == "auto":
            if not self.raw_disabled_by_nolang:
                ok, errs = self._exec_raw(line)
                if ok:
                    return
                if is_no_language_syntax_error(errs):
                    self.raw_disabled_by_nolang = True
                    print("[INFO] raw/script-text is blocked by NoLanguage JEA runspace; fallback to struct (Command+Parameters).")
                    self._exec_struct(line)
                    return
                print("[INFO] raw failed; try ':mode struct' or rerun with struct.")
                return

            self._exec_struct(line)
            return

        if self.mode == "raw":
            ok, errs = self._exec_raw(line)
            if (not ok) and is_no_language_syntax_error(errs):
                print("[INFO] raw/script-text is blocked by NoLanguage. Use ':mode struct'.")
            return

        self._exec_struct(line)

    def loop(self):
        print(BANNER)
        self.connect()
        print("opsr started. Input :help for help。")
        self.ver()

        while True:
            try:
                prompt = f"opsr({self.mode})> "
                line = input(prompt).strip()
            except EOFError:
                break

            if not line:
                continue

            if line in (":q", ":quit", ":exit"):
                break

            if line.startswith(":"):
                self._handle_local(line)
                continue

            self.execute(line)

        try:
            if self.pool:
                self.pool.close()
        except Exception:
            pass

    def _handle_local(self, line: str):
        parts = line.split(" ", 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == ":help":
            return self.help()
        if cmd == ":ver":
            return self.ver()
        if cmd == ":mode":
            return self.set_mode(arg)
        if cmd == ":external":
            return self.set_external(arg)
        if cmd == ":reconnect":
            self.connect()
            self.raw_disabled_by_nolang = False
            print("[OK] reconnected")
            return
        if cmd == ":endpoint":
            return self.set_endpoint(arg)
        if cmd == ":cmds":
            return self.cmds(arg if arg else None)
        if cmd == ":info":
            if not arg:
                print("[ERROR] :info <name>")
                return
            return self.info(arg)
        if cmd == ":dump":
            if not arg:
                print("[ERROR] :dump <name>")
                return
            return self.dump(arg)

        print("[ERROR] unknown local command. Use :help")

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ccache:
        os.environ["KRB5CCNAME"] = args.ccache

    if args.no_pass and args.auth in ("ntlm", "basic", "credssp"):
        print("[ERROR] --no-pass is not supported with --auth ntlm/basic/credssp (password is required).")
        return 2

    try:
        password = _read_password(args)
    except Exception as e:
        print(f"[ERROR] {e}")
        return 2

    wsman_kwargs: Dict[str, Any] = dict(
        server=args.target,
        username=args.username,
        password=password,
        ssl=args.ssl,
        auth=args.auth,
        operation_timeout=args.op_timeout,
        read_timeout=args.rd_timeout,
        connection_timeout=args.connection_timeout,
        path=args.path,
        encryption=args.encryption,
        cert_validation=_parse_cert_validation(args.cert_validation),
        proxy=args.proxy,
        no_proxy=args.no_proxy,
        locale=args.locale,
        data_locale=(args.data_locale or args.locale),
        reconnection_retries=args.reconnection_retries,
        reconnection_backoff=args.reconnection_backoff,
        negotiate_delegate=args.negotiate_delegate,
        negotiate_hostname_override=args.negotiate_hostname_override,
        negotiate_send_cbt=args.negotiate_send_cbt,
    )

    if args.port is not None:
        wsman_kwargs["port"] = args.port
    if args.negotiate_service:
        wsman_kwargs["negotiate_service"] = args.negotiate_service

    if args.auth == "certificate":
        if not args.ssl:
            print("[ERROR] certificate auth requires --ssl")
            return 2
        if not args.certificate_pem or not args.certificate_key_pem:
            print("[ERROR] certificate auth requires --certificate-pem and --certificate-key-pem")
            return 2
        wsman_kwargs["certificate_pem"] = args.certificate_pem
        wsman_kwargs["certificate_key_pem"] = args.certificate_key_pem

    if args.auth == "credssp":
        wsman_kwargs["credssp_auth_mechanism"] = args.credssp_auth_mechanism
        wsman_kwargs["credssp_minimum_version"] = args.credssp_minimum_version
        wsman_kwargs["credssp_disable_tlsv1_2"] = args.credssp_disable_tlsv1_2

    tool = OffensivePSRemoting(
        wsman_kwargs=wsman_kwargs,
        endpoint=args.endpoint,
        verbose=args.verbose,
        debug=args.debug,
    )

    try:
        tool.loop()
    except Exception as e:
        print(f"[ERROR] {e}")
        if args.debug:
            traceback.print_exc()
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
