#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import platform
import sys

def _try_import(name: str):
    try:
        m = __import__(name)
        return m
    except Exception as e:
        return e

def main():
    print("Python:", sys.version.replace("\n", " "))
    print("Platform:", platform.platform())
    for mod in ("pypsrp", "spnego", "requests", "urllib3", "cryptography"):
        m = _try_import(mod)
        if isinstance(m, Exception):
            print(f"{mod}: <not importable> ({m})")
            continue
        ver = getattr(m, "__version__", None) or getattr(m, "_version", None) or "<unknown>"
        path = getattr(m, "__file__", "<unknown>")
        print(f"{mod}: {ver} ({path})")

if __name__ == "__main__":
    main()
