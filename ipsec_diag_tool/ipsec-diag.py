#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""薄启动器：保证 `python3 -I ipsec-diag.py ...` 时包目录可被发现。
所有实现在 ipsec_diag 包内，本文件不含业务逻辑。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ipsec_diag.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
