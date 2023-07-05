#!/usr/bin/env python
# -*- coding: utf-8 -*-

def base64_encode(data: str) -> str:
    import base64
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")

def base64_decode(data: str) -> str:
    import base64
    return str(base64.b64decode(data.encode("utf-8")))