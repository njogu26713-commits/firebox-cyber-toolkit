from __future__ import annotations
import os, platform, shutil

def info() -> dict:
    return {"platform":platform.platform(),"python":platform.python_version(),"hostname":platform.node(),"architecture":platform.machine(),"cpu_count":os.cpu_count(),"disk_free_bytes":shutil.disk_usage('/').free}
