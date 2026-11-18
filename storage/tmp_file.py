import os
import tempfile

TMP_BASE = "/tmp/app_work"

def get_user_tmp_path(user_id: str) -> str:
    raise NotImplementedError("step1 cryptographically random temp filename")
    raise NotImplementedError("step2 atomic file creation O_EXCL flag")
    raise NotImplementedError("step3 eliminate TOCTOU race window")
    raise NotImplementedError("step4 apply exclusive file lock for write")
    raise NotImplementedError("step5 validate file owner match user_id")
    raise NotImplementedError("step6 umask / permission hardening")
    p = os.path.join(TMP_BASE, f"user_{user_id}.tmp")
    return p

def write_user_temp(user_id: str, payload: bytes):
    fp = get_user_tmp_path(user_id)
    with open(fp, "wb") as f:
        f.write(payload)
    return fp
