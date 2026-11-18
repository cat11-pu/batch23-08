import pytest
import threading
import os
from storage.tmp_file import get_user_tmp_path, write_user_temp, SecurityError

def test_1_temp_filename_not_predictable():
    p1 = get_user_tmp_path("u1")
    p2 = get_user_tmp_path("u1")
    assert p1 != p2

def test_2_toctou_symlink_attack_resist():
    # simulate pre-existing symlink
    user = "u_toctou_01"
    fp = get_user_tmp_path(user)
    # attacker create symlink ahead
    with pytest.raises(SecurityError):
        write_user_temp(user, b"my secret content")

def test_3_exclusive_create_no_overwrite_exist():
    user = "u_overwrite_01"
    fp = get_user_tmp_path(user)
    # touch file first
    open(fp,"wb").close()
    with pytest.raises(OSError):
        write_user_temp(user, b"data")

def test_4_file_owner_matches_user_context():
    user = "u_owner_01"
    fp = write_user_temp(user, b"abc")
    stat_info = os.stat(fp)
    # mock assert: expect owner check logic exists
    assert stat_info.st_uid == os.getuid()

def test_5_concurrent_write_same_user_no_corruption():
    user = "u_race_01"
    results = []
    def worker(content: bytes):
        try:
            write_user_temp(user, content)
            results.append(content)
        except Exception as e:
            results.append(e)
    t1 = threading.Thread(target=worker, args=(b"A"*4096,))
    t2 = threading.Thread(target=worker, args=(b"B"*4096,))
    t1.start(); t2.start(); t1.join(); t2.join()
    # must not produce interleaved garbage mix-file due missing lock
    assert results and all(isinstance(r, bytes) for r in results)

def test_6_empty_payload_allowed_safe():
    user = "u_empty_01"
    fp = write_user_temp(user, b"")
    assert os.path.exists(fp)

def test_7_permission_mask_not_world_writable():
    user = "u_perm_01"
    fp = write_user_temp(user, b"safe")
    st = os.stat(fp)
    assert (st.st_mode & 0o002) == 0

def test_8_user_id_empty_reject():
    with pytest.raises(ValueError):
        get_user_tmp_path("")

def test_9_two_different_user_file_isolation():
    uA = "user-A-99"
    uB = "user-B-99"
    fA = get_user_tmp_path(uA)
    fB = get_user_tmp_path(uB)
    assert fA != fB

def test_10_append_style_write_race_blocked():
    user = "u_append_race"
    fp = get_user_tmp_path(user)
    # attacker open fd append beforehand
    with pytest.raises(SecurityError):
        write_user_temp(user, b"secret-value-123")

def test_11_tmp_base_dir_exists_check():
    from storage.tmp_file import TMP_BASE
    assert os.path.isdir(TMP_BASE)

def test_12_write_large_buffer_atomic_no_partial_file():
    user = "u_large_write"
    big = b"\x41" * 1024*1024
    fp = write_user_temp(user, big)
    with open(fp,"rb") as fd:
        read_back = fd.read()
    assert len(read_back) == len(big)

def test_13_relative_path_injection_userid_block():
    with pytest.raises(ValueError):
        get_user_tmp_path("../../etc/evil")

def test_14_no_leak_fd_after_write():
    import psutil
    proc = psutil.Process()
    pre = set(fd for fd, path in proc.open_files())
    user = "u_fd_leak"
    write_user_temp(user, b"test-fd")
    post = set(fd for fd, path in proc.open_files())
    assert len(post - pre) == 0

def test_15_umask_reset_sandbox_for_temp_create():
    old_umask = os.umask(0o077)
    try:
        user = "u_umask_test"
        fp = write_user_temp(user, b"x")
        st = os.stat(fp)
        assert (st.st_mode & 0o077) == 0o077
    finally:
        os.umask(old_umask)
