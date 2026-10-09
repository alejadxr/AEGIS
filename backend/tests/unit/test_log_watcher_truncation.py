"""Truncation detection must use real byte offsets, not text-mode tell() cookies."""
import os

from app.services.log_watcher import _is_truncated


def _open(path):
    fp = open(path, "r", errors="replace")
    return fp, os.stat(path).st_ino


def test_multibyte_content_not_flagged_as_truncated(tmp_path):
    p = tmp_path / "access.log"
    line = "año señal café 🔥 ñandú é\n"
    p.write_text(line * 2000, encoding="utf-8")
    fp, ino = _open(p)
    for _ in range(1500):
        fp.readline()
    with open(p, "a", encoding="utf-8") as f:
        f.write(line * 10)
    assert not _is_truncated(fp, ino, os.stat(p))
    fp.close()


def test_in_place_truncation_detected_and_rewound(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("línea uno\n" * 500, encoding="utf-8")
    fp, ino = _open(p)
    while fp.readline():
        pass
    with open(p, "r+") as f:
        f.truncate(10)
    assert _is_truncated(fp, ino, os.stat(p))
    fp.seek(0)
    assert fp.readline().startswith("línea")
    assert not _is_truncated(fp, ino, os.stat(p))
    fp.close()


def test_unchanged_file_not_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("ñ é 🔥\n" * 300, encoding="utf-8")
    fp, ino = _open(p)
    while fp.readline():
        pass
    assert not _is_truncated(fp, ino, os.stat(p))
    fp.close()


def test_new_inode_not_flagged(tmp_path):
    p = tmp_path / "access.log"
    p.write_text("x\n")
    fp, ino = _open(p)
    assert not _is_truncated(fp, ino + 1, os.stat(p))
    fp.close()
