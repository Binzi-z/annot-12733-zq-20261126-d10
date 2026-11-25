# -*- coding: utf-8 -*-
"""独立验证器（仅 Python 标准库，不依赖导出方任何代码）。

用法:
  python verify.py <包目录> <密钥文件> [--pointer current.json] [--registry revocations.json]

默认按历史水位复验：只校验签名、清单与文件摘要自洽 —— 历史包因此总能复验。
给出 --pointer / --registry 时按“当前可见”标准加验：
  * 指针版本与清单摘要必须一致；
  * 撤销登记必须已全部反映在该包清单中。
旧版本的索引因此无法冒充当前包被复用。
退出码：0 通过，1 失败，2 用法错误。
"""
import hashlib
import hmac
import json
import sys
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg: str) -> int:
    print(f"FAIL: {msg}")
    return 1


def main(argv) -> int:
    pos, opts = [], {}
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("--pointer", "--registry"):
            if i + 1 >= len(argv):
                return fail(f"{a} 缺少参数")
            opts[a[2:]] = argv[i + 1]
            i += 2
        else:
            pos.append(a)
            i += 1
    if len(pos) != 2:
        print(__doc__)
        return 2

    pkg, key_path = Path(pos[0]), Path(pos[1])
    manifest_path = pkg / "manifest.json"
    sig_path = pkg / "manifest.sig"
    if not manifest_path.is_file() or not sig_path.is_file():
        return fail("包内缺少 manifest.json 或 manifest.sig")

    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        return fail(f"manifest.json 不是合法 JSON: {exc}")

    # 1) 签名：HMAC-SHA256(接收人密钥, 清单原始字节)
    key = key_path.read_bytes()
    expect_sig = hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()
    actual_sig = sig_path.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(expect_sig, actual_sig):
        return fail("清单签名不匹配")

    # 2) 清单声明的每个文件：存在、摘要与大小一致
    files = manifest.get("files", {})
    for rel, entry in files.items():
        fpath = pkg / "files" / rel
        if not fpath.is_file():
            return fail(f"清单声明的文件缺失: {rel}")
        data_len = fpath.stat().st_size
        if data_len != entry.get("size"):
            return fail(f"文件大小不符: {rel}")
        if sha256_file(fpath) != entry.get("sha256"):
            return fail(f"文件摘要不符: {rel}")

    # 3) 反向核对：files/ 下不得有清单之外的文件（防止残留旧索引/夹带）
    files_dir = pkg / "files"
    actual = {p.relative_to(files_dir).as_posix()
              for p in files_dir.rglob("*") if p.is_file()} if files_dir.is_dir() else set()
    extra = actual - set(files)
    if extra:
        return fail(f"存在清单之外的文件: {sorted(extra)}")

    # 4) 可选：按“当前可见”标准加验
    if "pointer" in opts:
        ptr = json.loads(Path(opts["pointer"]).read_text(encoding="utf-8"))
        if ptr.get("version") != manifest.get("version"):
            return fail(f"指针版本 {ptr.get('version')} 与清单版本 "
                        f"{manifest.get('version')} 不一致（非当前包）")
        if ptr.get("manifest_sha256") != sha256_bytes(manifest_bytes):
            return fail("指针记录的清单摘要不一致")
    if "registry" in opts:
        reg = json.loads(Path(opts["registry"]).read_text(encoding="utf-8"))
        registered = sorted(r["source"] for r in reg.get("revocations", [])
                            if r.get("recipient") == manifest.get("recipient"))
        applied = set(manifest.get("revocations_applied", []))
        missing = [s for s in registered if s not in applied]
        if missing:
            return fail(f"清单未反映已登记撤销 {missing}（旧索引不可作为当前包复用）")

    print(f"OK: recipient={manifest.get('recipient')} "
          f"version={manifest.get('version')} "
          f"watermark={manifest.get('watermark')} "
          f"files={len(files)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
