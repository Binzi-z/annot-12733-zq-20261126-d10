# -*- coding: utf-8 -*-
"""12733 离线安全复核：合成证据流的分接收人签名导出与验证演示。

场景：
  * reviewer-summary —— 能看摘要、不能看原始记录（summary 级）。
  * reviewer-dual    —— 有 alpha/beta 两个独立合法来源（full 级）。
演示：
  1. 分别生成每个接收人的签名清单与独立验证器；
  2. 三个可注入交错：最后文件失败、导出指针晋升前崩溃、撤销登记后崩溃；
  3. 单来源撤回后包不消失、当前可见目录无受限字节、旧索引不可复用；
  4. 历史包按旧水位复验；
  5. 同源/异源小样例穷举核对；
  6. 一次单来源更新的实际扫描/写入文件范围。
仅使用 Python 标准库，面向 Windows。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence_export import (  # noqa: E402
    ExportBuilder, Hooks, InjectedFailure, RevisionScopeError,
    RESTRICTED_MARKER, apply_revision, make_synthetic_evidence, sha256_bytes,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = Path(__file__).resolve().parent.parent / "artifacts" / "demo"

GRANTS = {
    "reviewer-summary": {"clearance": "summary", "sources": ["alpha", "beta"]},
    "reviewer-dual": {"clearance": "full", "sources": ["alpha", "beta"]},
}

FAILURES = []


def check(name, fn):
    try:
        fn()
    except Exception as exc:
        FAILURES.append(name)
        print(f"[FAIL] {name}: {exc!r}")
    else:
        print(f"[PASS] {name}")


def run_verifier(recipient, version, *extra):
    """以独立子进程运行随包验证器，证明其不依赖导出方代码。"""
    pkg = ROOT / "exports" / recipient / "packages" / f"v{version}"
    key = ROOT / "keys" / f"{recipient}.key"
    cmd = [sys.executable, str(pkg / "verify.py"), str(pkg), str(key),
           *[str(a) for a in extra]]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return r.returncode, (r.stdout.strip() or r.stderr.strip())


def read_manifest(recipient, version):
    p = ROOT / "exports" / recipient / "packages" / f"v{version}" / "manifest.json"
    return json.loads(p.read_bytes())


def scan_for_bytes(dirpath, needle):
    return [p for p in sorted(Path(dirpath).rglob("*"))
            if p.is_file() and needle in p.read_bytes()]


def make_tiny_evidence(root):
    ev = Path(root) / "evidence"
    for s in ("A", "B"):
        (ev / s / "records").mkdir(parents=True, exist_ok=True)
        (ev / s / "records" / "rec.raw.bin").write_bytes(
            s.encode() + b"-" + RESTRICTED_MARKER)
        (ev / s / "summaries").mkdir(parents=True, exist_ok=True)
        (ev / s / "summaries" / "rec.summary.txt").write_text(
            f"{s} 摘要\n", encoding="utf-8")


def exhaustive_check():
    """同源/异源小样例穷举核对，返回核对组合数。"""
    base = ROOT / "exhaustive"
    combos = 0
    # 授权矩阵：2 密级 × 4 个撤销子集，与逐文件独立推出的期望集比对
    for clearance in ("summary", "full"):
        for revoked in (frozenset(), frozenset({"A"}), frozenset({"B"}),
                        frozenset({"A", "B"})):
            root = base / f"entitle-{clearance}-{''.join(sorted(revoked)) or 'none'}"
            make_tiny_evidence(root)
            bb = ExportBuilder(root, {"r": {"clearance": clearance,
                                            "sources": ["A", "B"]}})
            for s in sorted(revoked):
                bb.register_revocation("r", s)
            got = set(bb.entitled_files("r"))
            want = set()
            for s in ("A", "B"):
                if s in revoked:
                    continue
                want.add(f"{s}/summaries/rec.summary.txt")
                if clearance == "full":
                    want.add(f"{s}/records/rec.raw.bin")
            assert got == want, (clearance, revoked, sorted(got ^ want))
            combos += 1
    # 修订作用域：同源修订生效且不动异源；两类越源修订都被拒绝
    for src, other in (("A", "B"), ("B", "A")):
        root = base / f"rev-{src}"
        make_tiny_evidence(root)
        ev = root / "evidence"
        other_raw = ev / other / "records" / "rec.raw.bin"
        before = sha256_bytes(other_raw.read_bytes())
        apply_revision(ev, src, {"source": src, "revision": 2, "files": {
            "records/rec.raw.bin": b"rev2-" + src.encode()}})
        assert sha256_bytes(other_raw.read_bytes()) == before, "异源字节被改动"
        combos += 1
        bad_docs = (
            {"source": src, "revision": 3,
             "files": {f"../{other}/records/rec.raw.bin": b"x"}},   # 路径越源
            {"source": other, "revision": 3,
             "files": {"records/rec.raw.bin": b"x"}},               # 声明不符
        )
        for bad in bad_docs:
            try:
                apply_revision(ev, src, bad)
            except RevisionScopeError:
                combos += 1
            else:
                raise AssertionError(f"越源修订未被拒绝: {bad}")
        assert sha256_bytes(other_raw.read_bytes()) == before, "越源尝试留下痕迹"
    return combos


def main():
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir(parents=True)
    make_synthetic_evidence(ROOT)

    hooks = Hooks()
    TRACE = []
    hooks.trace = lambda event, path: TRACE.append((event, Path(path)))
    b = ExportBuilder(ROOT, GRANTS, hooks)

    print("== 1. 初始导出：每个接收人各一份签名清单 + 独立验证器 ==")
    v_sum = b.build("reviewer-summary")
    v_dual = b.build("reviewer-dual")
    assert (v_sum, v_dual) == (1, 1)

    def c_initial():
        for rec in ("reviewer-summary", "reviewer-dual"):
            rc, out = run_verifier(rec, 1)
            assert rc == 0, out
            print(f"       {rec} v1 -> {out}")
    check("初始导出两个接收人均通过独立验证器", c_initial)

    def c_restricted():
        m = read_manifest("reviewer-summary", 1)
        assert not any(r.startswith(("alpha/records", "beta/records"))
                       for r in m["files"]), "清单中出现原始记录"
        files_dir = (ROOT / "exports" / "reviewer-summary" / "packages"
                     / "v1" / "files")
        hits = scan_for_bytes(files_dir, RESTRICTED_MARKER)
        assert not hits, f"摘要级包内发现受限字节: {hits}"
    check("摘要级接收人当前可见目录无受限字节", c_restricted)

    print("== 2. 可注入交错一：最后文件失败 ==")
    last_rel = sorted(b.entitled_files("reviewer-dual"))[-1]
    hooks.fail_on_write_relpath = last_rel

    def c_last_file():
        try:
            b.build("reviewer-dual")
        except InjectedFailure:
            pass
        else:
            raise AssertionError("注入故障未触发")
        assert b.current_version("reviewer-dual") == 1, "指针被提前晋升"
        pkgs = ROOT / "exports" / "reviewer-dual" / "packages"
        assert not (pkgs / "v2").exists(), "半成品以正式包亮相"
        rc, out = run_verifier("reviewer-dual", 1)
        assert rc == 0, out
        print(f"       故障点={last_rel}；current 仍为 v1 且复验通过")
    check("最后文件失败：指针不动、旧包仍可复验", c_last_file)
    hooks.fail_on_write_relpath = None

    print("== 3. 可注入交错二：导出指针晋升前崩溃 ==")
    def boom(*_):
        raise InjectedFailure("注入故障：指针晋升前崩溃")
    hooks.before_pointer_promote = boom

    def c_promote_crash():
        try:
            b.build("reviewer-dual")
        except InjectedFailure:
            pass
        else:
            raise AssertionError("注入故障未触发")
        assert b.current_version("reviewer-dual") == 1
        orphan = ROOT / "exports" / "reviewer-dual" / "packages" / "v2"
        assert orphan.exists(), "应留下未引用的孤儿包"
        ptr = json.loads((ROOT / "exports" / "reviewer-dual"
                          / "current.json").read_text(encoding="utf-8"))
        assert ptr["version"] == 1, "指针指向了未完成的包"
        print("       孤儿包 packages/v2 存在但 current.json 仍指向 v1")
    check("指针晋升前崩溃：旧水位不受影响", c_promote_crash)
    hooks.before_pointer_promote = None

    print("== 4. 单来源更新（alpha rev2）：实际扫描/写入范围 ==")
    TRACE.clear()
    apply_revision(b.evidence_dir, "alpha", {
        "source": "alpha", "revision": 2,
        "files": {
            "records/rec-001.raw.bin":
                b"ALPHA-" + RESTRICTED_MARKER + b"\npayload:rec-001 rev2\n",
            "summaries/rec-001.summary.txt":
                "alpha/rec-001 摘要 rev2（不含原始记录字节）\n",
        }}, trace=hooks.trace)
    v2 = b.build("reviewer-dual")
    assert v2 == 2

    def c_trace():
        scanned = [p for e, p in TRACE if e == "scan"]
        carried = [p for e, p in TRACE if e == "carry"]
        written = [p for e, p in TRACE if e == "write"]
        ev_written = [p for e, p in TRACE if e == "evidence-write"]
        assert scanned and all("alpha" in p.parts for p in scanned), \
            "扫描范围越出 alpha"
        assert carried and all("beta" in p.parts for p in carried), \
            "搬运范围不含 beta 或越界"
        print(f"       证据写入 {len(ev_written)} 个（全部在 alpha/）：")
        for p in ev_written:
            print(f"         W {p.relative_to(ROOT)}")
        print(f"       扫描证据 {len(scanned)} 个（全部在 alpha/）：")
        for p in scanned:
            print(f"         S {p.relative_to(ROOT)}")
        print(f"       自上一包搬运 {len(carried)} 个（全部来自 beta，未重扫证据）")
        print(f"       写入新包文件 {len(written)} 个"
              f"（alpha 新内容 + beta 校验后副本）")
        m1, m2 = read_manifest("reviewer-dual", 1), read_manifest("reviewer-dual", 2)
        beta1 = {r: e for r, e in m1["files"].items() if r.startswith("beta/")}
        beta2 = {r: e for r, e in m2["files"].items() if r.startswith("beta/")}
        assert beta1 == beta2, "alpha 的修订影响了 beta 的条目"
        assert m2["source_revisions"] == {"alpha": 2, "beta": 1}
        rc, out = run_verifier("reviewer-dual", 2)
        assert rc == 0, out
    check("单来源更新只扫描/写入自己来源的范围", c_trace)

    print("== 5. 可注入交错三：撤销登记后崩溃，再恢复重建 ==")
    hooks.after_revocation_registered = boom

    def c_revoke_crash():
        try:
            b.register_revocation("reviewer-dual", "alpha")
        except InjectedFailure:
            pass
        else:
            raise AssertionError("注入故障未触发")
        reg = json.loads((ROOT / "exports" / "registry" / "revocations.json")
                         .read_text(encoding="utf-8"))
        assert any(r["source"] == "alpha" and r["recipient"] == "reviewer-dual"
                   for r in reg["revocations"]), "撤销未持久化"
        print("       崩溃发生在登记落盘之后；登记本身已持久化")
    check("撤销登记后崩溃：登记仍然生效", c_revoke_crash)
    hooks.after_revocation_registered = None

    v3 = b.build("reviewer-dual")
    assert v3 == 3

    def c_revoked_pkg():
        m = read_manifest("reviewer-dual", 3)
        assert m["sources"] == ["beta"], m["sources"]
        assert m["revocations_applied"] == ["alpha"]
        assert m["files"], "来源被撤回后导出包全部消失"
        assert all(r.startswith("beta/") for r in m["files"])
        rc, out = run_verifier("reviewer-dual", 3,
                               "--pointer", ROOT / "exports" / "reviewer-dual"
                               / "current.json",
                               "--registry", ROOT / "exports" / "registry"
                               / "revocations.json")
        assert rc == 0, out
        print(f"       v3 仅含 beta 的 {len(m['files'])} 个文件，"
              f"按当前标准验证通过")
    check("单来源撤回：包不消失，仅剔除被撤来源", c_revoked_pkg)

    def c_no_stale_index():
        files_dir = ROOT / "exports" / "reviewer-dual" / "packages" / "v3" / "files"
        hits = scan_for_bytes(files_dir, b"ALPHA-RAW-RECORD")
        assert not hits, f"当前可见目录残留被撤来源字节: {hits}"
        # 旧索引不可复用：v1/v2 以“当前”标准加验必须失败
        ptr = ROOT / "exports" / "reviewer-dual" / "current.json"
        reg = ROOT / "exports" / "registry" / "revocations.json"
        for old in (1, 2):
            rc, out = run_verifier("reviewer-dual", old,
                                   "--pointer", ptr, "--registry", reg)
            assert rc != 0, f"v{old} 的旧索引被当作当前包接受"
            print(f"       v{old} 冒充当前包被拒绝 -> {out}")
    check("当前可见目录无被撤来源字节，旧索引不可复用", c_no_stale_index)

    print("== 6. 历史包按旧水位复验 ==")
    def c_history():
        for rec, ver in (("reviewer-dual", 1), ("reviewer-dual", 2),
                         ("reviewer-dual", 3), ("reviewer-summary", 1)):
            rc, out = run_verifier(rec, ver)
            assert rc == 0, out
            print(f"       {rec} v{ver} -> {out}")
    check("全部历史包按各自旧水位复验通过", c_history)

    print("== 7. 同源/异源小样例穷举核对 ==")
    def c_exhaustive():
        n = exhaustive_check()
        print(f"       穷举组合 {n} 项全部符合预期"
              f"（8 项授权矩阵 + 6 项修订作用域）")
    check("穷举核对：授权矩阵与修订作用域", c_exhaustive)

    print()
    if FAILURES:
        print(f"共 {len(FAILURES)} 项失败: {FAILURES}")
        return 1
    print("全部检查通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
