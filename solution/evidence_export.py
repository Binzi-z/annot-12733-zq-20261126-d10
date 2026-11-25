# -*- coding: utf-8 -*-
"""离线证据导出库（仅 Python 标准库，Windows 可运行）。

模型
----
- 证据按来源(source)分目录存放；``records/`` 下为含受限字节的原始记录，
  ``summaries/`` 下为可公开摘要。受限字节标记为 ``RAW-RECORD``。
- 每个接收人有 clearance("summary"/"full") 与来源授权；撤销登记落盘后，
  该来源从后续导出中剔除，但其余来源构成的包不受影响（不会全部消失）。
- 每次导出生成不可变包 ``packages/vN``（签名清单 + 独立验证器 verify.py），
  ``current.json`` 指针在最后一步原子晋升；历史包可按旧水位复验。
- 清单绑定：用途(purpose)、接收标识(recipient)、版本/水位(version/watermark)、
  以及每个实际文件的 SHA-256 摘要与大小。
- 修订按声明来源隔离：同编号的修订只能写入它自己声明的来源目录，
  越源路径或声明不符都会被拒绝（RevisionScopeError）。

可注入交错（Hooks）
-------------------
- ``before_pointer_promote``    导出指针晋升前（模拟晋升前崩溃）。
- ``after_revocation_registered`` 撤销登记落盘后（模拟登记后、重建前崩溃）。
- ``fail_on_write_relpath``     写入指定包内相对路径时失败（模拟最后文件失败）。
- ``trace``                     观察实际扫描/搬运/写入的文件范围。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

EXPORT_FORMAT = "evidence-export/1"
PURPOSE = "offline-evidence-review"
RESTRICTED_MARKER = b"RAW-RECORD"  # 受限字节：summary 级导出绝不得包含

VERIFIER_SOURCE = Path(__file__).with_name("verify_export.py")


class InjectedFailure(RuntimeError):
    """可注入交错触发的故障（指针晋升 / 撤销登记 / 最后文件写入）。"""


class RevisionScopeError(ValueError):
    """修订试图影响其声明来源之外的文件。"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)  # Windows 下同卷文件级原子替换


def atomic_write_json(path: Path, obj) -> None:
    atomic_write_bytes(path, canonical(obj))


class Hooks:
    """可注入的交错点；默认全部不生效。"""

    def __init__(self):
        self.before_pointer_promote = None       # fn(recipient, version) -> None | raise
        self.after_revocation_registered = None  # fn(recipient, source)   -> None | raise
        self.fail_on_write_relpath = None        # 写该包内相对路径时抛 InjectedFailure
        self.trace = None                        # fn(event: str, path: Path)


class ExportBuilder:
    def __init__(self, root, grants, hooks=None):
        self.root = Path(root)
        self.grants = grants
        self.hooks = hooks or Hooks()
        self.evidence_dir = self.root / "evidence"
        self.exports_dir = self.root / "exports"
        self.keys_dir = self.root / "keys"
        self.registry_path = self.exports_dir / "registry" / "revocations.json"

    # ---- 密钥与撤销登记 -------------------------------------------------
    def key_for(self, recipient) -> bytes:
        kpath = self.keys_dir / f"{recipient}.key"
        if not kpath.exists():
            atomic_write_bytes(kpath, os.urandom(32))
        return kpath.read_bytes()

    def load_registry(self) -> dict:
        if not self.registry_path.exists():
            return {"revocations": []}
        return json.loads(self.registry_path.read_text(encoding="utf-8"))

    def revoked_sources(self, recipient) -> set:
        return {r["source"] for r in self.load_registry()["revocations"]
                if r["recipient"] == recipient}

    def register_revocation(self, recipient, source) -> None:
        reg = self.load_registry()
        if not any(r["recipient"] == recipient and r["source"] == source
                   for r in reg["revocations"]):
            reg["revocations"].append({
                "recipient": recipient, "source": source,
                "seq": len(reg["revocations"]) + 1,
            })
            atomic_write_json(self.registry_path, reg)  # 先持久化，再触发交错
        if self.hooks.after_revocation_registered:
            self.hooks.after_revocation_registered(recipient, source)

    # ---- 指针与水位 -----------------------------------------------------
    def recipient_dir(self, recipient) -> Path:
        return self.exports_dir / recipient

    def current_pointer(self, recipient):
        p = self.recipient_dir(recipient) / "current.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def current_version(self, recipient) -> int:
        ptr = self.current_pointer(recipient)
        return ptr["version"] if ptr else 0

    def source_revision(self, source) -> int:
        p = self.evidence_dir / "revisions" / f"{source}.json"
        if not p.exists():
            return 0
        return json.loads(p.read_text(encoding="utf-8"))["current_revision"]

    # ---- 授权计算 -------------------------------------------------------
    def entitled_files(self, recipient) -> dict:
        """返回 {包内相对路径: 证据绝对路径}；撤销与密级在此生效。"""
        grant = self.grants[recipient]
        revoked = self.revoked_sources(recipient)
        out = {}
        for source in grant["sources"]:
            if source in revoked:
                continue
            sdir = self.evidence_dir / source
            for p in sorted(sdir.rglob("*")):
                if not p.is_file():
                    continue
                rel_in_source = p.relative_to(sdir).as_posix()
                if grant["clearance"] == "summary" and rel_in_source.startswith("records/"):
                    continue  # 摘要级接收人不得拿到原始记录
                out[f"{source}/{rel_in_source}"] = p
        return dict(sorted(out.items()))

    # ---- 导出 -----------------------------------------------------------
    def _trace(self, event, path):
        if self.hooks.trace:
            self.hooks.trace(event, Path(path))

    def build(self, recipient) -> int:
        version = self.current_version(recipient) + 1
        rdir = self.recipient_dir(recipient)
        packages = rdir / "packages"
        staging = packages / f".staging-v{version}"
        pkg_dir = packages / f"v{version}"
        if staging.exists():
            shutil.rmtree(staging)  # 上次失败留下的半成品
        if pkg_dir.exists():
            shutil.rmtree(pkg_dir)  # 上次晋升前崩溃留下的孤儿包（指针从未指向它）
        (staging / "files").mkdir(parents=True)

        old_ptr = self.current_pointer(recipient)
        old_manifest = old_pkg = None
        if old_ptr:
            old_pkg = rdir / old_ptr["package"]
            old_manifest = json.loads((old_pkg / "manifest.json").read_bytes())

        entitled = self.entitled_files(recipient)
        files_section, source_revisions = {}, {}
        for rel, src in entitled.items():
            source = rel.split("/", 1)[0]
            source_revisions[source] = self.source_revision(source)
            carried = (
                old_manifest is not None
                and old_manifest.get("source_revisions", {}).get(source)
                == source_revisions[source]
                and rel in old_manifest["files"]
            )
            if carried:
                # 来源水位未变：不重扫证据，从上一包搬运并校验摘要
                old_file = old_pkg / "files" / rel
                self._trace("carry", old_file)
                data = old_file.read_bytes()
                digest = old_manifest["files"][rel]["sha256"]
                if sha256_bytes(data) != digest:
                    raise RuntimeError(f"历史包文件被篡改，拒绝搬运: {rel}")
            else:
                self._trace("scan", src)
                data = src.read_bytes()
                digest = sha256_bytes(data)
            if self.hooks.fail_on_write_relpath == rel:
                raise InjectedFailure(f"注入故障：写入文件失败 {rel}")
            dst = staging / "files" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            self._trace("write", dst)
            files_section[rel] = {"sha256": digest, "size": len(data)}

        manifest = {
            "format": EXPORT_FORMAT,
            "purpose": PURPOSE,
            "recipient": recipient,
            "version": version,
            "watermark": version,
            "sources": sorted(source_revisions),
            "source_revisions": source_revisions,
            "revocations_applied": sorted(self.revoked_sources(recipient)),
            "files": files_section,
        }
        manifest_bytes = canonical(manifest)
        sig = hmac.new(self.key_for(recipient), manifest_bytes,
                       hashlib.sha256).hexdigest()
        atomic_write_bytes(staging / "manifest.json", manifest_bytes)
        atomic_write_bytes(staging / "manifest.sig", (sig + "\n").encode("ascii"))
        shutil.copyfile(VERIFIER_SOURCE, staging / "verify.py")  # 独立验证器随包分发

        os.rename(staging, pkg_dir)  # 目标不存在，单次重命名亮相
        if self.hooks.before_pointer_promote:
            self.hooks.before_pointer_promote(recipient, version)  # 可注入：晋升前崩溃
        atomic_write_json(rdir / "current.json", {
            "version": version,
            "package": f"packages/v{version}",
            "manifest_sha256": sha256_bytes(manifest_bytes),
        })
        return version


def apply_revision(evidence_dir, source, doc, trace=None) -> list:
    """应用一个修订；修订只能写入它自己声明的来源目录。

    先全量校验（声明来源一致、相对路径不越源、修订号递增），再落盘，
    因此越源修订不会留下任何半成品。
    """
    evidence_dir = Path(evidence_dir)
    declared = doc.get("source")
    if declared != source:
        raise RevisionScopeError(
            f"修订声明来源 {declared!r} 与目标来源 {source!r} 不符")
    revision = doc.get("revision")
    sdir = (evidence_dir / source).resolve()
    targets = []
    for rel, content in sorted(doc["files"].items()):
        target = (sdir / rel).resolve()
        if target != sdir and sdir not in target.parents:
            raise RevisionScopeError(
                f"修订 {revision} 试图写入声明来源之外的路径: {rel!r}")
        targets.append((target, content))
    rev_path = evidence_dir / "revisions" / f"{source}.json"
    state = (json.loads(rev_path.read_text(encoding="utf-8"))
             if rev_path.exists()
             else {"source": source, "current_revision": 0, "history": []})
    if not isinstance(revision, int) or revision <= state["current_revision"]:
        raise ValueError(
            f"修订号必须严格递增: {revision!r} <= {state['current_revision']}")
    written = []
    for target, content in targets:
        if trace:
            trace("evidence-write", target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes)
                           else content.encode("utf-8"))
        written.append(target)
    state["current_revision"] = revision
    state["history"].append(revision)
    atomic_write_json(rev_path, state)
    return written


def make_synthetic_evidence(root) -> None:
    """生成合成证据流：alpha/beta 两来源，各 2 条记录（原始 + 摘要）。"""
    ev = Path(root) / "evidence"
    for source, tag in (("alpha", b"ALPHA"), ("beta", b"BETA")):
        for rec in ("rec-001", "rec-002"):
            raw = ev / source / "records" / f"{rec}.raw.bin"
            raw.parent.mkdir(parents=True, exist_ok=True)
            raw.write_bytes(tag + b"-" + RESTRICTED_MARKER + b"\n"
                            b"payload:" + rec.encode() + b" rev1\n")
            summ = ev / source / "summaries" / f"{rec}.summary.txt"
            summ.parent.mkdir(parents=True, exist_ok=True)
            summ.write_text(f"{source}/{rec} 摘要 rev1（不含原始记录字节）\n",
                            encoding="utf-8")
        atomic_write_json(ev / "revisions" / f"{source}.json", {
            "source": source, "current_revision": 1, "history": [1]})
