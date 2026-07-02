# -*- coding: utf-8 -*-
"""
完整审核策略联调验证（真实飞书 API）。

按顺序逐项验证：highlight → replace → lock → notify → 组合策略。
会修改测试文档正文，并在结束时尝试解锁（若加锁成功）。

用法：
  cd demo
  python verify_full_policy_live.py
  python verify_full_policy_live.py --token <docx_token>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime

sys.path.insert(0, ".")

import demo  # noqa: E402


def _ok(result: dict) -> bool:
    if result.get("ok") is True:
        return True
    if result.get("sent_to"):
        return True
    if result.get("blocks_updated", 0) > 0:
        return True
    if result.get("note") and not result.get("errors"):
        return True
    return False


def _step(name: str, passed: bool, detail: dict) -> dict:
    status = "PASS" if passed else "FAIL"
    print(f"[{status}] {name}: {json.dumps(detail, ensure_ascii=False)}")
    return {"step": name, "passed": passed, "detail": detail}


def verify_document(file_token: str, file_type: str = "docx") -> dict:
    report = {
        "file_token": file_token,
        "file_type": file_type,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "steps": [],
        "summary": {},
    }

    # 0. 鉴权
    headers = demo._auth_headers()
    if not headers:
        report["steps"].append(_step("auth", False, {"error": "无法获取 tenant_access_token"}))
        report["summary"] = {"passed": 0, "failed": 1, "all_passed": False}
        return report

    meta, meta_err = demo.fetch_file_metadata(file_token, file_type)
    title = (meta or {}).get("title") or file_token
    report["document_title"] = title
    report["steps"].append(_step("auth", True, {"title": title}))

    # 1. 基线审核
    content, err = demo.fetch_file_content(file_token, file_type)
    if err:
        report["steps"].append(_step("baseline_audit", False, {"error": err}))
        report["summary"] = {"passed": 1, "failed": 1, "all_passed": False}
        return report

    moderation = demo.moderate_text(content)
    report["baseline"] = {
        "char_count": len(content or ""),
        "preview": (content or "")[:80],
        "moderation": moderation,
    }
    report["steps"].append(_step("baseline_audit", True, {
        "passed": moderation.get("passed"),
        "hits": moderation.get("hits"),
        "preview": report["baseline"]["preview"],
    }))

    if moderation.get("passed"):
        print("WARN: 文档未命中敏感词，highlight/replace 可能无 block 可更新")

    hits = moderation.get("hits") or demo.SENSITIVE_WORDS[:1]

    # 2. highlight
    hl = demo.apply_docx_content_policy(
        file_token, hits, "highlight",
        highlight_color=demo.AUDIT_HIGHLIGHT_COLOR,
    )
    hl_pass = hl.get("ok") and (
        hl.get("blocks_updated", 0) > 0 or hl.get("note") == "未命中可更新的 block"
    )
    if moderation.get("passed"):
        hl_pass = hl.get("ok", False)
    report["steps"].append(_step("highlight", hl_pass, hl))

    # 3. replace（高亮后敏感词仍在正文中）
    content2, _ = demo.fetch_file_content(file_token, file_type)
    mod2 = demo.moderate_text(content2)
    rp = demo.apply_docx_content_policy(
        file_token, mod2.get("hits") or hits, "replace",
        mask_text=demo.AUDIT_MASK_TEXT,
    )
    content3, _ = demo.fetch_file_content(file_token, file_type)
    still_has_hits = any(w in (content3 or "") for w in (mod2.get("hits") or hits))
    has_mask = demo.AUDIT_MASK_TEXT in (content3 or "")
    rp_pass = rp.get("ok") and (has_mask or moderation.get("passed"))
    if not moderation.get("passed") and still_has_hits and not has_mask:
        rp_pass = False
    report["steps"].append(_step("replace", rp_pass, {
        **rp,
        "after_preview": (content3 or "")[:80],
        "mask_found": has_mask,
        "sensitive_still_present": still_has_hits,
    }))

    # 4. lock
    lk = demo.apply_lock_policy(file_token, file_type)
    perm, perm_err = demo.get_public_permission(file_token, file_type)
    locked = bool((perm or {}).get("lock_switch"))
    share_closed = (perm or {}).get("link_share_entity") == "closed"
    lk_pass = lk.get("ok") and (locked or share_closed)
    if not lk.get("ok") and perm_err:
        lk_pass = False
    report["steps"].append(_step("lock", lk_pass, {
        **lk,
        "lock_switch_after": locked,
        "link_share_entity": (perm or {}).get("link_share_entity"),
        "share_closed": share_closed,
        "perm_error": perm_err,
    }))

    # 5. notify
    targets = demo.resolve_notify_targets(file_token, file_type)
    nt = demo.apply_notify_policy(file_token, file_type, hits, title=title)
    nt_pass = bool(nt.get("sent_to")) and not nt.get("errors")
    report["steps"].append(_step("notify", nt_pass, {
        **nt,
        "resolved_targets": targets,
    }))

    # 6. 组合策略（apply_audit_policies 编排）
    combo_moderation = demo.moderate_text(content3 or "")
    combo = demo.apply_audit_policies(
        file_token, file_type, combo_moderation,
        title=title, source="full_verify",
        actions=["highlight", "replace", "lock", "notify"],
    )
    combo_pass = (
        isinstance(combo.get("results"), dict)
        and combo.get("configured_actions") == ["highlight", "replace", "lock", "notify"]
    )
    report["steps"].append(_step("combined_orchestration", combo_pass, combo))

    # 7. audit_file 集成（应带 policy_actions）
    audit_result = demo.audit_file(file_token, file_type, source="full_verify_integration")
    audit_pass = "policy_actions" in audit_result or audit_result.get("passed")
    if not audit_result.get("passed"):
        audit_pass = audit_pass and bool(audit_result.get("policy_actions"))
    report["steps"].append(_step("audit_file_integration", audit_pass, {
        "passed": audit_result.get("passed"),
        "hits": audit_result.get("hits"),
        "policy_actions": audit_result.get("policy_actions"),
    }))

    # 8. 尝试解锁（清理：恢复链接分享；wiki 才尝试解除 lock_switch）
    unlock_detail = {}
    if locked or share_closed:
        ok_u, detail_u = demo.update_public_permission(
            file_token, file_type,
            lock_switch=False if locked else None,
            link_share_entity="tenant_readable" if share_closed else None,
        )
        unlock_detail = {
            "ok": ok_u,
            "detail": detail_u if isinstance(detail_u, dict) else str(detail_u),
        }
        perm2, _ = demo.get_public_permission(file_token, file_type)
        unlock_detail["link_share_after"] = (perm2 or {}).get("link_share_entity")
        unlock_detail["lock_switch_after_unlock"] = bool((perm2 or {}).get("lock_switch"))
    report["steps"].append(_step("cleanup_unlock", True, unlock_detail or {"skipped": "无需解锁"}))

    passed = sum(1 for s in report["steps"] if s["passed"])
    failed = sum(1 for s in report["steps"] if not s["passed"])
    report["finished_at"] = datetime.now().isoformat(timespec="seconds")
    report["summary"] = {
        "passed": passed,
        "failed": failed,
        "all_passed": failed == 0,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="完整审核策略联调验证")
    parser.add_argument("--token", help="docx file_token，默认取 AUDIT_DOC_TOKENS[0]")
    parser.add_argument("--out", default="verify_full_policy_report.json", help="报告输出路径")
    args = parser.parse_args()

    token = args.token or (demo.AUDIT_DOC_TOKENS[0] if demo.AUDIT_DOC_TOKENS else None)
    if not token:
        print("FAIL: 未配置文档 token，请设置 AUDIT_DOC_TOKENS 或 --token")
        return 1

    print("=" * 60)
    print(f"完整策略验证开始 | token={token}")
    print(f"敏感词库: {demo.SENSITIVE_WORDS}")
    print(f"当前默认策略: {demo.normalize_audit_actions()}")
    print("=" * 60)

    report = verify_document(token)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("=" * 60)
    print(f"报告已写入: {args.out}")
    print(f"汇总: {report['summary']}")
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
