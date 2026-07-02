# -*- coding: utf-8 -*-
"""验证审核处理策略实现（纯逻辑 + Flask 路由 + mock 集成）。"""
import importlib
import sys
import unittest
from unittest.mock import patch

# 确保从 demo 目录导入
sys.path.insert(0, ".")
import demo  # noqa: E402
importlib.reload(demo)


class PolicyLogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import demo as d
        cls.d = d

    def test_normalize_default_log_only(self):
        self.assertEqual(self.d.normalize_audit_actions(["log_only"]), ["log_only"])

    def test_normalize_combo_drops_log_only(self):
        actions = self.d.normalize_audit_actions(["log_only", "replace", "notify"])
        self.assertEqual(actions, ["replace", "notify"])

    def test_normalize_invalid_filtered(self):
        actions = self.d.normalize_audit_actions(["replace", "invalid", "notify"])
        self.assertEqual(actions, ["replace", "notify"])

    def test_build_highlight_elements(self):
        elems = self.d.build_text_elements_for_policy(
            "这里有暴力内容", ["暴力"], "highlight", highlight_color=3,
        )
        self.assertEqual(len(elems), 3)
        self.assertEqual(elems[0]["text_run"]["content"], "这里有")
        self.assertEqual(elems[1]["text_run"]["content"], "暴力")
        self.assertIn("background_color", elems[1]["text_run"]["text_element_style"])
        self.assertEqual(elems[2]["text_run"]["content"], "内容")

    def test_build_replace_elements(self):
        elems = self.d.build_text_elements_for_policy(
            "测试敏感词在这里", ["测试敏感"], "replace", mask_text="***",
        )
        texts = [e["text_run"]["content"] for e in elems]
        self.assertIn("***", texts)
        self.assertNotIn("测试敏感", "".join(texts))

    def test_apply_audit_policies_log_only(self):
        result = self.d.apply_audit_policies(
            "fake_token", "docx",
            {"passed": False, "hits": ["暴力"]},
            actions=["log_only"],
        )
        self.assertIn("note", result)
        self.assertEqual(result.get("results"), {})

    @patch("demo.apply_docx_content_policy")
    @patch("demo.apply_notify_policy")
    @patch("builtins.print")
    def test_apply_audit_policies_replace_notify(self, _print, mock_notify, mock_docx):
        mock_docx.return_value = {"ok": True, "blocks_updated": 2, "action": "replace"}
        mock_notify.return_value = {"ok": True, "sent_to": ["ou_test"]}

        result = demo.apply_audit_policies(
            "doc_token", "docx",
            {"passed": False, "hits": ["暴力"]},
            title="测试文档",
            actions=["replace", "notify"],
        )
        self.assertIn("replace", result["results"])
        self.assertIn("notify", result["results"])
        mock_docx.assert_called_once()
        mock_notify.assert_called_once()

    def test_apply_audit_policies_highlight_skips_non_docx(self):
        result = self.d.apply_audit_policies(
            "sheet_token", "sheet",
            {"passed": False, "hits": ["暴力"]},
            actions=["highlight"],
        )
        skipped = {s["action"] for s in result.get("skipped", [])}
        self.assertIn("highlight", skipped)

    @patch("builtins.print")
    def test_audit_file_attaches_policy_on_fail(self, _print):
        with patch.object(demo, "fetch_file_content", return_value=("含暴力内容", None)):
            with patch.object(demo, "apply_audit_policies") as mock_apply:
                mock_apply.return_value = {"configured_actions": ["replace"], "results": {}}
                result = demo.audit_file("tok", "docx", source="test")
        self.assertFalse(result["passed"])
        self.assertIn("policy_actions", result)
        mock_apply.assert_called_once()

    def test_get_audit_policy_config_shape(self):
        cfg = self.d.get_audit_policy_config()
        for key in ("actions", "mask_text", "notify_user_ids", "highlight_color", "descriptions"):
            self.assertIn(key, cfg)


class FlaskRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import demo as d
        cls.d = d
        cls.client = d.app.test_client()

    def test_audit_policy_route(self):
        res = self.client.get("/audit/policy")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("actions", data)
        self.assertIn("required_permissions", data)
        self.assertIn("example_config", data)

    def test_diagnose_includes_audit_policy(self):
        with patch.object(demo, "collect_all_folder_files", return_value=[]):
            with patch.object(demo, "check_subscribe_status", return_value={"is_subscribe": True}):
                res = self.client.get("/diagnose")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("audit_policy", data)
        self.assertIn("actions", data["audit_policy"])


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(PolicyLogicTests))
    suite.addTests(loader.loadTestsFromTestCase(FlaskRouteTests))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("PASS: all verification tests passed")
        return 0
    print(f"FAIL: failures={len(result.failures)} errors={len(result.errors)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
