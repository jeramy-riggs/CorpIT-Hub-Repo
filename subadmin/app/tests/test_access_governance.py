#!/usr/bin/env python3
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import access_governance as AG  # noqa: E402


class Capability:
    def __init__(self, key, label):
        self.key = key
        self.label = label


class AccessGovernanceTests(unittest.TestCase):
    def test_ad_timestamp_is_formatted_for_reviewers(self):
        self.assertEqual(AG._changed_at("20260921183033.0Z"), "2026-09-21 18:30 UTC")
        self.assertEqual(AG._changed_at(None), "unknown")

    def test_registry_joins_ad_to_enforcement_and_flags_drift(self):
        groups = [
            {"key": "saas-ith-ro", "name": "SaaS-ITH-RO",
             "description": "Read-only Hub access", "owner": "CorpIT",
             "members": ["cn=user one,ou=people,dc=example"], "member_count": 1,
             "scope": "global", "security": True, "changed": "2026-10-01"},
            {"key": "saas-ith-copy", "name": "SaaS-ITH-Copy",
             "description": "", "owner": "",
             "members": ["cn=user one,ou=people,dc=example"], "member_count": 1,
             "scope": "global", "security": True, "changed": "2026-10-01"},
        ]
        registry, findings = AG.assemble(
            groups,
            {"saas-ith-ro": "viewer", "saas-ith-missing": "operator"},
            {"directory.sync": ["saas-ith-ro"]},
            [Capability("directory.sync", "Start a directory sync")],
            [("corpit.nrpi.local", {"mode": "groups", "groups": ["SaaS-ITH-RO"]})],
        )
        by_key = {row["key"]: row for row in registry}
        tier1 = by_key["saas-ith-ro"]
        self.assertEqual(tier1["role"], "viewer")
        self.assertEqual(tier1["capabilities"], ["Start a directory sync"])
        self.assertEqual(tier1["sites"], ["corpit.nrpi.local"])
        self.assertEqual(tier1["duplicates"], ["saas-ith-copy"])
        self.assertEqual(by_key["saas-ith-missing"]["level"], "critical")
        messages = {(item["group"], item["message"]) for item in findings}
        self.assertIn(("SaaS-ITH-Copy", "No AD managedBy owner"), messages)
        self.assertIn(("SaaS-ITH-Copy", "No AD purpose description"), messages)

    def test_proposal_validation_and_round_trip(self):
        form = {
            "action": "review",
            "group_name": "SaaS-ITH-RO",
            "purpose": "Quarterly review of read-only Hub access",
            "business_owner": "CorpIT Operations",
            "technical_owner": "CorpIT Platform",
            "review_cycle": "quarterly",
            "resources": "corpit.nrpi.local\nHub read pages",
            "notes": "Confirm direct membership only.",
        }
        data, errors = AG.validate_proposal(form)
        self.assertEqual(errors, [])
        self.assertEqual(data["resources"], ["corpit.nrpi.local", "Hub read pages"])

        handle, path = tempfile.mkstemp(prefix="access-governance-", suffix=".db")
        os.close(handle)
        try:
            AG.init(path)
            con = sqlite3.connect(path)
            con.row_factory = sqlite3.Row
            proposal_id = AG.save_proposal(con, "tester@example.com", data)
            rows = AG.proposals(con)
            self.assertEqual(proposal_id, 1)
            self.assertEqual(rows[0]["group_name"], "SaaS-ITH-RO")
            self.assertEqual(rows[0]["resources"], data["resources"])
            self.assertEqual(rows[0]["status"], "draft")
            con.close()
        finally:
            os.unlink(path)

    def test_invalid_proposal_cannot_escape_group_standard(self):
        _, errors = AG.validate_proposal({
            "action": "change", "group_name": "Domain Admins", "purpose": "too short",
            "business_owner": "", "technical_owner": "", "review_cycle": "never",
            "resources": "", "notes": "",
        })
        self.assertGreaterEqual(len(errors), 5)


class AccessGovernanceRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app
        cls.A = app

    def client(self, group, role):
        client = self.A.app.test_client()
        with client.session_transaction() as session:
            session["user"] = "tester@example.com"
            session["auth_at"] = int(time.time())
            session["csrf"] = "route-test-token"
            session["sso"] = {
                "user": "tester@example.com", "name": "Test Operator", "role": role,
                "groups": [group], "can_write_prod": False, "auth": "entra",
            }
        return client

    @staticmethod
    def valid_form():
        return {
            "csrf": "route-test-token", "action": "review",
            "group_name": "SaaS-ITH-RO",
            "purpose": "Quarterly review of read-only Hub access",
            "business_owner": "CorpIT Operations", "technical_owner": "CorpIT Platform",
            "review_cycle": "quarterly", "resources": "corpit.nrpi.local", "notes": "",
        }

    def test_tier2_can_record_proposal_without_directory_write(self):
        client = self.client("saas-ith-hd", "operator")
        with mock.patch.object(AG, "save_proposal", return_value=77) as save, \
             mock.patch.object(self.A, "audit") as audit:
            response = client.post("/access-governance/proposals", data=self.valid_form())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/console#iam/governance")
        save.assert_called_once()
        audit.assert_called_once()

    def test_viewer_cannot_record_proposal(self):
        client = self.client("saas-ith-ro", "viewer")
        with mock.patch.object(AG, "save_proposal") as save:
            response = client.post("/access-governance/proposals", data=self.valid_form())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/console")
        save.assert_not_called()

    def test_design_lab_renders_live_registry_without_a_write_path(self):
        client = self.client("saas-ith-ro", "viewer")

        def build_lab(_app, ctx):
            ctx.update(
                access_registry=[{
                    "name": "SaaS-ITH-RO", "description": "Read-only Hub access",
                    "owner": "CorpIT", "member_count": 1, "scope": "global",
                    "changed": "2026-10-07", "role": "viewer", "capabilities": [],
                    "sites": ["corpit.nrpi.local"], "level": "healthy", "issues": [],
                    "missing": False, "referenced": True,
                }],
                access_findings=[], access_directory_error=None,
                access_summary={"groups": 1, "attention": 0, "unowned": 0, "unreferenced": 0},
                access_proposals=[], access_proposal_actions=AG.PROPOSAL_ACTIONS,
                access_review_cycles=AG.REVIEW_CYCLES,
            )

        with mock.patch.object(self.A, "site_policy", return_value={"sites": {}}), \
             mock.patch.object(self.A, "permission_policy", return_value={}), \
             mock.patch.object(AG, "build", side_effect=build_lab):
            response = client.get("/access-governance-lab")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Access workspace", response.data)
        self.assertIn(b"Sites &amp; access paths", response.data)
        self.assertIn(b"Start with Access Portal", response.data)
        self.assertIn(b"Start review", response.data)
        self.assertIn(b"Needs attention", response.data)
        self.assertIn(b"Review approver groups", response.data)
        self.assertIn(b"Everyone signed in", response.data)
        self.assertIn(b"ZPA segment", response.data)
        self.assertIn(b"site-route-zpa-policy", response.data)
        self.assertIn(b"CorpIT Reporting Allow", response.data)
        self.assertIn(b"CorpIT Restricted Access Deny", response.data)
        self.assertIn(b"Locked down", response.data)
        self.assertIn(b"Everyone with CorpIT sign-in", response.data)
        self.assertIn(b"Entra enterprise applications", response.data)
        self.assertIn(b"SSO-CorpIT Hub", response.data)
        self.assertIn(b"e2791948-8032-4560-863c-bb0fb0564e72", response.data)
        self.assertIn(b"SSO-CorpIT - Operations Hub", response.data)
        self.assertIn(b"Access Portal", response.data)
        self.assertIn(b"Separate governance boundary", response.data)
        self.assertIn(b"Access Portal approver groups", response.data)
        self.assertIn(b"SaaS-CorpITHub-Security \\u0026 Compliance", response.data)
        self.assertIn(b"approver-manager", response.data)
        self.assertIn(b"approver-cto", response.data)
        self.assertIn(b"No live AD role mapping", response.data)
        self.assertIn(b"Open separate Approval Access", response.data)
        self.assertIn(b"SaaS-ITH-RO", response.data)
        self.assertNotIn(b"<form", response.data)

    def _console_with_registry(self, client):
        def build(_app, ctx):
            ctx.update(
                access_registry=[{
                    "key": "saas-ith-ro", "name": "SaaS-ITH-RO", "description": "Read-only Hub access",
                    "owner": "CorpIT", "member_count": 1, "scope": "global",
                    "changed": "2026-10-07", "role": "viewer", "capabilities": [],
                    "sites": ["corpit.nrpi.local"], "level": "healthy", "issues": [],
                    "missing": False, "referenced": True,
                }],
                access_findings=[], access_directory_error=None,
                access_summary={"groups": 1, "attention": 0, "unowned": 0, "unreferenced": 0},
                access_proposals=[], access_proposal_actions=AG.PROPOSAL_ACTIONS,
                access_review_cycles=AG.REVIEW_CYCLES,
            )
        with mock.patch.object(AG, "build", side_effect=build):
            return client.get("/console")

    def test_console_review_access_tab_embeds_the_workspace(self):
        response = self._console_with_registry(self.client("saas-ith-sa", "platform-owner"))
        self.assertEqual(response.status_code, 200)
        body = response.data
        self.assertIn(b'data-tab="governance" aria-selected="true">Review access<', body)
        self.assertIn(b'data-tab="permissions"', body)
        self.assertIn(b'data-tab="roles"', body)
        self.assertNotIn(b'data-tab="siteaccess"', body)
        self.assertNotIn(b'<nav class="ledger-identity-nav"', body)
        self.assertIn(b"data-access-workspace", body)
        self.assertIn(b"data-agw-sites", body)
        self.assertIn(b"data-access-proposal-form", body)
        self.assertIn(b"Recent proposals", body)
        self.assertEqual(body.count(b'id="ag-group"'), 1)
        self.assertEqual(body.count(b"data-access-workspace"), 1)

    def test_console_workspace_is_review_only_for_viewer(self):
        response = self._console_with_registry(self.client("saas-ith-ro", "viewer"))
        self.assertEqual(response.status_code, 200)
        body = response.data
        self.assertIn(b"data-access-workspace", body)
        self.assertNotIn(b"data-access-proposal-form", body)
        self.assertIn(b"Review-only access", body)
        self.assertIn(b"Proposal history", body)
        self.assertNotIn(b">Record proposal<", body)

    def test_console_keeps_console_data_policy_rows(self):
        import app as A
        seen = {}
        real = A.change_control.build

        def spy(app_mod, ctx):
            seen["rows"] = list(ctx.get("policy_rows") or [])
            return real(app_mod, ctx)

        with mock.patch.object(A.change_control, "build", side_effect=spy):
            response = self._console_with_registry(self.client("saas-ith-sa", "platform-owner"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all("sub_id" in rule for _fqdn, rule in seen.get("rows", [])),
                        "access workspace must not replace console_data's policy_rows")


if __name__ == "__main__":
    unittest.main()
