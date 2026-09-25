"""AR-0140 one-command board acceptance and hostile release/gate checks."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.autonomous_orchestrator import OrchestratorError, graph_digest, validate_graph
from scripts.board_acceptance import (
    BoardAcceptanceError, compile_project_graph, digest, run_acceptance, verify_evidence,
    verify_release_provenance,
)


class BoardAcceptanceAR0140Tests(unittest.TestCase):
    def test_one_operator_entrypoint_builds_runs_routes_and_exports_accepted_project(self):
        provenance = {
            "umbrella_origin": "https://github.com/martin-beck/agent-workflow.git",
            "umbrella_commit": "78cff9000086e4fc73ec6a86b259b4f85e29f46b",
            "umbrella_manifest_digest": "sha256:" + "1" * 64,
            "runtime_origin": "https://github.com/martin-beck/agent-workflow-runtime.git",
            "runtime_release": "v0.1.8", "runtime_release_commit": "2" * 40,
            "runtime_under_test_commit": "3" * 40,
        }
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "new-complex-project"
            with patch("scripts.board_acceptance.verify_release_provenance", return_value=provenance):
                result = run_acceptance(name="board-project", organization="agent-team",
                                        workspace=workspace, umbrella_root=Path(temporary))
            self.assertEqual(result["status"], "accepted")
            self.assertEqual((result["task_count"], result["session_count"]), (7, 7))
            state = workspace / "state"
            graph = json.loads((state / "generated-task-graph.json").read_text())
            self.assertEqual(len(graph["tasks"]), 7)
            self.assertEqual({item["profile_id"] for item in graph["tasks"]}, {"fake-alpha", "fake-beta"})
            self.assertTrue(all(item["dependencies"] is not None for item in graph["tasks"]))
            for task in graph["tasks"]:
                authority = json.loads((state / "run" / (task["id"] + ".authority.json")).read_text())
                self.assertEqual([item["authority"] for item in authority["admission"]["trace"]],
                                 ["coordinator", "awq", "awg", "ui"])
                self.assertEqual([item["authority"] for item in authority["acceptance"]["trace"]],
                                 ["awq", "awg", "ui"])
                self.assertTrue(all(item["task_revision"] == 1 for item in
                                    authority["admission"]["trace"] + authority["acceptance"]["trace"]))
                coordinator = json.loads((state / "run" / (task["id"] + ".coordinator.json")).read_text())
                self.assertEqual(coordinator["task"]["status"], "done")
                self.assertEqual(sum(item["kind"] == "reconciled" for item in coordinator["events"]), 1)
            evidence = json.loads(Path(result["evidence"]).read_text())
            self.assertEqual(verify_evidence(evidence)["status"], "verified")
            evidence["accounting"]["sessions"] = 0
            with self.assertRaisesRegex(BoardAcceptanceError, "digest_or_terminal"):
                verify_evidence(evidence)
            forged = json.loads(Path(result["evidence"]).read_text())
            forged["transcript"] = "unexpected"
            forged["evidence_digest"] = digest({key: value for key, value in forged.items() if key != "evidence_digest"})
            with self.assertRaisesRegex(BoardAcceptanceError, "evidence_shape_invalid"):
                verify_evidence(forged)

    def test_compiler_creates_dependency_graph_and_rejects_provider_profile(self):
        graph = compile_project_graph("hostile-project", "sha256:" + "a" * 64,
                                      {"tree-a": "sha256:" + "b" * 64,
                                       "tree-b": "sha256:" + "c" * 64})
        self.assertEqual(graph["tasks"][2]["dependencies"], [graph["tasks"][0]["id"], graph["tasks"][1]["id"]])
        graph["tasks"][0]["profile_id"] = "live-provider"
        graph["approval"].update(status="approved", decision_id="DEC-TEST")
        graph["approval"]["graph_digest"] = graph_digest(graph)
        with self.assertRaisesRegex(OrchestratorError, "only_deterministic_fake_profiles"):
            validate_graph(graph, 2)

    def test_compiler_rejects_invalid_project_identity(self):
        with self.assertRaisesRegex(BoardAcceptanceError, "invalid_project_identity"):
            compile_project_graph("../outside", "sha256:" + "a" * 64,
                                  {"tree-a": "sha256:" + "b" * 64,
                                   "tree-b": "sha256:" + "c" * 64})

    def test_provenance_fails_closed_when_canonical_manifest_is_absent_or_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "project-manifest.yaml").write_text("project: altered\n")
            with self.assertRaisesRegex(BoardAcceptanceError, "manifest_digest_mismatch"):
                verify_release_provenance(root, Path(__file__).resolve().parents[1])


if __name__ == "__main__":
    unittest.main()
