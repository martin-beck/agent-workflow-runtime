import copy
import unittest

from scripts.interactive_session import InteractionBinding, InteractionError, InteractiveSession, replay


class InteractiveSessionTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.binding = InteractionBinding("SES-AR0132-1", 2, "LSE-AR0132-1", 3)

    def session(self, protocol="fake-alpha", **kwargs):
        return InteractiveSession(self.binding, protocol=protocol, lease_expires_at=200,
                                  clock=lambda: self.now, **kwargs)

    def begin(self, session):
        return session.input({"session_id": self.binding.session_id, "task_revision": 2,
                              "lease_id": self.binding.lease_id, "lease_fence": 3,
                              "correlation_id": "COR-1", "prompt": "hello", "deadline": 150})

    def test_two_native_shapes_normalize_and_replay_identically(self):
        streams = []
        for protocol, raw in (("fake-alpha", '{"type":"message","data":{"text":"hello token=secret"}}'),
                              ("fake-beta", '{"event":"assistant_delta","payload":{"text":"hello token=secret"}}')):
            session = self.session(protocol)
            self.begin(session)
            session.feed("stdout", raw)
            session.end_turn("COR-1")
            session.close()
            self.assertEqual(session.events[0]["kind"], "assistant")
            self.assertEqual(session.events[0]["text"], "hello token=REDACTED")
            self.assertEqual(session.events[0]["correlation_id"], "COR-1")
            self.assertEqual([e["sequence"] for e in session.events], [1, 2, 3])
            self.assertEqual(replay(session.events), session.events)
            streams.append(session.events)
        self.assertEqual(streams[0], streams[1])

    def test_tool_status_stdout_stderr_and_explicit_turn_end(self):
        session = self.session("fake-beta")
        self.begin(session)
        session.feed("stdout", '{"event":"tool_invocation","payload":{"name":"read"}}')
        session.feed("stderr", '{"event":"lifecycle","payload":{"state":"working"}}')
        with self.assertRaisesRegex(InteractionError, "correlation_mismatch"):
            session.end_turn("COR-WRONG")
        end = session.end_turn("COR-1")
        self.assertEqual([event["kind"] for event in session.events], ["tool", "status", "end_turn"])
        self.assertEqual(end["correlation_id"], "COR-1")

    def test_fences_reject_stale_cross_session_oversized_and_unsolicited(self):
        s = self.session()
        with self.assertRaisesRegex(InteractionError, "unsolicited_output"):
            s.feed("stdout", '{}')
        bad = {"session_id": "SES-OTHER", "task_revision": 2, "lease_id": self.binding.lease_id,
               "lease_fence": 3, "correlation_id": "COR-1", "prompt": "x", "deadline": 150}
        with self.assertRaisesRegex(InteractionError, "stale_binding"):
            s.input(bad)
        with self.assertRaisesRegex(InteractionError, "cross_session_input"):
            s.input({**bad, "session_id": self.binding.session_id}, session_id="SES-OTHER")
        self.begin(s)
        with self.assertRaisesRegex(InteractionError, "frame_too_large"):
            s.feed("stdout", b"x" * (s.MAX_FRAME + 1))
        self.now = 200
        with self.assertRaisesRegex(InteractionError, "lease_stale"):
            s.end_turn("COR-1")

    def test_malformed_frames_backpressure_and_bad_replay_fail_closed(self):
        s = self.session()
        self.begin(s)
        with self.assertRaisesRegex(InteractionError, "native_event_malformed"):
            s.feed("stdout", '{"type":"unknown","data":{}}')
        s = self.session(queue_limit=1)
        self.begin(s)
        s.feed("stdout", '{"type":"message","data":{"text":"ok"}}')
        with self.assertRaisesRegex(InteractionError, "backpressure_exceeded"):
            s.feed("stderr", '{"type":"message","data":{"text":"again"}}')
        s.end_turn("COR-1")
        s.close()
        altered = copy.deepcopy(s.events)
        altered[0]["text"] = "tampered"
        with self.assertRaisesRegex(InteractionError, "replay_digest_invalid"):
            replay(altered)

    def test_prompt_deadline_terminal_and_event_bounds(self):
        s = self.session()
        with self.assertRaisesRegex(InteractionError, "deadline_invalid"):
            s.input({"session_id": self.binding.session_id, "task_revision": 2,
                     "lease_id": self.binding.lease_id, "lease_fence": 3,
                     "correlation_id": "COR-1", "prompt": "x", "deadline": 201})
        self.begin(s)
        s.end_turn("COR-1")
        s.close("timed_out")
        with self.assertRaisesRegex(InteractionError, "session_terminal"):
            self.begin(s)

    def test_cancel_fences_late_output_and_requires_cleanup_ack(self):
        s = self.session()
        self.begin(s)
        operation = "OP-SES-AR0132-CANCEL"
        self.assertEqual(s.request_cancel(operation)["status"], "cancelling")
        with self.assertRaisesRegex(InteractionError, "session_cancelling"):
            s.feed("stdout", '{"type":"message","data":{"text":"late"}}')
        with self.assertRaisesRegex(InteractionError, "cancel_cleanup_unconfirmed"):
            s.acknowledge_cancel(operation, process_group_clean=False)
        terminal = s.acknowledge_cancel(operation, process_group_clean=True)
        self.assertEqual(terminal["status"], "cancelled")
        with self.assertRaisesRegex(InteractionError, "session_terminal"):
            s.acknowledge_cancel(operation, process_group_clean=True)


if __name__ == "__main__":
    unittest.main()
