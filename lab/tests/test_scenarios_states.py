"""Unit test state machine Scenario Driver + template skenario."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scenario


class TestTransitions(unittest.TestCase):
    def test_happy_path_approved(self):
        path = [
            scenario.STATE_IDLE, scenario.STATE_PRECHECK, scenario.STATE_RECONNAISSANCE,
            scenario.STATE_CANARY_EVENT, scenario.STATE_EVIDENCE_VALIDATION,
            scenario.STATE_POLICY_EVALUATION, scenario.STATE_POLICY_APPROVED,
            scenario.STATE_TARGET_DRAINED, scenario.STATE_CANARY_QUARANTINED,
            scenario.STATE_HEALTH_VERIFICATION, scenario.STATE_RECOVERY,
            scenario.STATE_COMPLETE,
        ]
        for current, nxt in zip(path, path[1:]):
            self.assertTrue(scenario.valid_transition(current, nxt), f"{current}->{nxt}")

    def test_rejected_path(self):
        path = [
            scenario.STATE_POLICY_EVALUATION, scenario.STATE_POLICY_REJECTED,
            scenario.STATE_REJECTION_RECORDED, scenario.STATE_SERVICE_PRESERVED,
            scenario.STATE_COMPLETE,
        ]
        for current, nxt in zip(path, path[1:]):
            self.assertTrue(scenario.valid_transition(current, nxt), f"{current}->{nxt}")

    def test_skip_probe_not_allowed(self):
        self.assertFalse(scenario.valid_transition(scenario.STATE_IDLE, scenario.STATE_CANARY_EVENT))

    def test_complete_to_recovery_not_allowed(self):
        self.assertFalse(scenario.valid_transition(scenario.STATE_COMPLETE, scenario.STATE_RECOVERY))

    def test_terminal_contains_expected(self):
        self.assertEqual(
            scenario.TERMINAL_STATES,
            {scenario.STATE_COMPLETE, scenario.STATE_FAILED, scenario.STATE_CANCELLED},
        )


class TestScenarioTemplates(unittest.TestCase):
    def test_all_three_present(self):
        expected = {
            "containment_allowed",
            "containment_blocked_survivor_down",
            "containment_blocked_evidence_invalid",
        }
        self.assertTrue(expected.issubset(scenario.SCENARIOS.keys()))

    def test_negative_group_validation_present(self):
        for scenario_name in (
            "containment_blocked_survivor_down",
            "containment_blocked_evidence_invalid",
        ):
            self.assertIn("Penolakan", scenario.SCENARIOS[scenario_name], scenario_name)


class TestPlanFor(unittest.TestCase):
    def make_runner(self):
        return scenario.Runner(deps=None, config={})

    def test_approved_plan_contains_containment_steps(self):
        runner = self.make_runner()
        plan = runner.plan_for({"run_id": "r", "scenario": "containment_allowed"})
        states = [state for state, _ in plan]
        self.assertIn(scenario.STATE_TARGET_DRAINED, states)
        self.assertIn(scenario.STATE_CANARY_QUARANTINED, states)
        self.assertIn(scenario.STATE_HEALTH_VERIFICATION, states)
        self.assertEqual(states[-1], scenario.STATE_COMPLETE)
        self.assertNotIn(scenario.STATE_POLICY_REJECTED, states)

    def test_rejected_plan_preserves_service(self):
        runner = self.make_runner()
        plan = runner.plan_for({"run_id": "r", "scenario": "containment_blocked_survivor_down"})
        states = [state for state, _ in plan]
        self.assertIn(scenario.STATE_POLICY_REJECTED, states)
        self.assertIn(scenario.STATE_SERVICE_PRESERVED, states)
        self.assertEqual(states[-1], scenario.STATE_COMPLETE)
        self.assertNotIn(scenario.STATE_TARGET_DRAINED, states)

    def test_evidence_invalid_shares_rejection_branch(self):
        runner = self.make_runner()
        plan = runner.plan_for({"run_id": "r", "scenario": "containment_blocked_evidence_invalid"})
        states = [state for state, _ in plan]
        self.assertIn(scenario.STATE_SERVICE_PRESERVED, states)
        self.assertNotIn(scenario.STATE_TARGET_DRAINED, states)


class TestRunnerExecution(unittest.TestCase):
    """Runner.execute dengan deps palsu: cancel dan kegagalan tengah jalan."""

    def make_runner(self, deps, config=None):
        return scenario.Runner(deps=deps, config=config or {})

    def test_cancel_before_first_step(self):
        deps = CancelDeps(cancelled=True)
        runner = self.make_runner(deps)
        result = runner.execute({"run_id": "r", "scenario": "containment_allowed"})
        self.assertEqual(result["state"], scenario.STATE_CANCELLED)
        self.assertIn(scenario.STATE_CANCELLED, deps.states)

    def test_scenario_error_becomes_failed(self):
        class FailDeps(CancelDeps):
            def backend_states(self):
                raise ScenarioError("backend_status_tidak_terbaca")

        deps = FailDeps()
        runner = self.make_runner(deps)
        result = runner.execute({"run_id": "r", "scenario": "containment_allowed"})
        self.assertEqual(result["state"], scenario.STATE_FAILED)

    def test_unexpected_error_becomes_failed(self):
        class CrashDeps(CancelDeps):
            def backend_states(self):
                raise KeyError("unexpected")

        deps = CrashDeps()
        runner = self.make_runner(deps)
        result = runner.execute({"run_id": "r", "scenario": "containment_allowed"})
        self.assertEqual(result["state"], scenario.STATE_FAILED)

    def test_parse_iso_guards(self):
        self.assertIsNone(scenario.parse_iso(None))
        self.assertIsNone(scenario.parse_iso("not-a-date"))
        parsed = scenario.parse_iso("2026-01-01T00:00:00+00:00")
        self.assertEqual(parsed.year, 2026)


class CancelDeps:
    def __init__(self, cancelled=False):
        self.states = []
        self._cancelled = cancelled

    def enter_state(self, run_id, state, detail=None):
        self.states.append(state)

    def cancelled(self, run_id):
        return self._cancelled

    def paused(self, run_id):
        return False

    def record_step(self, run_id, state, detail):
        pass

    def finalize_metrics(self, run_id):
        pass


if __name__ == "__main__":
    unittest.main()
