from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .models import ActionProposal, ActionResult, ActionStatus, GuardDecision, GuardStatus


@dataclass
class BuiltAction:
    command: List[str]
    adapter: str
    system_change: bool = False


class ActEngine:
    """Execute approved actions through conservative adapters.

    v0.4 distinguishes internal, simulation, and system adapters.  Commands are
    dry-run unless ``execute=True``.  System adapters additionally require
    ``allow_system_changes=True``.
    """

    def execute(
        self,
        proposal: ActionProposal,
        decision: GuardDecision,
        execute: bool = False,
        *,
        allow_system_changes: bool = False,
        is_rollback: bool = False,
    ) -> ActionResult:
        if decision.status != GuardStatus.APPROVED.value:
            return ActionResult(
                proposal_id=proposal.proposal_id,
                status=ActionStatus.SKIPPED.value,
                command="",
                stdout="",
                stderr=f"guard decision is not APPROVED: {decision.status}",
                returncode=1,
                adapter="none",
                is_rollback=is_rollback,
            )

        built = self._build_action(proposal)
        if not built:
            return ActionResult(
                proposal_id=proposal.proposal_id,
                status=ActionStatus.SKIPPED.value,
                command="",
                stdout="",
                stderr=f"no executable adapter for action: {proposal.action}",
                returncode=1,
                adapter="none",
                is_rollback=is_rollback,
            )

        command_text = " ".join(shlex.quote(x) for x in built.command)
        if not execute:
            return ActionResult(
                proposal_id=proposal.proposal_id,
                status=ActionStatus.DRY_RUN.value,
                command=command_text,
                stdout="dry-run: action was not executed",
                stderr="",
                returncode=0,
                adapter=built.adapter,
                is_rollback=is_rollback,
            )

        if built.system_change and not allow_system_changes:
            return ActionResult(
                proposal_id=proposal.proposal_id,
                status=ActionStatus.SKIPPED.value,
                command=command_text,
                stdout="",
                stderr="system-changing adapter requires --allow-system-changes",
                returncode=1,
                adapter=built.adapter,
                is_rollback=is_rollback,
            )

        if built.adapter == "internal":
            return ActionResult(
                proposal_id=proposal.proposal_id,
                status=ActionStatus.EXECUTED.value,
                command=command_text,
                stdout="internal action accepted; state will be persisted by the controller",
                stderr="",
                returncode=0,
                adapter=built.adapter,
                is_rollback=is_rollback,
            )

        proc = subprocess.run(built.command, capture_output=True, text=True, check=False)
        return ActionResult(
            proposal_id=proposal.proposal_id,
            status=ActionStatus.EXECUTED.value if proc.returncode == 0 else ActionStatus.FAILED.value,
            command=command_text,
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            adapter=built.adapter,
            is_rollback=is_rollback,
        )

    def _build_action(self, proposal: ActionProposal) -> Optional[BuiltAction]:
        if proposal.action == "switch_route":
            route = proposal.parameters.get("route", "secondary")
            # Route manipulation is environment-specific.  The built-in adapter
            # intentionally records a simulation rather than changing routes.
            return BuiltAction(
                ["echo", f"KANSOKU route switch simulated: target={proposal.target}, route={route}"],
                adapter="simulation",
            )

        if proposal.action == "increase_observation_rate":
            interval = proposal.parameters.get("interval_sec", 5)
            return BuiltAction(
                ["internal", "set-observation-interval", proposal.target, str(interval)],
                adapter="internal",
            )

        if proposal.action == "restore_observation_rate":
            interval = proposal.parameters.get("interval_sec", 30)
            return BuiltAction(
                ["internal", "set-observation-interval", proposal.target, str(interval)],
                adapter="internal",
            )

        if proposal.action == "safe_hold":
            reason = proposal.parameters.get("reason", "unknown")
            return BuiltAction(
                ["echo", f"KANSOKU safe hold simulated: target={proposal.target}, reason={reason}"],
                adapter="simulation",
            )

        if proposal.action == "manual_release":
            return BuiltAction(
                ["echo", f"KANSOKU manual release simulated: target={proposal.target}"],
                adapter="simulation",
            )

        if proposal.action == "tc_netem_apply":
            dev = proposal.parameters.get("dev")
            delay_ms = proposal.parameters.get("delay_ms", 0)
            loss_pct = proposal.parameters.get("loss_pct", 0)
            if not dev:
                return None
            return BuiltAction(
                [
                    "tc",
                    "qdisc",
                    "replace",
                    "dev",
                    str(dev),
                    "root",
                    "netem",
                    "delay",
                    f"{delay_ms}ms",
                    "loss",
                    f"{loss_pct}%",
                ],
                adapter="system",
                system_change=True,
            )

        if proposal.action == "tc_netem_clear":
            dev = proposal.parameters.get("dev")
            if not dev:
                return None
            return BuiltAction(
                ["tc", "qdisc", "del", "dev", str(dev), "root"],
                adapter="system",
                system_change=True,
            )

        return None
