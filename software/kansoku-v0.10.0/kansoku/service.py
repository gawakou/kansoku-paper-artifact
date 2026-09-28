from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import time
from typing import Any, Dict, Iterable, List, Optional

from .agent import AgentCommandError, Iperf3Agent, PingAgent, SimulatedNetworkAgent
from .artifacts import save_collection_run
from .controller import SafeController
from .hub import Hub
from .inventory import ManagedTarget
from .models import CollectionResult, new_id, utc_now
from .scheduler import DueStatus, SchedulerCycle, parse_time
from .workflow import evaluate_and_persist


class ObservationService:
    """Persistent multi-target observation scheduler.

    v0.5 intentionally keeps execution single-process and conservative. A SQLite
    lease prevents two service instances from collecting the same fleet at once.
    System-changing actions are never enabled by this service; only low-risk
    proposals accepted by the target safety policy can be auto-processed.
    """

    LEASE_NAME = "observation-service"

    def __init__(
        self,
        hub: Hub,
        *,
        owner_id: Optional[str] = None,
        ping_agent: Optional[PingAgent] = None,
        iperf3_agent: Optional[Iperf3Agent] = None,
        simulated_agent: Optional[SimulatedNetworkAgent] = None,
    ):
        self.hub = hub
        self.owner_id = owner_id or f"{socket.gethostname()}-{new_id('svc')}"
        self.ping_agent = ping_agent or PingAgent()
        self.iperf3_agent = iperf3_agent or Iperf3Agent()
        self.simulated_agent = simulated_agent or SimulatedNetworkAgent()

    def interval_for(self, target: ManagedTarget) -> int:
        plan = self.hub.get_observation_plan(target.target)
        if plan:
            return max(1, int(plan.interval_sec))
        profile = self.hub.get_target_profile(target.target)
        if profile:
            return max(1, int(profile.normal_interval_sec))
        return 30

    def due_status(self, target: ManagedTarget, *, now: Optional[datetime] = None) -> DueStatus:
        now = now or datetime.now(timezone.utc)
        interval = self.interval_for(target)
        latest = self.hub.latest_scheduler_cycle(target.target)
        last_finished = parse_time(latest.finished_at) if latest else None
        next_due = last_finished + timedelta(seconds=interval) if last_finished else None
        due = bool(target.enabled and (next_due is None or now >= next_due))
        return DueStatus(
            target=target.target,
            enabled=target.enabled,
            interval_sec=interval,
            last_finished_at=last_finished.isoformat() if last_finished else None,
            next_due_at=next_due.isoformat() if next_due else None,
            due=due,
        )

    def fleet_status(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for target in self.hub.list_managed_targets(limit=1000):
            due = self.due_status(target)
            latest_state = self.hub.latest_state(target.target)
            latest_cycle = self.hub.latest_scheduler_cycle(target.target)
            rows.append(
                {
                    "target": target.to_dict(),
                    "due": due.to_dict(),
                    "state": latest_state.to_dict() if latest_state else None,
                    "latest_cycle": latest_cycle.to_dict() if latest_cycle else None,
                }
            )
        return rows

    def _persist_collection(self, result: CollectionResult, raw_dir: str) -> Path:
        self.hub.add_collection_run(result.run)
        self.hub.add_observations(result.observations)
        return save_collection_run(result.run, raw_dir)

    def _collect_real(
        self,
        target: ManagedTarget,
        *,
        cycle_number: int,
    ) -> tuple[List[str], int, List[str]]:
        run_ids: List[str] = []
        observation_count = 0
        messages: List[str] = []

        if target.ping_enabled:
            try:
                result = self.ping_agent.collect(
                    target.target,
                    count=target.ping_count,
                    timeout=target.ping_timeout_sec,
                )
                self._persist_collection(result, target.raw_dir)
                run_ids.append(result.run.run_id)
                observation_count += len(result.observations)
                if result.run.returncode != 0:
                    messages.append(f"ping rc={result.run.returncode}")
            except AgentCommandError as exc:
                messages.append(f"ping command error: {exc}")

        run_iperf = (
            target.iperf3_enabled
            and target.iperf3_every_n_cycles > 0
            and cycle_number % target.iperf3_every_n_cycles == 0
        )
        if run_iperf:
            try:
                result = self.iperf3_agent.collect(
                    target.target,
                    port=target.iperf3_port,
                    duration=target.iperf3_duration_sec,
                    parallel=target.iperf3_parallel,
                )
                self._persist_collection(result, target.raw_dir)
                run_ids.append(result.run.run_id)
                observation_count += len(result.observations)
                if result.run.returncode != 0:
                    messages.append(f"iperf3 rc={result.run.returncode}")
            except AgentCommandError as exc:
                messages.append(f"iperf3 command error: {exc}")

        return run_ids, observation_count, messages

    def _collect_simulated(
        self,
        target: ManagedTarget,
        profile: str,
    ) -> tuple[List[str], int, List[str]]:
        observations = self.simulated_agent.observe(target.target, profile=profile, count=1)
        inserted = self.hub.add_observations(observations)
        return [], inserted, [f"simulation profile={profile}"]

    def run_target(
        self,
        target: ManagedTarget,
        *,
        auto_control: bool = True,
        simulate_profile: Optional[str] = None,
    ) -> SchedulerCycle:
        started = utc_now()
        cycle_number = self.hub.count_scheduler_cycles(target.target) + 1
        run_ids: List[str] = []
        observation_count = 0
        messages: List[str] = []
        state_id: Optional[str] = None
        proposal_id: Optional[str] = None
        transaction_id: Optional[str] = None

        try:
            if simulate_profile:
                run_ids, observation_count, messages = self._collect_simulated(
                    target, simulate_profile
                )
            else:
                run_ids, observation_count, messages = self._collect_real(
                    target, cycle_number=cycle_number
                )

            if observation_count > 0:
                outcome = evaluate_and_persist(self.hub, target.target, limit=100)
                state_id = outcome.state.state_id
                if outcome.proposal:
                    proposal_id = outcome.proposal.proposal_id
                    if (
                        auto_control
                        and target.auto_process_low_risk
                        and outcome.proposal.risk_level == "low"
                    ):
                        controlled = SafeController(self.hub).process(
                            outcome.proposal,
                            execute=True,
                            allow_system_changes=False,
                        )
                        transaction_id = controlled.transaction.transaction_id
                        messages.append(
                            f"controller outcome={controlled.transaction.outcome}"
                        )

            if observation_count == 0:
                status = "FAILED"
                messages.append("no observations were collected")
            elif any("rc=" in item or "error" in item for item in messages):
                status = "PARTIAL"
            else:
                status = "SUCCESS"
        except Exception as exc:  # defensive boundary for long-running service
            status = "FAILED"
            messages.append(f"unhandled cycle error: {exc}")

        cycle = SchedulerCycle(
            target=target.target,
            owner_id=self.owner_id,
            status=status,
            started_at=started,
            finished_at=utc_now(),
            collection_run_ids=run_ids,
            observation_count=observation_count,
            state_id=state_id,
            proposal_id=proposal_id,
            transaction_id=transaction_id,
            message="; ".join(messages),
        )
        self.hub.add_scheduler_cycle(cycle)
        return cycle

    def run_once(
        self,
        *,
        target_name: Optional[str] = None,
        force: bool = False,
        auto_control: bool = True,
        simulate_profile: Optional[str] = None,
        lease_ttl_sec: int = 120,
    ) -> List[SchedulerCycle]:
        if not self.hub.acquire_scheduler_lease(
            self.LEASE_NAME, self.owner_id, ttl_sec=lease_ttl_sec
        ):
            lease = self.hub.get_scheduler_lease(self.LEASE_NAME)
            owner = lease.owner_id if lease else "unknown"
            raise RuntimeError(f"scheduler lease is held by {owner}")

        cycles: List[SchedulerCycle] = []
        try:
            targets: Iterable[ManagedTarget]
            if target_name:
                item = self.hub.get_managed_target(target_name)
                if not item:
                    raise ValueError(f"managed target not found: {target_name}")
                targets = [item]
            else:
                targets = self.hub.list_managed_targets(limit=1000, enabled_only=True)

            for target in targets:
                if not target.enabled:
                    continue
                due = self.due_status(target)
                if not force and not due.due:
                    continue
                cycles.append(
                    self.run_target(
                        target,
                        auto_control=auto_control,
                        simulate_profile=simulate_profile,
                    )
                )
            return cycles
        finally:
            self.hub.release_scheduler_lease(self.LEASE_NAME, self.owner_id)

    def run_loop(
        self,
        *,
        iterations: int = 0,
        poll_interval_sec: float = 1.0,
        target_name: Optional[str] = None,
        force_first: bool = False,
        auto_control: bool = True,
        simulate_profile: Optional[str] = None,
    ) -> List[SchedulerCycle]:
        if poll_interval_sec <= 0:
            raise ValueError("poll_interval_sec must be > 0")
        all_cycles: List[SchedulerCycle] = []
        iteration = 0
        try:
            while iterations == 0 or iteration < iterations:
                iteration += 1
                cycles = self.run_once(
                    target_name=target_name,
                    force=force_first and iteration == 1,
                    auto_control=auto_control,
                    simulate_profile=simulate_profile,
                )
                all_cycles.extend(cycles)
                if iterations and iteration >= iterations:
                    break
                time.sleep(poll_interval_sec)
        except KeyboardInterrupt:
            pass
        return all_cycles
