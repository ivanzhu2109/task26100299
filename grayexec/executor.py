"""进程内单服务单规则灰度执行器。

调用方注入正式版规则与单调时钟；规则为本地函数，接收请求内容，
返回是否命中或抛出异常（命中攻击不算执行错误）。
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional, Tuple

RuleFn = Callable[[object], bool]
ClockFn = Callable[[], float]

GRAY_WINDOW_SECONDS = 900.0
ERROR_WINDOW_SECONDS = 300.0
ERROR_RATE_THRESHOLD = 0.01
GRAY_BUCKET_LIMIT = 10

STAGE_GRAY = "gray"
STAGE_DRAINING = "draining"
STAGE_FUSED = "fused"


@dataclass(frozen=True)
class InspectOutcome:
    generation: int
    hit: Optional[bool]
    error: Optional[BaseException]


@dataclass(frozen=True)
class StateView:
    stable_generation: int
    candidate_generation: Optional[int]
    candidate_stage: Optional[str]
    candidate_inflight: int


class _Candidate:
    __slots__ = ("generation", "rule", "deadline", "stage", "inflight", "samples")

    def __init__(self, generation: int, rule: RuleFn, deadline: float) -> None:
        self.generation = generation
        self.rule = rule
        self.deadline = deadline
        self.stage = STAGE_GRAY
        self.inflight = 0
        # (提交时刻, 是否异常)，仅属于本代次
        self.samples: Deque[Tuple[float, bool]] = deque()


class GrayExecutor:
    def __init__(self, stable_rule: RuleFn, clock: ClockFn) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._stable_rule = stable_rule
        self._stable_generation = 0
        self._next_generation = 1
        self._candidate: Optional[_Candidate] = None

    # ---- 内部：必须在 _lock 内调用 ----

    def _settle(self, now: float) -> None:
        """结算当前时刻：移除窗口外样本 -> 判定熔断 -> 判定到期/晋级。"""
        cand = self._candidate
        if cand is None:
            return
        cutoff = now - ERROR_WINDOW_SECONDS
        while cand.samples and cand.samples[0][0] <= cutoff:
            cand.samples.popleft()
        if cand.stage != STAGE_FUSED and cand.samples:
            errors = sum(1 for _, is_error in cand.samples if is_error)
            if errors / len(cand.samples) > ERROR_RATE_THRESHOLD:
                cand.stage = STAGE_FUSED
        if cand.stage == STAGE_GRAY and now >= cand.deadline:
            cand.stage = STAGE_DRAINING
        if cand.stage == STAGE_DRAINING and cand.inflight == 0:
            self._stable_rule = cand.rule
            self._stable_generation = cand.generation
            self._candidate = None

    # ---- 公开操作：各自为可线性化的状态事件 ----

    def publish(self, rule: RuleFn) -> int:
        with self._lock:
            now = self._clock()
            self._settle(now)
            generation = self._next_generation
            self._next_generation += 1
            self._candidate = _Candidate(
                generation, rule, now + GRAY_WINDOW_SECONDS
            )
            return generation

    def inspect(self, payload: object, bucket: int) -> InspectOutcome:
        if not 0 <= bucket <= 99:
            raise ValueError("bucket must be in [0, 99]")
        with self._lock:
            now = self._clock()
            self._settle(now)
            cand = self._candidate
            if cand is not None and cand.stage == STAGE_GRAY and bucket < GRAY_BUCKET_LIMIT:
                chosen_rule = cand.rule
                chosen_generation = cand.generation
                chosen_candidate: Optional[_Candidate] = cand
                cand.inflight += 1
            else:
                chosen_rule = self._stable_rule
                chosen_generation = self._stable_generation
                chosen_candidate = None
        # 规则执行不持有锁，不属于原子状态事件
        hit: Optional[bool] = None
        error: Optional[BaseException] = None
        try:
            hit = bool(chosen_rule(payload))
        except BaseException as exc:  # 规则异常即执行异常
            error = exc
        with self._lock:
            submit_time = self._clock()
            if chosen_candidate is not None:
                chosen_candidate.inflight -= 1
                # 仅当前候选代次的有效结果进入统计；迟到结果不污染其他代次
                if chosen_candidate is self._candidate:
                    chosen_candidate.samples.append((submit_time, error is not None))
            self._settle(submit_time)
        return InspectOutcome(chosen_generation, hit, error)

    def state(self) -> StateView:
        with self._lock:
            now = self._clock()
            self._settle(now)
            cand = self._candidate
            return StateView(
                stable_generation=self._stable_generation,
                candidate_generation=cand.generation if cand else None,
                candidate_stage=cand.stage if cand else None,
                candidate_inflight=cand.inflight if cand else 0,
            )
