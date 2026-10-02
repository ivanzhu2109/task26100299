"""进程内规则灰度执行器。

只管理一个服务的一条规则：一个正式版 + 至多一个候选版。
规则是本地函数，接收请求内容，返回 bool（是否命中）或抛出异常。
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

GRAY_WINDOW_SECONDS = 900.0
ERROR_WINDOW_SECONDS = 300.0
ERROR_RATE_THRESHOLD = 0.01
GRAY_BUCKET_LIMIT = 10

STAGE_GRAYING = "graying"
STAGE_DRAINING = "draining"
STAGE_FUSED = "fused"

Rule = Callable[[object], bool]
Clock = Callable[[], float]


@dataclass(frozen=True)
class InspectResult:
    """单次检查结果：实际执行的代次，以及命中结果或执行异常。"""

    generation: int
    hit: Optional[bool] = None
    error: Optional[BaseException] = None


@dataclass(frozen=True)
class State:
    official_generation: int
    candidate_generation: Optional[int]
    candidate_stage: Optional[str]
    candidate_inflight: int


@dataclass
class _Candidate:
    rule: Rule
    generation: int
    deadline: float
    fused: bool = False
    inflight: int = 0
    samples: List[Tuple[float, bool]] = field(default_factory=list)  # (提交时刻, 是否异常)


class GrayExecutor:
    def __init__(self, official_rule: Rule, clock: Clock) -> None:
        self._lock = threading.Lock()
        self._clock = clock
        self._official_rule = official_rule
        self._official_generation = 0
        self._next_generation = 1
        self._candidate: Optional[_Candidate] = None

    # ---- 内部：结算当前时刻（调用时必须已持有锁） ----
    def _settle(self, now: float) -> None:
        cand = self._candidate
        if cand is None:
            return
        # 1. 移除窗口外样本（窗口为 (now-300, now]）
        cutoff = now - ERROR_WINDOW_SECONDS
        cand.samples = [s for s in cand.samples if s[0] > cutoff]
        # 2. 判定熔断：异常数/完成数 严格大于 1%
        if not cand.fused and cand.samples:
            completed = len(cand.samples)
            errors = sum(1 for _, is_error in cand.samples if is_error)
            if errors / completed > ERROR_RATE_THRESHOLD:
                cand.fused = True
        # 3. 判定到期晋级：截止后且在途排空、候选仍健康
        if not cand.fused and now >= cand.deadline and cand.inflight == 0:
            self._official_rule = cand.rule
            self._official_generation = cand.generation
            self._candidate = None

    # ---- 发布 ----
    def publish(self, rule: Rule) -> int:
        with self._lock:
            now = self._clock()
            self._settle(now)  # 先结算旧状态（可能令旧候选晋级）
            # 再替换尚未晋级的候选（被替换者永久失去晋级资格）
            generation = self._next_generation
            self._next_generation += 1
            self._candidate = _Candidate(
                rule=rule, generation=generation, deadline=now + GRAY_WINDOW_SECONDS
            )
            return generation

    # ---- 检查 ----
    def inspect(self, payload: object, bucket: int) -> InspectResult:
        if not 0 <= bucket <= 99:
            raise ValueError("bucket 必须在 0 至 99 之间")

        # 事件一：分流（原子）。固定本次实际执行的规则与代次。
        with self._lock:
            now = self._clock()
            self._settle(now)
            cand = self._candidate
            if (
                cand is not None
                and not cand.fused
                and now < cand.deadline
                and bucket < GRAY_BUCKET_LIMIT
            ):
                cand.inflight += 1
                rule = cand.rule
                generation = cand.generation
                routed = cand
            else:
                rule = self._official_rule
                generation = self._official_generation
                routed = None

        # 规则执行不属于原子事件，不持有锁。
        hit: Optional[bool] = None
        error: Optional[BaseException] = None
        try:
            hit = bool(rule(payload))
        except BaseException as exc:  # 规则异常即执行异常
            error = exc

        # 事件二：结果提交（原子）。
        with self._lock:
            now = self._clock()
            if routed is not None:
                routed.inflight -= 1
                # 只有未被替换的当前候选才计入统计；
                # 被替换/熔断候选的迟到结果不影响任何代次。
                if self._candidate is routed and not routed.fused:
                    routed.samples.append((now, error is not None))
            self._settle(now)

        return InspectResult(generation=generation, hit=hit, error=error)

    # ---- 状态观察 ----
    def state(self) -> State:
        with self._lock:
            now = self._clock()
            self._settle(now)
            cand = self._candidate
            if cand is None:
                return State(self._official_generation, None, None, 0)
            if cand.fused:
                stage = STAGE_FUSED
            elif now >= cand.deadline:
                stage = STAGE_DRAINING
            else:
                stage = STAGE_GRAYING
            return State(
                self._official_generation, cand.generation, stage, cand.inflight
            )
