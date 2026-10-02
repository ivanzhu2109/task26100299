"""GrayExecutor 自动化测试：可控时钟 + 同步事件交错。"""
import threading

import pytest

from gray_executor import (
    GrayExecutor,
    STAGE_DRAINING,
    STAGE_FUSED,
    STAGE_GRAYING,
)


class ManualClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return ManualClock()


def official_rule(payload):
    return False


def run_inspect_async(executor, payload, bucket):
    """在后台线程执行 inspect，返回 (thread, 结果容器)。"""
    box = {}

    def target():
        box["result"] = executor.inspect(payload, bucket)

    thread = threading.Thread(target=target)
    thread.start()
    return thread, box


def test_candidate_inflight_blocks_promotion_until_last_result(clock):
    entered = threading.Event()
    release = threading.Event()

    def candidate_rule(payload):
        entered.set()
        release.wait(5)
        return True  # 命中攻击，属正常返回

    executor = GrayExecutor(official_rule, clock)
    gen = executor.publish(candidate_rule)
    assert gen == 1

    # 候选检查在窗口内开始，随后被规则执行卡住
    thread, box = run_inspect_async(executor, "payload", bucket=5)
    assert entered.wait(5)

    # 推进到截止时刻之后：灰度入口关闭，进入排空
    clock.advance(901)
    state = executor.state()
    assert state.official_generation == 0
    assert state.candidate_generation == 1
    assert state.candidate_stage == STAGE_DRAINING
    assert state.candidate_inflight == 1

    # 排空期间新请求（包括小 bucket）全部走旧正式版
    res = executor.inspect("payload", bucket=3)
    assert res.generation == 0 and res.hit is False and res.error is None

    # 在途检查仍未提交，不得提前晋级
    assert executor.state().official_generation == 0

    # 最后一份健康结果提交后才晋级
    release.set()
    thread.join(5)
    assert box["result"].generation == 1
    assert box["result"].hit is True and box["result"].error is None

    state = executor.state()
    assert state.official_generation == 1
    assert state.candidate_generation is None
    assert state.candidate_stage is None
    assert state.candidate_inflight == 0


def test_replace_during_drain_late_results_and_slow_official(clock):
    official_entered = threading.Event()
    official_release = threading.Event()

    def official(payload):
        if payload == "slow-official":
            official_entered.set()
            official_release.wait(5)
        return False

    executor = GrayExecutor(official, clock)

    gates = {
        "ok": (threading.Event(), threading.Event()),
        "bad": (threading.Event(), threading.Event()),
    }

    def cand_rule(payload):
        if payload in gates:
            entered, release = gates[payload]
            entered.set()
            release.wait(5)
            if payload == "bad":
                raise RuntimeError("boom")
        return True

    gen1 = executor.publish(cand_rule)
    assert gen1 == 1

    # 旧代次上的两笔在途检查：一笔将成功，一笔将异常
    t_ok, box_ok = run_inspect_async(executor, "ok", bucket=5)
    assert gates["ok"][0].wait(5)
    t_bad, box_bad = run_inspect_async(executor, "bad", bucket=5)
    assert gates["bad"][0].wait(5)

    # 进入排空期
    clock.advance(901)
    assert executor.state().candidate_stage == STAGE_DRAINING
    assert executor.state().candidate_inflight == 2

    # 排空期间发布替代候选：同一个函数对象也必须产生新代次
    gen2 = executor.publish(cand_rule)
    assert gen2 == 2
    state = executor.state()
    assert state.candidate_generation == 2
    assert state.candidate_stage == STAGE_GRAYING
    assert state.candidate_inflight == 0

    # 旧代次迟到成功：不能使旧代次晋级，也不污染新代次
    gates["ok"][1].set()
    t_ok.join(5)
    assert box_ok["result"].generation == 1
    assert box_ok["result"].hit is True
    state = executor.state()
    assert state.official_generation == 0
    assert state.candidate_generation == 2

    # 旧代次迟到异常：不影响新代次（否则 1/1 异常必然熔断新代次）
    gates["bad"][1].set()
    t_bad.join(5)
    assert box_bad["result"].generation == 1
    assert isinstance(box_bad["result"].error, RuntimeError)
    state = executor.state()
    assert state.candidate_generation == 2
    assert state.candidate_stage == STAGE_GRAYING

    # 新代次健康，小 bucket 请求分流到新候选
    res = executor.inspect("ping", bucket=5)
    assert res.generation == 2 and res.hit is True

    # 旧正式版检查开始（代次 0），随后被规则执行卡住
    t_off, box_off = run_inspect_async(executor, "slow-official", bucket=50)
    assert official_entered.wait(5)

    # 推进到新候选截止之后，下一事件触发晋级
    clock.advance(901)
    state = executor.state()
    assert state.official_generation == 2
    assert state.candidate_generation is None

    # 跨越一次晋级后才返回的旧正式版检查：代次在分流时已固定为 0
    official_release.set()
    t_off.join(5)
    assert box_off["result"].generation == 0
    assert box_off["result"].hit is False


def make_threshold_rule():
    def rule(payload):
        if payload == "bad":
            raise RuntimeError("boom")
        return True  # 命中攻击的正常返回，计为成功执行

    return rule


def test_error_rate_threshold_1_of_100_ok_2_of_101_fuses(clock):
    executor = GrayExecutor(official_rule, clock)
    executor.publish(make_threshold_rule())

    # 99 笔成功（命中攻击的正常返回计为成功）
    for _ in range(99):
        res = executor.inspect("ok", bucket=5)
        assert res.generation == 1 and res.hit is True and res.error is None

    # 1/100 = 1%，不严格大于 1%，不熔断
    res = executor.inspect("bad", bucket=5)
    assert res.generation == 1 and isinstance(res.error, RuntimeError)
    assert executor.state().candidate_stage == STAGE_GRAYING

    # 2/101 > 1%，立即熔断
    executor.inspect("bad", bucket=5)
    state = executor.state()
    assert state.candidate_stage == STAGE_FUSED

    # 熔断后立即停止灰度分流，且不能自动恢复
    res = executor.inspect("ok", bucket=5)
    assert res.generation == 0
    clock.advance(10000)
    executor.inspect("ok", bucket=5)
    assert executor.state().candidate_stage == STAGE_FUSED
    res = executor.inspect("ok", bucket=5)
    assert res.generation == 0


def test_success_sample_expiring_at_left_boundary_fuses_without_new_error(clock):
    executor = GrayExecutor(official_rule, clock)
    executor.publish(make_threshold_rule())

    # t=0：1 笔成功（恰将在窗口左边界过期）
    executor.inspect("ok", bucket=5)

    # t=1：197 成功 + 2 异常，合计窗口内 2/200 = 1%，不熔断
    clock.advance(1)
    for _ in range(197):
        executor.inspect("ok", bucket=5)
    executor.inspect("bad", bucket=5)
    executor.inspect("bad", bucket=5)
    assert executor.state().candidate_stage == STAGE_GRAYING

    # t=299：t=0 的样本仍在窗口内（窗口为 (now-300, now]），不熔断
    clock.advance(298)
    assert executor.state().candidate_stage == STAGE_GRAYING

    # t=300：t=0 的成功样本恰在左边界过期，2/199 > 1%，无新增异常也熔断
    clock.advance(1)
    assert executor.state().candidate_stage == STAGE_FUSED


def test_routing_basics(clock):
    executor = GrayExecutor(official_rule, clock)

    # 没有候选时全部使用正式版
    res = executor.inspect("p", bucket=5)
    assert res.generation == 0 and res.hit is False

    executor.publish(make_threshold_rule())

    # bucket < 10 走候选，其余走正式版
    assert executor.inspect("p", bucket=0).generation == 1
    assert executor.inspect("p", bucket=9).generation == 1
    assert executor.inspect("p", bucket=10).generation == 0
    assert executor.inspect("p", bucket=99).generation == 0

    # bucket 越界直接拒绝
    with pytest.raises(ValueError):
        executor.inspect("p", bucket=100)
    with pytest.raises(ValueError):
        executor.inspect("p", bucket=-1)
