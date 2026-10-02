"""灰度执行器测试：可控时钟 + 同步事件构造交错，不依赖真实等待。"""
import threading
import unittest

from grayexec.executor import (
    STAGE_DRAINING,
    STAGE_FUSED,
    STAGE_GRAY,
    GrayExecutor,
)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def set(self, value):
        self.t = value

    def advance(self, dt):
        self.t += dt


class ScriptedRule:
    """每次调用阻塞，直到测试主线程放行；行为由 behaviors 按调用序决定。"""

    def __init__(self, behaviors):
        self.behaviors = behaviors
        self.gates = []  # (entered, release)
        self._lock = threading.Lock()

    def __call__(self, payload):
        with self._lock:
            idx = len(self.gates)
            entered, release = threading.Event(), threading.Event()
            self.gates.append((entered, release))
        entered.set()
        if not release.wait(10):
            raise AssertionError("test deadlocked: rule not released")
        behavior = self.behaviors[idx]
        if behavior == "raise":
            raise RuntimeError("boom")
        return behavior == "hit"

    def wait_entered(self, idx, timeout=5):
        deadline = threading.Event()
        while True:
            with self._lock:
                if len(self.gates) > idx:
                    assert self.gates[idx][0].wait(timeout)
                    return
            if deadline.wait(0.005):
                raise AssertionError("rule call never entered")


def simple_rule(payload):
    if payload == "bad":
        raise RuntimeError("bad")
    return payload == "attack"


def run_inspect(ex, payload, bucket):
    box = {}
    thread = threading.Thread(
        target=lambda: box.setdefault("out", ex.inspect(payload, bucket)),
        daemon=True,
    )
    thread.start()
    return thread, box


class RoutingTest(unittest.TestCase):
    def test_bucket_split_and_unique_generations(self):
        clock = FakeClock()
        ex = GrayExecutor(simple_rule, clock)
        g1 = ex.publish(simple_rule)
        g2 = ex.publish(simple_rule)  # 同一函数对象也必须产生新代次
        self.assertNotEqual(g1, g2)
        out = ex.inspect("attack", 0)
        self.assertEqual((out.generation, out.hit, out.error), (g2, True, None))
        out = ex.inspect("attack", 9)
        self.assertEqual(out.generation, g2)
        out = ex.inspect("attack", 10)
        self.assertEqual(out.generation, 0)  # 正式版
        out = ex.inspect("attack", 99)
        self.assertEqual(out.generation, 0)
        with self.assertRaises(ValueError):
            ex.inspect("x", 100)


class DrainPromotionTest(unittest.TestCase):
    def test_inflight_blocks_promotion_until_last_result(self):
        clock = FakeClock()
        ex = GrayExecutor(simple_rule, clock)
        cand = ScriptedRule(["hit"])
        gen = ex.publish(cand)

        thread, box = run_inspect(ex, "attack", 5)
        cand.wait_entered(0)

        clock.advance(901)  # 越过截止时刻，检查仍在途
        view = ex.state()  # 状态操作不被规则阻塞
        self.assertEqual(view.stable_generation, 0)  # 不得提前晋级
        self.assertEqual(view.candidate_stage, STAGE_DRAINING)
        self.assertEqual(view.candidate_inflight, 1)

        out = ex.inspect("x", 5)  # 排空期间新请求全部使用旧正式版
        self.assertEqual(out.generation, 0)

        cand.gates[0][1].set()  # 放行，提交健康结果
        thread.join(5)
        self.assertEqual(box["out"].generation, gen)
        self.assertEqual(box["out"].hit, True)

        view = ex.state()
        self.assertEqual(view.stable_generation, gen)  # 提交后才晋级
        self.assertIsNone(view.candidate_generation)


class ReplaceDuringDrainTest(unittest.TestCase):
    def test_replace_and_republish_same_object(self):
        clock = FakeClock()
        stable = ScriptedRule(["hit"])
        ex = GrayExecutor(stable, clock)
        rule_a = ScriptedRule(["hit", "raise"])
        gen_a = ex.publish(rule_a)

        t1, box1 = run_inspect(ex, "x", 5)
        rule_a.wait_entered(0)
        t2, box2 = run_inspect(ex, "x", 5)
        rule_a.wait_entered(1)

        clock.advance(901)
        self.assertEqual(ex.state().candidate_stage, STAGE_DRAINING)

        rule_b = ScriptedRule([])
        gen_b = ex.publish(rule_b)
        gen_c = ex.publish(rule_b)  # 同一函数对象，必须产生新代次
        self.assertLess(gen_a, gen_b)
        self.assertLess(gen_b, gen_c)
        self.assertEqual(ex.state().candidate_generation, gen_c)

        rule_a.gates[0][1].set()  # 旧代次迟到成功：不能使其复活晋级
        t1.join(5)
        self.assertEqual(box1["out"].generation, gen_a)
        self.assertEqual(ex.state().stable_generation, 0)

        rule_a.gates[1][1].set()  # 旧代次迟到异常：不能污染新代次
        t2.join(5)
        self.assertIsNotNone(box2["out"].error)
        view = ex.state()  # 若污染新代次，1/1=100% 会熔断
        self.assertEqual(view.candidate_generation, gen_c)
        self.assertEqual(view.candidate_stage, STAGE_GRAY)

        # 旧正式版检查跨越一次晋级后才返回
        ts, boxs = run_inspect(ex, "x", 50)
        stable.wait_entered(0)
        clock.advance(901)  # gen_c 到期且无在途，下一事件晋级
        self.assertEqual(ex.state().stable_generation, gen_c)
        stable.gates[0][1].set()
        ts.join(5)
        self.assertEqual(boxs["out"].generation, 0)  # 分流时固定，仍执行旧正式版
        self.assertEqual(boxs["out"].hit, True)


class ErrorRateTest(unittest.TestCase):
    def make(self):
        clock = FakeClock()
        ex = GrayExecutor(simple_rule, clock)
        ex.publish(simple_rule)
        return clock, ex

    def test_1_of_100_does_not_fuse(self):
        clock, ex = self.make()
        for _ in range(99):
            ex.inspect("ok", 5)
        ex.inspect("bad", 5)  # 1/100 = 1%，不严格大于，不熔断
        self.assertEqual(ex.state().candidate_stage, STAGE_GRAY)
        self.assertEqual(ex.inspect("ok", 5).generation, 1)

    def test_2_of_101_fuses(self):
        clock, ex = self.make()
        for _ in range(99):
            ex.inspect("ok", 5)
        ex.inspect("bad", 5)  # 1/100，不熔断
        self.assertEqual(ex.state().candidate_stage, STAGE_GRAY)
        ex.inspect("bad", 5)  # 2/101 > 1%，立即熔断
        self.assertEqual(ex.state().candidate_stage, STAGE_FUSED)
        self.assertEqual(ex.inspect("ok", 5).generation, 0)  # 熔断后全走正式版

    def test_success_expiry_fuses_without_new_error(self):
        clock, ex = self.make()
        clock.set(10)
        for _ in range(100):
            ex.inspect("ok", 5)
        clock.set(20)
        ex.inspect("bad", 5)  # 1/101，不熔断
        self.assertEqual(ex.state().candidate_stage, STAGE_GRAY)
        clock.set(311)  # 成功样本(10)恰在窗口左边界过期，异常(20)仍在窗口内
        self.assertEqual(ex.state().candidate_stage, STAGE_FUSED)  # 无新增异常也熔断

    def test_attack_hit_counts_as_success(self):
        clock, ex = self.make()
        for _ in range(100):
            out = ex.inspect("attack", 5)  # 命中攻击的正常返回
            self.assertEqual((out.hit, out.error), (True, None))
        ex.inspect("bad", 5)  # 若命中未计为成功，此处 1/1 会熔断
        self.assertEqual(ex.state().candidate_stage, STAGE_GRAY)


if __name__ == "__main__":
    unittest.main()
