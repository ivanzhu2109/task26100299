# task26100299

进程内规则灰度执行器（Python，仅标准库）。

## 功能

`gray_executor.GrayExecutor` 管理一个服务的一条规则：一个正式版 + 至多一个候选版。

- `GrayExecutor(official_rule, clock)`：注入正式版规则与以秒计时的单调时钟（可调用对象）。
- `publish(rule) -> int`：发布候选规则，返回唯一递增代次；先结算旧状态，再替换尚未晋级的候选。
- `inspect(payload, bucket) -> InspectResult`：同步检查一次，返回实际执行代次及命中结果或异常；`bucket` 取值 0–99。
- `state() -> State`：观察正式代次、候选代次、候选阶段（`graying`/`draining`/`fused`）及候选在途检查数。

语义要点：

- 每次发布开启 900 秒灰度窗口；窗口内 `bucket < 10` 走健康候选，其余走正式版。
- 分流时固定规则与代次；截止后进入排空，在途候选检查全部提交且候选仍健康才自动晋级。
- 被替换或熔断的候选永久失去晋级资格，迟到结果不影响其他代次。
- 仅对候选按结果提交时间统计最近 300 秒 `(now-300, now]` 的精确滚动窗口，
  异常数/完成数严格大于 1% 立即熔断，熔断不可自动恢复。
- 分流、结果提交、`publish`、`state` 均为可线性化的状态事件，规则执行期间不持有锁。

## 运行测试

```bash
python3 -m pytest tests -q
```

## 最小示例

```python
import time
from gray_executor import GrayExecutor

executor = GrayExecutor(official_rule=lambda p: False, clock=time.monotonic)
gen = executor.publish(lambda p: "attack" in p)
result = executor.inspect({"path": "/attack"}, bucket=5)
print(result.generation, result.hit, result.error)
print(executor.state())
```
