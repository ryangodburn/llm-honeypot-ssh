# Model Resilience
# bounded waiting for the AI and a process-local circuit breaker, with no response cache

# Imports
from __future__ import annotations
from contextlib import asynccontextmanager
from dataclasses import dataclass
import asyncio
import math
import time


def positive_seconds(value, name):
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError(f'{name} must be finite and positive')
    return float(value)


# Total queue and model deadline, paused only while a real tool runs
class AIDeadline:
    def __init__(self, seconds):
        self.seconds = positive_seconds(seconds, 'AI timeout')
        self.timer = None

    async def __aenter__(self):
        self.timer = asyncio.timeout(self.seconds)
        await self.timer.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.timer.__aexit__(*args)

    @asynccontextmanager
    async def tool_execution(self):
        loop = asyncio.get_running_loop()
        deadline = self.timer.when()
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError('AI deadline expired before tool execution')
        self.timer.reschedule(None)
        try:
            yield
        finally:
            self.timer.reschedule(loop.time() + remaining)


@dataclass(frozen=True)
class Permit:
    generation: int
    probe: bool = False


# Allows one recovery probe after the cooldown
# older in-flight results cannot reset it
class CircuitBreaker:
    def __init__(self, threshold=3, cooldown=30., *, clock=None):
        if type(threshold) is not int or threshold < 1:
            raise ValueError('AI failure threshold must be a positive integer')
        self.threshold = threshold
        self.cooldown = positive_seconds(cooldown, 'AI cooldown')
        self.clock = clock or time.monotonic
        self.failures = 0
        self.open_until = 0.
        self.generation = 0
        self.probing = False

    def acquire(self):
        if self.open_until:
            if self.clock() < self.open_until or self.probing:
                return None
            self.probing = True
            return Permit(self.generation, True)
        return Permit(self.generation)

    def finish(self, permit, *, failed=False, cancelled=False):
        if permit is None or permit.generation != self.generation:
            return
        if permit.probe:
            self.probing = False
        if cancelled:
            return
        if not failed:
            self.failures, self.open_until = 0, 0.
            return
        self.failures += 1
        if permit.probe or self.failures >= self.threshold:
            self.trip()

    def trip(self):
        self.failures = max(self.failures, self.threshold)
        self.open_until = self.clock() + self.cooldown
        self.probing = False
        self.generation += 1

    def state(self):
        return {'state': 'half_open' if self.probing else 'open' if self.open_until else 'closed',
                'consecutive_failures': self.failures,
                'retry_after_s': round(max(0., self.open_until-self.clock()), 3)}
