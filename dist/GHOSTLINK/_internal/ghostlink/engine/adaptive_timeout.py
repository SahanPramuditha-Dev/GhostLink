import time

class AdaptiveTimeout:
    def __init__(self, base_timeout=10, min_timeout=3, fast_threshold=2.0, reduce_after=5):
        self.base = base_timeout
        self.min = min_timeout
        self.current = base_timeout
        self.fast_threshold = fast_threshold
        self.reduce_after = reduce_after
        self.fast_fails = 0

    def report(self, elapsed: float):
        if elapsed < self.fast_threshold:
            self.fast_fails += 1
        else:
            self.fast_fails = 0
        if self.fast_fails >= self.reduce_after:
            self.current = max(self.min, self.current - 1)
            self.fast_fails = 0
        elif self.current < self.base:
            self.current = min(self.base, self.current + 0.5)

    def reset(self):
        self.current = self.base
        self.fast_fails = 0