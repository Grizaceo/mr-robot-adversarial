"""Pure computation — canonical benign sample."""
from functools import lru_cache


@lru_cache(maxsize=None)
def fib(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    if n < 2:
        return n
    return fib(n - 1) + fib(n - 2)


def fib_sequence(count: int) -> list[int]:
    return [fib(i) for i in range(count)]


if __name__ == "__main__":
    print(fib_sequence(10))
