"""Retry logic with exponential backoff for handling transient failures."""

import asyncio
import logging
from functools import wraps
from typing import Callable, Type, Tuple

from scanner.exceptions import NetworkError

logger = logging.getLogger(__name__)


def async_retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[Exception], ...] = (NetworkError, asyncio.TimeoutError, ConnectionError)
):
    """Decorator for retrying async functions with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        backoff_base: Base for exponential backoff calculation
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay between retries in seconds
        exceptions: Tuple of exception types to retry on

    Example:
        @async_retry(max_attempts=3, initial_delay=1.0)
        async def fetch_data(url):
            # Code that might fail transiently
            pass
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(initial_delay * (backoff_base ** (attempt - 1)), max_delay)

                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )

                    await asyncio.sleep(delay)

            # This should never be reached, but just in case
            if last_exception:
                raise last_exception

        return wrapper
    return decorator


def sync_retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: Tuple[Type[Exception], ...] = (NetworkError, ConnectionError)
):
    """Decorator for retrying synchronous functions with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        backoff_base: Base for exponential backoff calculation
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay between retries in seconds
        exceptions: Tuple of exception types to retry on

    Example:
        @sync_retry(max_attempts=3, initial_delay=1.0)
        def fetch_data(url):
            # Code that might fail transiently
            pass
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            import time
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(initial_delay * (backoff_base ** (attempt - 1)), max_delay)

                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )

                    time.sleep(delay)

            # This should never be reached, but just in case
            if last_exception:
                raise last_exception

        return wrapper
    return decorator
