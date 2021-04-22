import concurrent
from concurrent.futures import Future, ThreadPoolExecutor, ALL_COMPLETED
from dataclasses import dataclass
from queue import Queue
from typing import Callable, List, Tuple

from dragoneye.utils.app_logger import logger


@dataclass
class ThreadedFunctionData:
    callable: Callable
    args: Tuple
    error_msg: str
    timeout_msg: str = None


def execute_parallel_functions_in_threads(queue: Queue, max_workers, timeout=None):
    """
    This function takes a Queue (queue: Queue[List[ThreadedFunctionData]])
    of lists, when each queued item represents a list of functions that should be run in parallel.
    """
    tasks_data: List[Tuple[Future, str, str]] = []
    executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=max_workers)

    for commands_data in queue.queue:
        for command_data in commands_data:
            tasks_data.append((
                executor.submit(command_data.callable, *command_data.args),
                command_data.error_msg, command_data.timeout_msg))

        concurrent.futures.wait([task[0] for task in tasks_data], timeout=timeout, return_when=ALL_COMPLETED)

    timeout_tasks = [task for task in tasks_data if task[0].running()]
    for timeout_task in timeout_tasks:
        logger.exception(timeout_task[2])
    failed_tasks = [task for task in tasks_data if task[0].exception()]
    for failed_task in failed_tasks:
        logger.exception(failed_task[1], exc_info=failed_task[0].exception())
    executor.shutdown(True)
