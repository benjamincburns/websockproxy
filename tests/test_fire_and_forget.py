import asyncio
import gc
import weakref

from websockproxy.switchedrelay import _fire_and_forget


async def test_pending_task_is_not_garbage_collected():
    async def wait_forever():
        await asyncio.get_running_loop().create_future()

    before = asyncio.all_tasks()
    _fire_and_forget(wait_forever())
    (task,) = asyncio.all_tasks() - before
    ref = weakref.ref(task)
    del task
    await asyncio.sleep(0)  # let the task start and block

    gc.collect()

    task = ref()
    assert task is not None and not task.done()
    task.cancel()
