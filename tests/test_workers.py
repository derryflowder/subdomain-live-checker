from PySide6.QtCore import QCoreApplication, QThreadPool

from src.gui.workers import Worker


def test_worker_emits_result() -> None:
    worker = Worker(lambda: 42)

    results: list[int] = []
    errors: list[str] = []
    finished: list[bool] = []

    worker.signals.result.connect(results.append)
    worker.signals.error.connect(errors.append)
    worker.signals.finished.connect(lambda: finished.append(True))

    worker.run()

    assert results == [42]
    assert errors == []
    assert finished == [True]


def test_worker_emits_error_and_finished() -> None:
    def failing_function() -> None:
        raise ValueError("test error")

    worker = Worker(failing_function)

    results: list[object] = []
    errors: list[str] = []
    finished: list[bool] = []

    worker.signals.result.connect(results.append)
    worker.signals.error.connect(errors.append)
    worker.signals.finished.connect(lambda: finished.append(True))

    worker.run()

    assert results == []
    assert errors == ["test error"]
    assert finished == [True]


def test_worker_runs_in_thread_pool() -> None:
    app = QCoreApplication.instance() or QCoreApplication([])

    pool = QThreadPool.globalInstance()
    worker = Worker(lambda: 42)

    results: list[int] = []

    worker.signals.result.connect(results.append)

    pool.start(worker)
    pool.waitForDone()

    app.processEvents()

    assert results == [42]
