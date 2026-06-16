"""
B2 — server/file_watch.py::DebouncedDirectoryWatcher testleri.

Gerçek dosya sistemi üzerinde gerçek inotify event'leri kullanılır (A3'teki
nginx kısıtı burada yok — watchdog doğrudan işletim sistemi seviyesinde
çalışır, TestClient/HTTP katmanına bağımlı değil).

pytest-asyncio kurulu değil (bkz. improvement_todos.md yeni bulgu) — async
senaryolar asyncio.run() ile sarılmış sync test fonksiyonlarında çalıştırılır.
"""

import asyncio
import time

from server.file_watch import DebouncedDirectoryWatcher


class TestStart:
    def test_returns_false_when_directory_missing(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            watcher = DebouncedDirectoryWatcher(tmp_path / "missing", lambda: None, loop)
            return watcher.start()

        assert asyncio.run(scenario()) is False

    def test_returns_true_when_directory_exists(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            watcher = DebouncedDirectoryWatcher(tmp_path, lambda: None, loop)
            started = watcher.start()
            watcher.stop()
            return started

        assert asyncio.run(scenario()) is True

    def test_stop_without_start_is_safe(self, tmp_path):
        loop = asyncio.new_event_loop()
        watcher = DebouncedDirectoryWatcher(tmp_path, lambda: None, loop)
        watcher.stop()  # exception fırlatmamalı


class TestTriggerOnChange:
    def test_triggers_on_file_creation(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            event = asyncio.Event()
            watcher = DebouncedDirectoryWatcher(tmp_path, event.set, loop, debounce_seconds=0.05)
            assert watcher.start() is True
            try:
                (tmp_path / "new.log").write_text("line1\n")
                await asyncio.wait_for(event.wait(), timeout=3.0)
            finally:
                watcher.stop()
            return event.is_set()

        assert asyncio.run(scenario()) is True

    def test_triggers_on_file_modification(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            target = tmp_path / "existing.log"
            target.write_text("line1\n")

            event = asyncio.Event()
            watcher = DebouncedDirectoryWatcher(tmp_path, event.set, loop, debounce_seconds=0.05)
            assert watcher.start() is True
            try:
                with target.open("a") as fh:
                    fh.write("line2\n")
                await asyncio.wait_for(event.wait(), timeout=3.0)
            finally:
                watcher.stop()
            return event.is_set()

        assert asyncio.run(scenario()) is True


class TestDebounce:
    def test_rapid_writes_coalesce_into_single_trigger(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            counter = {"n": 0}

            def _cb():
                counter["n"] += 1

            watcher = DebouncedDirectoryWatcher(tmp_path, _cb, loop, debounce_seconds=0.3)
            assert watcher.start() is True
            try:
                target = tmp_path / "burst.log"
                for i in range(10):
                    with target.open("a") as fh:
                        fh.write(f"line{i}\n")
                    time.sleep(0.02)
                await asyncio.sleep(0.8)  # debounce penceresini geçecek kadar bekle
            finally:
                watcher.stop()
            return counter["n"]

        assert asyncio.run(scenario()) == 1


class TestPathFilter:
    def test_ignores_changes_to_other_files_in_same_directory(self, tmp_path):
        async def scenario():
            loop = asyncio.get_running_loop()
            watched = tmp_path / "watched.log"
            watched.write_text("init\n")
            other = tmp_path / "other.log"
            other.write_text("init\n")

            counter = {"n": 0}
            watcher = DebouncedDirectoryWatcher(
                tmp_path, lambda: counter.__setitem__("n", counter["n"] + 1),
                loop, debounce_seconds=0.1, watch_file=watched,
            )
            assert watcher.start() is True
            try:
                with other.open("a") as fh:
                    fh.write("changed\n")
                await asyncio.sleep(0.4)
                ignored_count = counter["n"]

                with watched.open("a") as fh:
                    fh.write("changed\n")
                await asyncio.sleep(0.4)
                triggered_count = counter["n"]
            finally:
                watcher.stop()
            return ignored_count, triggered_count

        ignored_count, triggered_count = asyncio.run(scenario())
        assert ignored_count == 0
        assert triggered_count == 1
