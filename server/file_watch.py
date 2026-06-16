"""
NetGuard — Watchdog tabanlı dosya değişim izleyici (B2)

Zeek/Suricata collector'ları varsayılan olarak periyodik poll (5s) yapıyordu —
tespit gecikmesi 0-5s arasında değişiyordu. Bu modül inotify (Linux) ile
dosya yazıldığı anda tetikleme sağlar; poll tamamen kaldırılmaz, fallback
olarak kalır (NFS gibi inotify desteklemeyen dosya sistemlerinde veya
event kaçırılırsa veri kaybı olmasın) — Filebeat'in scan_frequency +
event-driven harvester hibrit modeliyle aynı yaklaşım.

debounce_seconds: Zeek/Suricata saniyede onlarca satır yazabilir — her
write event'inde collect_once() tetiklemek DB'yi gereksiz yere yorar.
Bu pencere içindeki ardışık event'ler birleştirilip tek tetikleme yapılır.
"""

import asyncio
import logging
import threading
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

DEFAULT_DEBOUNCE_SECONDS = 0.5


class _Handler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[], None], path_filter: Optional[Path] = None):
        self._callback = callback
        self._path_filter = path_filter

    def _maybe_trigger(self, event) -> None:
        if event.is_directory:
            return
        if self._path_filter is not None:
            try:
                if Path(event.src_path).resolve() != self._path_filter:
                    return
            except OSError:
                return
        self._callback()

    def on_modified(self, event) -> None:
        self._maybe_trigger(event)

    def on_created(self, event) -> None:
        self._maybe_trigger(event)

    def on_moved(self, event) -> None:
        self._maybe_trigger(event)


class DebouncedDirectoryWatcher:
    """
    Bir dizini (gerekirse tek bir dosyaya filtrelenmiş) izler; değişiklik
    olduğunda debounce penceresi sonunda on_change() çağrısını asyncio
    event loop'una thread-safe biçimde planlar.
    """

    def __init__(
        self,
        directory: Path,
        on_change: Callable[[], None],
        loop: asyncio.AbstractEventLoop,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
        watch_file: Optional[Path] = None,
    ):
        self._directory = directory
        self._on_change = on_change
        self._loop = loop
        self._debounce_seconds = debounce_seconds
        self._watch_file = watch_file.resolve() if watch_file else None
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._observer: Optional[Observer] = None

    def start(self) -> bool:
        """Watcher'ı başlatır. Dizin yoksa False döner — çağıran taraf poll-only fallback'e düşer."""
        if not self._directory.exists():
            logger.warning(f"İzlenecek dizin yok, inotify başlatılamadı: {self._directory}")
            return False
        try:
            handler = _Handler(self._schedule, path_filter=self._watch_file)
            observer = Observer()
            observer.schedule(handler, str(self._directory.resolve()), recursive=False)
            observer.start()
        except Exception as exc:
            logger.warning(f"inotify watcher başlatılamadı, poll-only fallback: {exc}")
            return False
        self._observer = observer
        logger.info(f"Dosya izleyici (inotify) başlatıldı: {self._directory}")
        return True

    def _schedule(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce_seconds, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        self._loop.call_soon_threadsafe(self._on_change)

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._observer = None
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
