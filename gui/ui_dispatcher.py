"""Thread-safe delivery of worker results to Tk's main thread."""

import logging
import queue


log = logging.getLogger(__name__)


class UiDispatcher:
    """Mixin that polls a queue from Tk instead of calling Tk from workers."""

    def _init_ui_dispatcher(self):
        self._ui_queue = queue.SimpleQueue()
        self._ui_dispatch_after = self.after(20, self._drain_ui_queue)
        self.bind("<Destroy>", self._stop_ui_dispatcher, add="+")

    def post_ui(self, callback, *args, **kwargs):
        self._ui_queue.put((callback, args, kwargs))

    def _drain_ui_queue(self):
        while True:
            try:
                callback, args, kwargs = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args, **kwargs)
            except Exception:
                log.exception("Unhandled main-thread UI callback error")
        try:
            self._ui_dispatch_after = self.after(20, self._drain_ui_queue)
        except Exception as exc:
            log.debug("UI dispatcher stopped: %s", type(exc).__name__)
            self._ui_dispatch_after = None

    def _stop_ui_dispatcher(self, event=None):
        if event is not None and event.widget is not self:
            return
        after_id = getattr(self, "_ui_dispatch_after", None)
        self._ui_dispatch_after = None
        if after_id:
            try:
                self.after_cancel(after_id)
            except Exception as exc:
                log.debug("UI dispatcher timer was already closed: %s", type(exc).__name__)
