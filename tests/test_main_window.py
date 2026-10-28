import src.gui.main_window as main_window
from src.database import DatabaseError


def test_check_result_stops_when_history_read_fails(monkeypatch):
    window = main_window.MainWindow.__new__(main_window.MainWindow)

    class FakeWidget:
        def __init__(self):
            self.enabled = False
            self.text = ""

        def setVisible(self, visible):
            pass

        def setText(self, text):
            self.text = text

        def setEnabled(self, enabled):
            self.enabled = enabled

    window.progress_bar = FakeWidget()
    window.status_label = FakeWidget()
    window.scan_button = FakeWidget()
    window.current_domain = "example.com"

    warnings = []
    saved_results = []

    def fail_to_read(domain):
        raise DatabaseError("database unavailable")

    monkeypatch.setattr(main_window, "get_previous_results", fail_to_read)
    monkeypatch.setattr(
        main_window.QMessageBox,
        "warning",
        lambda *args: warnings.append(args),
    )
    monkeypatch.setattr(
        main_window,
        "save_results",
        lambda *args: saved_results.append(args),
    )

    window._handle_check_result([object()])

    assert window.scan_button.enabled is True
    assert window.status_label.text == (
        "Scan completed, but history comparison failed."
    )
    assert len(warnings) == 1
    assert warnings[0][1] == "History unavailable"
    assert saved_results == []

