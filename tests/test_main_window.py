import src.gui.main_window as main_window
from src.database import DatabaseError


class FakeFailingRepo:
    def get_previous_results(self, domain):
        raise DatabaseError("database unavailable")

    def save_results(self, domain, results):
        pass

    def clear_history(self):
        pass


def test_check_result_stops_when_history_read_fails():
    window = main_window.MainWindow.__new__(main_window.MainWindow)
    window.repository = FakeFailingRepo()

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
    main_window.QMessageBox.warning = lambda *args: warnings.append(args)

    window._handle_check_result([object()])

    assert window.scan_button.enabled is True
    assert window.status_label.text == (
        "Scan completed, but history comparison failed."
    )
    assert len(warnings) == 1
    assert warnings[0][1] == "History unavailable"