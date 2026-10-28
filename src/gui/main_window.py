import os
from collections import Counter

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.checker import check_subdomains
from src.database import (
    DB_PATH,
    DatabaseError,
    calculate_diff,
    get_previous_results,
    init_db,
    save_results,
)
from src.discovery_sources import discover_from_all_sources
from src.export import build_csv, build_html
from src.gui.filtering import filter_results
from src.gui.workers import Worker
from src.models import ResultStatus, SubdomainResult

ADMIN_KEYWORDS = (
    "admin",
    "panel",
    "login",
    "dashboard",
    "jenkins",
    "gitlab",
    "jira",
    "grafana",
)


def normalize_domain_input(raw: str) -> str:
    """Strip scheme, path, trailing dot and lowercase a user-supplied domain."""
    domain = raw.strip().lower()

    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
            break

    domain = domain.split("/", 1)[0]
    domain = domain.split("?", 1)[0]
    domain = domain.rstrip(".")
    return domain


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Subdomain Live Checker")
        self.resize(1280, 760)
        self.setMinimumSize(1000, 650)

        self.thread_pool = QThreadPool.globalInstance()
        self.active_workers: set[Worker] = set()
        self.current_domain = ""
        self.current_results: list[SubdomainResult] = []

        self._build_ui()
        self._apply_styles()

    # ---------- workers ----------
    def _track_worker(self, worker: Worker) -> None:
        worker.setAutoDelete(False)
        self.active_workers.add(worker)
        worker.signals.finished.connect(lambda: self.active_workers.discard(worker))

    def _run_discovery(self, domain: str):
        return discover_from_all_sources(domain)

    def _run_checks(self, hostnames: list[str], on_progress=None) -> list:
        return check_subdomains(hostnames, on_progress=on_progress)

    # ---------- flow ----------
    def _start_scan(self) -> None:
        domain = normalize_domain_input(self.target_input.text())
        if not domain:
            self.status_label.setText("Enter a target domain")
            return

        self.current_domain = domain
        self.target_input.setText(domain)

        self.scan_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_bar.setValue(0)
        self.results_table.setRowCount(0)
        self.results_table.setVisible(False)
        self.legend.setVisible(False)

        self._update_summary(discovered=0, live=0, issues=0)
        self.status_label.setText(f"Discovering subdomains for {self.current_domain}...")

        worker = Worker(self._run_discovery, self.current_domain)
        worker.signals.result.connect(self._handle_discovery_result)
        worker.signals.error.connect(self._handle_discovery_error)
        self._track_worker(worker)
        self.thread_pool.start(worker)

    def _handle_discovery_result(self, result) -> None:
        hostnames, source_results = result

        if not hostnames:
            self.scan_button.setEnabled(True)
            errors = [f"{s.source}: {s.error}" for s in source_results if s.error]
            self.status_label.setText(
                "Discovery failed: " + " | ".join(errors) if errors else "No subdomains found"
            )
            return

        self._update_summary(discovered=len(hostnames))
        self.status_label.setText(
            f"Discovered {len(hostnames)} subdomains. Starting HTTP checks..."
        )

        self.progress_bar.setMaximum(len(hostnames))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.results_table.setRowCount(0)
        self.results_table.setVisible(True)
        self.legend.setVisible(True)

        worker = Worker(self._run_checks, hostnames)
        worker.kwargs["on_progress"] = worker.signals.progress.emit
        worker.signals.progress.connect(self._handle_check_progress)
        worker.signals.result.connect(self._handle_check_result)
        worker.signals.error.connect(self._handle_check_error)
        self._track_worker(worker)
        self.thread_pool.start(worker)

    def _handle_check_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(done)
        self.status_label.setText(f"Checking subdomains: {done}/{total}")

    def _handle_check_result(self, results: list) -> None:
        self.progress_bar.setVisible(False)

        if not results:
            self.status_label.setText("No hosts responded.")
            self.scan_button.setEnabled(True)
            return

        try:
            previous_data = get_previous_results(self.current_domain)
        except DatabaseError as exc:
            QMessageBox.warning(self, "History unavailable", str(exc))
            previous_data = {}

        current_data = {
            r.hostname: {
                "hostname": r.hostname,
                "status_code": r.status_code if r.status_code is not None else -1,
                "status_text": r.status.value if r.status else "",
            }
            for r in results
        }

        diff = calculate_diff(previous_data, current_data)

        removed_results = [
            SubdomainResult(
                hostname=hostname,
                is_removed=True,
                error="Was present in previous scan",
            )
            for hostname in sorted(diff["removed"])
        ]

        display_results = results + removed_results
        self.current_results = display_results

        for r in results:
            r.is_new = r.hostname in diff["new"]
            r.status_changed = r.hostname in diff["changed"]

        try:
            save_results(self.current_domain, results)
        except DatabaseError as exc:
            QMessageBox.warning(self, "History not saved", str(exc))

        counts = Counter((r.status.value if r.status else "unknown") for r in results)
        live = (
            counts.get("live", 0)
            + counts.get("redirect", 0)
            + counts.get("forbidden", 0)
        )
        issues = len(results) - live
        takeovers = sum(1 for r in results if r.takeover)

        self._update_summary(live=live, issues=issues)

        status_text = (
            f"Checked {len(results)} | Live: {live} | Issues: {issues}"
            f" | New: {len(diff['new'])}"
            f" | Changed: {len(diff['changed'])}"
            f" | Removed: {len(diff['removed'])}"
        )

        if takeovers > 0:
            status_text += f" | ⚠️ Potential Takeovers: {takeovers}"

        self.status_label.setText(status_text)

        self._apply_filters()
        self.scan_button.setEnabled(True)

    def _apply_filters(self, *_args) -> None:
        try:
            filtered_results = filter_results(
                self.current_results,
                filter_name=self.filter_combo.currentText(),
                query=self.search_input.text(),
            )
        except ValueError as exc:
            self.status_label.setText(f"Filter error: {exc}")
            return
        self._populate_table(filtered_results)

    def _populate_table(self, results: list) -> None:
        self.results_table.setUpdatesEnabled(False)
        try:
            self.results_table.setRowCount(len(results))
            for row, r in enumerate(results):
                if r.is_removed:
                    status_item = QTableWidgetItem("REMOVED")
                    status_item.setForeground(QColor("#888888"))

                    self.results_table.setItem(row, 0, QTableWidgetItem(r.hostname))
                    self.results_table.setItem(row, 1, status_item)
                    self.results_table.setItem(row, 2, QTableWidgetItem("-"))
                    self.results_table.setItem(row, 3, QTableWidgetItem("-"))
                    self.results_table.setItem(
                        row,
                        4,
                        QTableWidgetItem(r.error or "Was present in previous scan"),
                    )

                    for col in range(5):
                        item = self.results_table.item(row, col)
                        if item is not None:
                            item.setForeground(QColor("#888888"))

                    continue
                code_str = str(r.status_code) if r.status_code is not None else "-"
                time_str = f"{r.response_time_ms:.1f}" if r.response_time_ms is not None else "-"
                status_str = r.status.value if r.status else "-"

                host_item = QTableWidgetItem(r.hostname)
                status_item = QTableWidgetItem(status_str)
                code_item = QTableWidgetItem(code_str)
                time_item = QTableWidgetItem(time_str)

                extra = r.title or r.error or "-"
                if r.takeover:
                    extra = f"⚠️ Potential Takeover: {r.takeover}"
                extra_item = QTableWidgetItem(extra)

                bg_color = None
                fg_color = QColor("#e2e8f0")

                if r.takeover:
                    bg_color = QColor("#7f1d1d")
                    fg_color = QColor("#fecaca")
                elif r.is_new:
                    bg_color = QColor("#064e3b")
                    fg_color = QColor("#d1fae5")
                elif r.status_changed:
                    bg_color = QColor("#78350f")
                    fg_color = QColor("#fef3c7")
                elif r.status_code in (401, 403):
                    bg_color = QColor("#312e81")
                    fg_color = QColor("#e0e7ff")
                elif r.status == ResultStatus.LIVE and self._looks_like_admin(r):
                    bg_color = QColor("#4c1d95")
                    fg_color = QColor("#ede9fe")

                items = [host_item, status_item, code_item, time_item, extra_item]
                for col, item in enumerate(items):
                    if bg_color:
                        item.setBackground(bg_color)
                    item.setForeground(fg_color)
                    self.results_table.setItem(row, col, item)
        finally:
            self.results_table.setUpdatesEnabled(True)

    @staticmethod
    def _looks_like_admin(result: SubdomainResult) -> bool:
        haystack = " ".join(
            filter(
                None,
                [
                    result.title or "",
                    result.final_url or "",
                    result.hostname or "",
                ],
            )
        ).lower()
        return any(keyword in haystack for keyword in ADMIN_KEYWORDS)

    def _handle_discovery_error(self, error: str) -> None:
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText(f"Discovery error: {error or 'unknown error'}")

    def _handle_check_error(self, error: str) -> None:
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText(f"HTTP check error: {error or 'unknown error'}")

    def _update_summary(
        self, discovered: int | None = None, live: int | None = None, issues: int | None = None
    ) -> None:
        if discovered is not None:
            self.discovered_value.setText(str(discovered))
        if live is not None:
            self.live_value.setText(str(live))
        if issues is not None:
            self.issues_value.setText(str(issues))

    def _clear_history(self) -> None:
        answer = QMessageBox.question(
            self,
            "Clear scan history?",
            "This will remove all saved scans. "
            "The next scan will mark all subdomains as NEW.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)
        init_db()
        self.status_label.setText(
            "History cleared. Next scan will mark all subdomains as NEW."
        )

    def _export_csv(self) -> None:
        if not self.current_results:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save CSV",
            f"{self.current_domain}_scan.csv",
            "CSV Files (*.csv)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                f.write(build_csv(self.current_results))
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write file: {exc}")

    def _export_html(self) -> None:
        if not self.current_results:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save HTML Report",
            f"{self.current_domain}_report.html",
            "HTML Files (*.html)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(build_html(self.current_results, self.current_domain))
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", f"Could not write file: {exc}")

    def _build_ui(self) -> None:
        central_widget = QWidget()
        central_widget.setObjectName("centralWidget")
        self.setCentralWidget(central_widget)
        root_layout = QHBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = self._build_sidebar()
        content = self._build_content()
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content, 1)

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(24, 28, 24, 24)
        layout.setSpacing(16)

        logo = QLabel("SLC")
        logo.setObjectName("logo")
        subtitle = QLabel("Subdomain\nLive Checker")
        subtitle.setObjectName("sidebarTitle")
        description = QLabel("Passive discovery\nand low-impact\nHTTP checks.")
        description.setObjectName("sidebarDescription")
        version = QLabel("v0.2.1 - Intelligence")
        version.setObjectName("version")

        layout.addWidget(logo)
        layout.addWidget(subtitle)
        layout.addSpacing(16)
        layout.addWidget(description)
        layout.addStretch()
        layout.addWidget(version)
        return sidebar

    def _make_summary_card(self, label_text: str) -> tuple[QLabel, QFrame]:
        card = QFrame()
        card.setObjectName("summaryCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(4)
        value = QLabel("0")
        value.setObjectName("summaryValue")
        label = QLabel(label_text)
        label.setObjectName("summaryLabel")
        card_layout.addWidget(value)
        card_layout.addWidget(label)
        return value, card

    def _build_content(self) -> QWidget:
        content = QWidget()
        content.setObjectName("content")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(20)

        summary_grid = QGridLayout()
        summary_grid.setSpacing(12)
        layout.addLayout(summary_grid)

        self.discovered_value, discovered_card = self._make_summary_card("Discovered")
        self.live_value, live_card = self._make_summary_card("Live")
        self.issues_value, issues_card = self._make_summary_card("Issues")

        summary_grid.addWidget(discovered_card, 0, 0)
        summary_grid.addWidget(live_card, 0, 1)
        summary_grid.addWidget(issues_card, 0, 2)

        header = QLabel("Subdomain Scanner")
        header.setObjectName("pageTitle")
        description = QLabel("Discover subdomains and inspect their HTTP(S) availability.")
        description.setObjectName("pageDescription")

        target_frame = QFrame()
        target_frame.setObjectName("targetFrame")
        target_layout = QVBoxLayout(target_frame)
        target_layout.setContentsMargins(20, 20, 20, 20)
        target_layout.setSpacing(12)

        target_label = QLabel("Target domain")
        target_label.setObjectName("sectionLabel")
        input_row = QHBoxLayout()
        input_row.setSpacing(12)

        self.target_input = QLineEdit()
        self.target_input.setObjectName("targetInput")
        self.target_input.setPlaceholderText("example.com")
        self.target_input.setMinimumHeight(48)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setMinimumSize(120, 48)
        self.scan_button.clicked.connect(self._start_scan)

        self.clear_btn = QPushButton("Clear DB")
        self.clear_btn.setObjectName("exportButton")
        self.clear_btn.setMinimumSize(80, 48)
        self.clear_btn.clicked.connect(self._clear_history)

        self.export_csv_btn = QPushButton("CSV")
        self.export_csv_btn.setObjectName("exportButton")
        self.export_csv_btn.setMinimumSize(80, 48)
        self.export_csv_btn.clicked.connect(self._export_csv)

        self.export_html_btn = QPushButton("HTML")
        self.export_html_btn.setObjectName("exportButton")
        self.export_html_btn.setMinimumSize(80, 48)
        self.export_html_btn.clicked.connect(self._export_html)

        input_row.addWidget(self.target_input, 1)
        input_row.addWidget(self.scan_button)
        input_row.addWidget(self.clear_btn)
        input_row.addWidget(self.export_csv_btn)
        input_row.addWidget(self.export_html_btn)

        target_layout.addWidget(target_label)
        target_layout.addLayout(input_row)

        status_frame = QFrame()
        status_frame.setObjectName("statusFrame")
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 18, 20, 18)
        status_layout.setSpacing(10)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        self.status_label = QLabel("Ready to scan")
        self.status_label.setObjectName("statusLabel")
        status_layout.addWidget(self.progress_bar)
        status_layout.addWidget(self.status_label)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText("Search hostname...")
        self.search_input.setMinimumHeight(38)
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)

        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("filterCombo")
        self.filter_combo.addItems([
            "All",
            "Live",
            "Issues",
            "New",
            "Changed",
            "Removed",
            "Takeover",
        ])
        self.filter_combo.setMinimumHeight(38)
        self.filter_combo.currentTextChanged.connect(self._apply_filters)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(12)
        filter_row.addWidget(self.search_input, 1)
        filter_row.addWidget(self.filter_combo)

        self.results_table = QTableWidget()
        self.results_table.setObjectName("resultsTable")
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(
            ["Hostname", "Status", "Code", "Time (ms)", "Title / Error"]
        )

        header_view = self.results_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setVisible(False)

        legend_label = QLabel(
            "Legend: 🟩 New subdomain   |   🟨 Status changed\n"
            "🟥 Takeover indicator   |   🟦 401/403 (Access denied)\n"
            "🟪 Admin-like panel"
        )
        legend_label.setObjectName("legendLabel")
        legend_label.setVisible(False)
        self.legend = legend_label

        layout.addWidget(header)
        layout.addWidget(description)
        layout.addWidget(target_frame)
        layout.addWidget(status_frame)
        layout.addLayout(filter_row)
        layout.addWidget(self.results_table, 1)
        layout.addWidget(self.legend)
        return content

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QFrame#targetFrame, QFrame#statusFrame {
    background: #111720;
    border: 1px solid #202936;
    border-radius: 12px;
}

QLineEdit#targetInput {
    background: #0b0f14;
    color: #f8fafc;
    border: 1px solid #2a3544;
    border-radius: 8px;
    padding: 0 14px;
    font-size: 14px;
}

QPushButton#scanButton {
    background: #38bdf8;
    color: #071018;
    border: none;
    border-radius: 8px;
    padding: 0 20px;
    font-size: 14px;
    font-weight: 700;
}

QPushButton#exportButton {
    background: #1e293b;
    color: #94a3b8;
    border: 1px solid #334155;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
}

QFrame#summaryCard {
    background: #111720;
    border: 1px solid #202936;
    border-radius: 12px;
}

QTableWidget#resultsTable {
    background: #111720;
    color: #e2e8f0;
    border: 1px solid #202936;
    border-radius: 8px;
    gridline-color: #202936;
    font-size: 13px;
    outline: none;
}

QHeaderView::section {
    background: #0b0f14;
    color: #8996a8;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #202936;
    font-weight: 600;
}
        """)