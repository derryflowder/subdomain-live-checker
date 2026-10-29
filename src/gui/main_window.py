from collections import Counter

from PySide6.QtCore import Qt, QThreadPool, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from src.checker import check_subdomains
from src.database import (
    DatabaseError,
    ScanRepository,
    SQLiteScanRepository,
    calculate_diff,
)
from src.discovery_sources import discover_from_all_sources
from src.export import build_csv, build_html
from src.gui.filtering import filter_results
from src.gui.table_model import SubdomainTableModel
from src.gui.workers import Worker, WorkerSignals
from src.models import SubdomainResult
from src.paths import DEFAULT_PATHS, MAX_PATHS


def normalize_domain_input(raw: str) -> str:
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
    def __init__(self, repository: ScanRepository | None = None) -> None:
        super().__init__()
        self.setWindowTitle("Subdomain Live Checker")
        self.resize(1320, 820)
        self.setMinimumSize(1040, 700)

        self.repository = repository or SQLiteScanRepository()
        self.thread_pool = QThreadPool.globalInstance()
        self.active_workers: set[Worker] = set()
        self.current_domain = ""
        self.current_results: list[SubdomainResult] = []

        self._build_ui()
        self._apply_styles()

    def _track_worker(self, worker: Worker) -> None:
        worker.setAutoDelete(False)
        self.active_workers.add(worker)
        worker.signals.finished.connect(
            lambda: self.active_workers.discard(worker)
        )

    def _run_discovery(self, domain: str):
        return discover_from_all_sources(domain)

    def _run_checks(
        self,
        hostnames: list[str],
        paths,
        verify: bool,
        trust_env: bool,
        on_progress,
    ) -> list:
        return check_subdomains(
            hostnames,
            on_progress=on_progress,
            paths=paths,
            verify=verify,
            trust_env=trust_env,
        )

    def _parse_paths(self) -> list[str]:
        if not self.paths_toggle.isChecked():
            return []
        paths: list[str] = []
        for line in self.paths_input.toPlainText().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            paths.append(line)
            if len(paths) >= MAX_PATHS:
                break
        return paths

    def _toggle_paths(self) -> None:
        visible = self.paths_toggle.isChecked()
        self.paths_panel.setVisible(visible)
        self.paths_toggle.setText("Paths ▴" if visible else "Paths ▾")

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
        self.results_table.setVisible(False)
        self.legend.setVisible(False)
        self.findings_banner.setVisible(False)
        self.table_model.set_results([])

        self._update_summary(discovered=0, live=0, issues=0)
        self.status_label.setText(
            f"Discovering subdomains for {self.current_domain}..."
        )

        worker = Worker(self._run_discovery, self.current_domain)
        worker.signals.result.connect(self._handle_discovery_result)
        worker.signals.error.connect(self._handle_discovery_error)
        self._track_worker(worker)
        self.thread_pool.start(worker)

    def _handle_discovery_result(self, result) -> None:
        hostnames, source_results = result

        if not hostnames:
            self.scan_button.setEnabled(True)
            errors = [
                f"{s.source}: {s.error}" for s in source_results if s.error
            ]
            self.status_label.setText(
                "Discovery failed: " + " | ".join(errors)
                if errors
                else "No subdomains found"
            )
            return

        paths = self._parse_paths()
        verify = not self.ignore_tls_check.isChecked()
        trust_env = self.use_proxy_check.isChecked()

        self._update_summary(discovered=len(hostnames))
        phase_hint = (
            f"with {len(paths)} paths" if paths else "no path scan"
        )
        self.status_label.setText(
            f"Discovered {len(hostnames)} subdomains. "
            f"Starting HTTP checks ({phase_hint})..."
        )

        self.progress_bar.setMaximum(len(hostnames))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.results_table.setVisible(True)
        self.legend.setVisible(True)

        signals = WorkerSignals()
        worker = Worker(
            self._run_checks,
            hostnames,
            paths,
            verify,
            trust_env,
            signals.progress.emit,
            _signals=signals,
        )
        signals.progress.connect(self._handle_check_progress)
        signals.result.connect(self._handle_check_result)
        signals.error.connect(self._handle_check_error)
        self._track_worker(worker)
        self.thread_pool.start(worker)

    def _handle_check_progress(self, done: int, total: int) -> None:
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(done)
        self.status_label.setText(f"Checking: {done}/{total}")

    def _handle_check_result(self, results: list) -> None:
        self.progress_bar.setVisible(False)

        if not results:
            self.status_label.setText("No hosts responded.")
            self.scan_button.setEnabled(True)
            return

        try:
            previous_data = self.repository.get_previous_results(
                self.current_domain
            )
        except DatabaseError as exc:
            QMessageBox.warning(
                self,
                "History unavailable",
                f"Cannot compare with the previous scan:\n{exc}",
            )
            self.status_label.setText(
                "Scan completed, but history comparison failed."
            )
            self.scan_button.setEnabled(True)
            return

        current_data = {
            r.hostname: {
                "hostname": r.hostname,
                "status_code": (
                    r.status_code if r.status_code is not None else -1
                ),
                "status_text": r.status.value if r.status else "",
                "tech": _tech_signature(r),
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
            self.repository.save_results(self.current_domain, results)
        except DatabaseError as exc:
            QMessageBox.warning(self, "History not saved", str(exc))

        counts = Counter(
            (r.status.value if r.status else "unknown") for r in results
        )
        live = (
            counts.get("live", 0)
            + counts.get("redirect", 0)
            + counts.get("forbidden", 0)
        )
        issues = len(results) - live
        takeovers = sum(1 for r in results if r.takeover)
        findings_total = sum(len(r.findings) for r in results)

        self._update_summary(live=live, issues=issues)
        self._update_findings_banner(results)

        status_text = (
            f"Checked {len(results)} | Live: {live} | Issues: {issues}"
            f" | New: {len(diff['new'])}"
            f" | Changed: {len(diff['changed'])}"
            f" | Removed: {len(diff['removed'])}"
        )
        if findings_total:
            status_text += f" | Path findings: {findings_total}"
        if takeovers > 0:
            status_text += f" | ⚠️ Takeovers: {takeovers}"

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

        self.table_model.set_results(filtered_results)

        header = self.results_table.horizontalHeader()
        sort_col = header.sortIndicatorSection()
        if sort_col >= 0:
            self.table_model.sort(sort_col, header.sortIndicatorOrder())

    def _on_table_context_menu(self, pos) -> None:
        index = self.results_table.indexAt(pos)
        if not index.isValid():
            return

        result = self.table_model.get_result(index.row())
        if result is None or result.is_removed:
            return

        menu = QMenu(self.results_table)
        copy_action = menu.addAction("Copy hostname")
        open_action = menu.addAction("Open in browser")

        chosen = menu.exec(self.results_table.viewport().mapToGlobal(pos))
        if chosen == copy_action:
            QApplication.clipboard().setText(result.hostname)
        elif chosen == open_action:
            QDesktopServices.openUrl(QUrl(f"https://{result.hostname}/"))

    def _update_findings_banner(self, results: list) -> None:
        counter: Counter[str] = Counter()
        for r in results:
            for f in r.findings:
                counter[f.path] += 1

        interesting = [
            (path, count)
            for path, count in counter.most_common(8)
            if count > 1
        ]
        if not interesting:
            self.findings_banner.setVisible(False)
            return

        text = "Common across hosts: " + "  ·  ".join(
            f"{path} ({count})" for path, count in interesting
        )
        self.findings_banner.setText(text)
        self.findings_banner.setVisible(True)

    def _handle_discovery_error(self, error: str) -> None:
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText(
            f"Discovery error: {error or 'unknown error'}"
        )

    def _handle_check_error(self, error: str) -> None:
        self.progress_bar.setVisible(False)
        self.scan_button.setEnabled(True)
        self.status_label.setText(
            f"HTTP check error: {error or 'unknown error'}"
        )

    def _update_summary(
        self,
        discovered: int | None = None,
        live: int | None = None,
        issues: int | None = None,
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

        self.repository.clear_history()
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
            QMessageBox.critical(
                self, "Export failed", f"Could not write file: {exc}"
            )

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
                f.write(
                    build_html(self.current_results, self.current_domain)
                )
        except OSError as exc:
            QMessageBox.critical(
                self, "Export failed", f"Could not write file: {exc}"
            )

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("root")
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(44, 32, 44, 32)
        layout.setSpacing(18)

        layout.addLayout(self._build_header())
        layout.addWidget(self._build_title())
        layout.addLayout(self._build_target_row())
        layout.addLayout(self._build_action_row())
        layout.addWidget(self._build_paths_panel())
        layout.addLayout(self._build_summary_row())
        layout.addWidget(self._build_status_block())
        layout.addWidget(self._build_findings_banner())
        layout.addLayout(self._build_filter_row())
        layout.addWidget(self._build_table(), 1)
        layout.addWidget(self._build_legend())

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        brand = QLabel("SLC")
        brand.setObjectName("brand")

        version = QLabel("v0.4.0")
        version.setObjectName("version")

        row.addWidget(brand)
        row.addWidget(version)
        row.addStretch()
        return row

    def _build_title(self) -> QWidget:
        wrapper = QWidget()
        wl = QVBoxLayout(wrapper)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.setSpacing(4)

        title = QLabel("Subdomain Scanner")
        title.setObjectName("pageTitle")

        subtitle = QLabel(
            "Discover, inspect, and analyze your attack surface."
        )
        subtitle.setObjectName("pageSubtitle")

        wl.addWidget(title)
        wl.addWidget(subtitle)
        return wrapper

    def _build_target_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com")
        self.target_input.setObjectName("targetInput")
        self.target_input.setMinimumHeight(50)

        self.scan_button = QPushButton("Scan")
        self.scan_button.setObjectName("scanButton")
        self.scan_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_button.setMinimumSize(140, 50)
        self.scan_button.clicked.connect(self._start_scan)

        row.addWidget(self.target_input, 1)
        row.addWidget(self.scan_button)
        return row

    def _build_action_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)

        self.paths_toggle = QPushButton("Paths ▾")
        self.paths_toggle.setObjectName("ghostButton")
        self.paths_toggle.setCheckable(True)
        self.paths_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.paths_toggle.clicked.connect(self._toggle_paths)

        self.ignore_tls_check = QCheckBox("Ignore TLS")
        self.ignore_tls_check.setObjectName("ghostCheckbox")
        self.ignore_tls_check.setCursor(Qt.CursorShape.PointingHandCursor)

        self.use_proxy_check = QCheckBox("Use system proxy")
        self.use_proxy_check.setObjectName("ghostCheckbox")
        self.use_proxy_check.setCursor(Qt.CursorShape.PointingHandCursor)
        self.use_proxy_check.setChecked(False)

        self.clear_btn = QPushButton("Clear history")
        self.clear_btn.setObjectName("ghostButton")
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.clicked.connect(self._clear_history)

        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.setObjectName("ghostButton")
        self.export_csv_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_csv_btn.clicked.connect(self._export_csv)

        self.export_html_btn = QPushButton("Export HTML")
        self.export_html_btn.setObjectName("ghostButton")
        self.export_html_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_html_btn.clicked.connect(self._export_html)

        row.addWidget(self.paths_toggle)
        row.addWidget(self.ignore_tls_check)
        row.addWidget(self.use_proxy_check)
        row.addWidget(self.clear_btn)
        row.addStretch()
        row.addWidget(self.export_csv_btn)
        row.addWidget(self.export_html_btn)
        return row

    def _build_paths_panel(self) -> QFrame:
        self.paths_panel = QFrame()
        self.paths_panel.setObjectName("pathsPanel")
        self.paths_panel.setVisible(False)

        pl = QVBoxLayout(self.paths_panel)
        pl.setContentsMargins(20, 18, 20, 18)
        pl.setSpacing(10)

        label = QLabel("Path pool — one path per line")
        label.setObjectName("sectionLabel")

        self.paths_input = QPlainTextEdit()
        self.paths_input.setObjectName("pathsInput")
        self.paths_input.setPlainText("\n".join(DEFAULT_PATHS))
        self.paths_input.setFixedHeight(160)

        hint = QLabel(
            f"Up to {MAX_PATHS} paths. Soft-404 pages are auto-detected "
            "and skipped."
        )
        hint.setObjectName("hintLabel")

        pl.addWidget(label)
        pl.addWidget(self.paths_input)
        pl.addWidget(hint)
        return self.paths_panel

    def _build_summary_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self.discovered_value, discovered_card = self._make_summary_card(
            "Discovered"
        )
        self.live_value, live_card = self._make_summary_card("Live")
        self.issues_value, issues_card = self._make_summary_card("Issues")

        row.addWidget(discovered_card)
        row.addWidget(live_card)
        row.addWidget(issues_card)
        return row

    def _make_summary_card(
        self, label_text: str
    ) -> tuple[QLabel, QFrame]:
        card = QFrame()
        card.setObjectName("summaryCard")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 18, 20, 18)
        cl.setSpacing(6)

        value = QLabel("0")
        value.setObjectName("summaryValue")

        label = QLabel(label_text.upper())
        label.setObjectName("summaryLabel")

        cl.addWidget(value)
        cl.addWidget(label)
        return value, card

    def _build_status_block(self) -> QWidget:
        wrapper = QWidget()
        wl = QVBoxLayout(wrapper)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.setSpacing(8)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setFixedHeight(2)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusLabel")

        wl.addWidget(self.progress_bar)
        wl.addWidget(self.status_label)
        return wrapper

    def _build_findings_banner(self) -> QLabel:
        self.findings_banner = QLabel("")
        self.findings_banner.setObjectName("findingsBanner")
        self.findings_banner.setWordWrap(True)
        self.findings_banner.setVisible(False)
        return self.findings_banner

    def _build_filter_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("searchInput")
        self.search_input.setPlaceholderText(
            "Search hostname, title, technology, path..."
        )
        self.search_input.setMinimumHeight(42)
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._apply_filters)

        self.filter_combo = QComboBox()
        self.filter_combo.setObjectName("filterCombo")
        self.filter_combo.addItems(
            [
                "All",
                "Live",
                "Issues",
                "New",
                "Changed",
                "Removed",
                "Takeover",
                "With findings",
            ]
        )
        self.filter_combo.setMinimumHeight(42)
        self.filter_combo.currentTextChanged.connect(self._apply_filters)

        row.addWidget(self.search_input, 1)
        row.addWidget(self.filter_combo)
        return row

    def _build_table(self) -> QTableView:
        self.results_table = QTableView()
        self.results_table.setObjectName("resultsTable")

        self.table_model = SubdomainTableModel(self)
        self.results_table.setModel(self.table_model)

        hv = self.results_table.horizontalHeader()
        hv.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        hv.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        hv.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.results_table.setEditTriggers(
            QTableView.EditTrigger.NoEditTriggers
        )
        self.results_table.setSelectionBehavior(
            QTableView.SelectionBehavior.SelectRows
        )
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setShowGrid(False)
        self.results_table.setAlternatingRowColors(False)
        self.results_table.setSortingEnabled(True)
        self.results_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        self.results_table.customContextMenuRequested.connect(
            self._on_table_context_menu
        )
        self.results_table.setVisible(False)
        return self.results_table

    def _build_legend(self) -> QLabel:
        self.legend = QLabel(
            "● live   ● redirect / forbidden   ● error     "
            "·   row tint:  new · changed · takeover     "
            "·   right-click: copy / open"
        )
        self.legend.setObjectName("legendLabel")
        self.legend.setVisible(False)
        return self.legend

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QMainWindow, QWidget#root {
                background: #0a0a0a;
                color: #fafafa;
                font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
                font-size: 13px;
            }

            QLabel#brand {
                font-size: 20px;
                font-weight: 800;
                letter-spacing: 3px;
                color: #fafafa;
            }

            QLabel#version {
                font-size: 11px;
                color: #525252;
                padding-left: 6px;
                padding-top: 4px;
            }

            QLabel#pageTitle {
                font-size: 26px;
                font-weight: 700;
                color: #fafafa;
            }

            QLabel#pageSubtitle {
                font-size: 13px;
                color: #737373;
            }

            QLineEdit#targetInput {
                background: #141414;
                color: #fafafa;
                border: 1px solid #262626;
                border-radius: 10px;
                padding: 0 16px;
                font-size: 14px;
                selection-background-color: #404040;
            }

            QLineEdit#targetInput:focus {
                border-color: #404040;
            }

            QPushButton#scanButton {
                background: #fafafa;
                color: #0a0a0a;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 600;
                padding: 0 24px;
            }

            QPushButton#scanButton:hover  { background: #e5e5e5; }
            QPushButton#scanButton:disabled {
                background: #1f1f1f;
                color: #525252;
            }

            QPushButton#ghostButton {
                background: transparent;
                color: #a3a3a3;
                border: 1px solid #262626;
                border-radius: 8px;
                padding: 0 16px;
                min-height: 36px;
                font-size: 12px;
                font-weight: 500;
            }

            QPushButton#ghostButton:hover {
                color: #fafafa;
                border-color: #404040;
            }

            QPushButton#ghostButton:checked {
                background: #1f1f1f;
                color: #fafafa;
                border-color: #404040;
            }

            QCheckBox#ghostCheckbox {
                color: #a3a3a3;
                font-size: 12px;
                font-weight: 500;
                spacing: 8px;
                padding: 0 4px;
            }

            QCheckBox#ghostCheckbox:hover {
                color: #fafafa;
            }

            QCheckBox#ghostCheckbox::indicator {
                width: 16px;
                height: 16px;
                border: 1px solid #262626;
                border-radius: 4px;
                background: #141414;
            }

            QCheckBox#ghostCheckbox::indicator:hover {
                border-color: #404040;
            }

            QCheckBox#ghostCheckbox::indicator:checked {
                background: #fafafa;
                border-color: #fafafa;
            }

            QFrame#summaryCard {
                background: #111111;
                border: 1px solid #1f1f1f;
                border-radius: 12px;
            }

            QLabel#summaryValue {
                font-size: 28px;
                font-weight: 700;
                color: #fafafa;
            }

            QLabel#summaryLabel {
                font-size: 10px;
                color: #737373;
                letter-spacing: 1.5px;
            }

            QFrame#pathsPanel {
                background: #0f0f0f;
                border: 1px solid #1f1f1f;
                border-radius: 12px;
            }

            QPlainTextEdit#pathsInput {
                background: #0a0a0a;
                color: #d4d4d4;
                border: 1px solid #262626;
                border-radius: 8px;
                padding: 10px;
                font-family: "SF Mono", "JetBrains Mono", Monaco, Consolas, monospace;
                font-size: 12px;
                selection-background-color: #262626;
            }

            QPlainTextEdit#pathsInput:focus {
                border-color: #404040;
            }

            QLabel#sectionLabel {
                font-size: 12px;
                color: #a3a3a3;
                font-weight: 600;
            }

            QLabel#hintLabel {
                font-size: 11px;
                color: #525252;
            }

            QLabel#statusLabel {
                font-size: 12px;
                color: #a3a3a3;
            }

            QLabel#findingsBanner {
                background: rgba(245, 158, 11, 0.08);
                border: 1px solid rgba(245, 158, 11, 0.2);
                border-radius: 8px;
                color: #fbbf24;
                padding: 10px 14px;
                font-size: 12px;
            }

            QProgressBar#progressBar {
                background: #1a1a1a;
                border: none;
                border-radius: 1px;
            }

            QProgressBar#progressBar::chunk {
                background: #fafafa;
                border-radius: 1px;
            }

            QLineEdit#searchInput {
                background: #141414;
                color: #fafafa;
                border: 1px solid #262626;
                border-radius: 10px;
                padding: 0 14px;
                font-size: 13px;
            }

            QLineEdit#searchInput:focus {
                border-color: #404040;
            }

            QComboBox#filterCombo {
                background: #141414;
                color: #fafafa;
                border: 1px solid #262626;
                border-radius: 10px;
                padding: 0 14px;
                min-width: 140px;
            }

            QComboBox#filterCombo::drop-down {
                border: none;
                width: 24px;
            }

            QComboBox#filterCombo::down-arrow {
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid #737373;
                margin-right: 12px;
            }

            QComboBox QAbstractItemView {
                background: #141414;
                color: #fafafa;
                border: 1px solid #262626;
                border-radius: 8px;
                selection-background-color: #262626;
                padding: 4px;
                outline: none;
            }

            QTableView#resultsTable {
                background: #0a0a0a;
                color: #e5e5e5;
                border: 1px solid #1f1f1f;
                border-radius: 12px;
                font-size: 13px;
                outline: none;
                selection-background-color: #1a1a1a;
                selection-color: #fafafa;
            }

            QTableView#resultsTable::item {
                padding: 10px 12px;
                border-bottom: 1px solid #141414;
            }

            QHeaderView::section {
                background: #0f0f0f;
                color: #737373;
                padding: 12px;
                border: none;
                border-bottom: 1px solid #1f1f1f;
                font-weight: 600;
                font-size: 10px;
                letter-spacing: 0.8px;
            }

            QLabel#legendLabel {
                font-size: 11px;
                color: #525252;
                padding-top: 6px;
            }

            QMenu {
                background: #141414;
                color: #fafafa;
                border: 1px solid #262626;
                border-radius: 8px;
                padding: 4px;
            }

            QMenu::item {
                padding: 6px 20px;
                border-radius: 4px;
            }

            QMenu::item:selected {
                background: #262626;
            }

            QMessageBox {
                background: #141414;
                color: #fafafa;
            }

            QScrollBar:vertical {
                background: transparent;
                width: 10px;
            }

            QScrollBar::handle:vertical {
                background: #2a2a2a;
                border-radius: 5px;
                min-height: 30px;
            }

            QScrollBar::handle:vertical:hover {
                background: #404040;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)


def _tech_signature(result: SubdomainResult) -> str:
    import json

    return json.dumps(
        [
            {"name": t.name, "version": t.version, "category": t.category}
            for t in result.technologies
        ]
    )