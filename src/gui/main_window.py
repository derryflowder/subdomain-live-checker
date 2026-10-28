from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("Subdomain Live Checker")
        self.resize(1280, 760)
        self.setMinimumSize(1000, 650)

        self._build_ui()
        self._apply_styles()

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

        layout.addWidget(logo)
        layout.addWidget(subtitle)
        layout.addSpacing(16)
        layout.addWidget(description)
        layout.addStretch()

        version = QLabel("v0.1.0")
        version.setObjectName("version")
        layout.addWidget(version)

        return sidebar

    def _build_content(self) -> QWidget:
        content = QWidget()
        content.setObjectName("content")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(36, 32, 36, 32)
        layout.setSpacing(24)

        summary_grid = QGridLayout()
        summary_grid.setSpacing(12)

        layout.addLayout(summary_grid)

        discovered_card = QFrame()
        discovered_card.setObjectName("summaryCard")

        discovered_layout = QVBoxLayout(discovered_card)
        discovered_layout.setContentsMargins(18, 16, 18, 16)
        discovered_layout.setSpacing(4)

        discovered_value = QLabel("0")
        discovered_value.setObjectName("summaryValue")

        discovered_label = QLabel("Discovered")
        discovered_label.setObjectName("summaryLabel")

        discovered_layout.addWidget(discovered_value)
        discovered_layout.addWidget(discovered_label)

        summary_grid.addWidget(discovered_card, 0, 0)

        live_card = QFrame()
        live_card.setObjectName("summaryCard")

        live_layout = QVBoxLayout(live_card)
        live_layout.setContentsMargins(18, 16, 18, 16)
        live_layout.setSpacing(4)

        live_value = QLabel("0")
        live_value.setObjectName("summaryValue")

        live_label = QLabel("Live")
        live_label.setObjectName("summaryLabel")

        live_layout.addWidget(live_value)
        live_layout.addWidget(live_label)

        summary_grid.addWidget(live_card, 0, 1)

        live_card = QFrame()
        live_card.setObjectName("summaryCard")

        live_layout = QVBoxLayout(live_card)
        live_layout.setContentsMargins(18, 16, 18, 16)
        live_layout.setSpacing(4)

        live_value = QLabel("0")
        live_value.setObjectName("summaryValue")

        live_label = QLabel("Live")
        live_label.setObjectName("summaryLabel")

        live_layout.addWidget(live_value)
        live_layout.addWidget(live_label)

        summary_grid.addWidget(live_card, 0, 1)

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

        input_row.addWidget(self.target_input, 1)
        input_row.addWidget(self.scan_button)

        target_layout.addWidget(target_label)
        target_layout.addLayout(input_row)

        status_frame = QFrame()
        status_frame.setObjectName("statusFrame")
        status_layout = QVBoxLayout(status_frame)
        status_layout.setContentsMargins(20, 18, 20, 18)

        self.status_label = QLabel("Ready to scan")
        self.status_label.setObjectName("statusLabel")

        status_layout.addWidget(self.status_label)

        layout.addWidget(header)
        layout.addWidget(description)
        layout.addWidget(target_frame)
        layout.addWidget(status_frame)
        layout.addStretch()

        return content

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow {
                background: #0b0f14;
            }

            QWidget#centralWidget {
                background: #0b0f14;
            }

            QFrame#sidebar {
                background: #111720;
                border-right: 1px solid #202936;
            }

            QLabel#logo {
                color: #7dd3fc;
                font-size: 28px;
                font-weight: 800;
            }

            QLabel#sidebarTitle {
                color: #f1f5f9;
                font-size: 17px;
                font-weight: 700;
            }

            QLabel#sidebarDescription {
                color: #8491a3;
                font-size: 13px;
                line-height: 1.4;
            }

            QLabel#version {
                color: #566273;
                font-size: 12px;
            }

            QLabel#pageTitle {
                color: #f8fafc;
                font-size: 30px;
                font-weight: 750;
            }

            QLabel#pageDescription {
                color: #8996a8;
                font-size: 14px;
            }

            QFrame#targetFrame,
            QFrame#statusFrame {
                background: #111720;
                border: 1px solid #202936;
                border-radius: 12px;
            }

            QLabel#sectionLabel {
                color: #d8e0ea;
                font-size: 13px;
                font-weight: 650;
            }

            QLineEdit#targetInput {
                background: #0b0f14;
                color: #f8fafc;
                border: 1px solid #2a3544;
                border-radius: 8px;
                padding: 0 14px;
                font-size: 14px;
            }

            QLineEdit#targetInput:focus {
                border: 1px solid #38bdf8;
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

            QPushButton#scanButton:hover {
                background: #67cdf9;
            }

            QPushButton#scanButton:pressed {
                background: #0ea5e9;
            }

            QLabel#statusLabel {
                color: #8f9cad;
                font-size: 13px;
            }
                        QFrame#summaryCard {
                background: #111720;
                border: 1px solid #202936;
                border-radius: 12px;
            }

            QLabel#summaryValue {
                color: #f8fafc;
                font-size: 26px;
                font-weight: 750;
            }

            QLabel#summaryLabel {
                color: #8996a8;
                font-size: 12px;
            }
            """
        )
