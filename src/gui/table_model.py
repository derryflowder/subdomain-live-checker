from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor, QFont

from src.models import ResultStatus, SubdomainResult


class SubdomainTableModel(QAbstractTableModel):
    HEADERS = [
        "Hostname",
        "Status",
        "Code",
        "Tech",
        "Findings",
        "Time",
        "Title / Details",
    ]

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._results: list[SubdomainResult] = []

    def set_results(self, results: list[SubdomainResult]) -> None:
        self.beginResetModel()
        self._results = results
        self.endResetModel()

    def get_result(self, row: int) -> SubdomainResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._results)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.HEADERS)

    def headerData(self, section: int, orientation, role=Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        result = self._results[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._get_display_data(result, col)

        if role == Qt.ForegroundRole:
            if result.is_removed:
                return QColor("#6b6b6b")
            if col == 1:
                return self._get_status_color(result.status)
            return QColor("#e5e5e5")

        if role == Qt.BackgroundRole:
            if result.takeover:
                return QColor(239, 68, 68, 26)
            if result.is_new:
                return QColor(16, 185, 129, 16)
            if result.status_changed:
                return QColor(245, 158, 11, 16)
            if result.status_code in (401, 403):
                return QColor(96, 165, 250, 14)
            return None

        if role == Qt.FontRole and result.is_removed and col == 0:
            font = QFont()
            font.setItalic(True)
            return font

        if role == Qt.ToolTipRole:
            if col == 4 and result.findings:
                return "\n".join(
                    f"{f.path}  →  {f.status_code}" for f in result.findings
                )
            if col == 3 and result.technologies:
                return "\n".join(t.display() for t in result.technologies)
            if col == 6 and result.error:
                return result.error

        if role == Qt.TextAlignmentRole:
            if col in (2, 5):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        return None

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        if not self._results:
            return

        self.layoutAboutToBeChanged.emit()
        reverse = order == Qt.DescendingOrder

        def sort_key(r: SubdomainResult) -> Any:
            if column == 0:
                return r.hostname
            if column == 1:
                return r.status.value if r.status else ""
            if column == 2:
                return r.status_code if r.status_code is not None else -1
            if column == 3:
                return len(r.technologies)
            if column == 4:
                return len(r.findings)
            if column == 5:
                return r.response_time_ms if r.response_time_ms is not None else -1.0
            if column == 6:
                return r.title or r.error or ""
            return ""

        try:
            self._results.sort(key=sort_key, reverse=reverse)
        except TypeError:
            self._results.sort(key=lambda x: str(sort_key(x)), reverse=reverse)

        self.layoutChanged.emit()

    def _get_display_data(self, result: SubdomainResult, col: int) -> str:
        if result.is_removed:
            if col == 0:
                return result.hostname
            if col == 1:
                return "REMOVED"
            if col == 6:
                return result.error or "Was present in previous scan"
            return "-"

        if col == 0:
            return result.hostname

        if col == 1:
            return result.status.value if result.status else "-"

        if col == 2:
            return str(result.status_code) if result.status_code is not None else "-"

        if col == 3:
            techs = [t.display() for t in result.technologies]
            if len(techs) > 3:
                return ", ".join(techs[:3]) + f" +{len(techs) - 3}"
            return ", ".join(techs) if techs else "-"

        if col == 4:
            return f"{len(result.findings)} paths" if result.findings else "-"

        if col == 5:
            return f"{result.response_time_ms:.0f}" if result.response_time_ms is not None else "-"

        if col == 6:
            extra = result.title or result.error or "-"
            if result.takeover:
                return f"⚠️ Potential Takeover: {result.takeover}"
            return extra

        return ""

    @staticmethod
    def _get_status_color(status: ResultStatus | None) -> QColor:
        if status == ResultStatus.LIVE:
            return QColor("#10b981")
        if status == ResultStatus.REDIRECT:
            return QColor("#f59e0b")
        if status == ResultStatus.FORBIDDEN:
            return QColor("#f59e0b")
        if status == ResultStatus.NOT_FOUND:
            return QColor("#737373")
        if status in (
            ResultStatus.TIMEOUT,
            ResultStatus.UNREACHABLE,
            ResultStatus.ERROR,
        ):
            return QColor("#ef4444")
        return QColor("#a3a3a3")