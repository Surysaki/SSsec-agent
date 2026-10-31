"""SSsec 应用入口。"""

from __future__ import annotations

import ctypes
import logging
import logging.handlers
import sys
import traceback

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QMessageBox

from sssec import APP_NAME, __version__
from sssec.config import SettingsStore, ensure_data_dirs, get_data_dir
from sssec.ui.icons import app_icon
from sssec.ui.main_window import MainWindow
from sssec.ui.theme import apply_theme


def setup_logging() -> None:
    data_dir = get_data_dir()
    ensure_data_dirs(data_dir)
    log_path = data_dir / "logs" / "sssec.log"
    logger = logging.getLogger("sssec")
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"
    )
    file_handler = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.setLevel(logging.INFO)
    logger.addHandler(console)
    logging.getLogger("sssec.agent").setLevel(logging.INFO)
    logging.getLogger("sssec.ui").setLevel(logging.INFO)


def _install_exception_hook(app: QApplication) -> None:
    def handle(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logging.getLogger("sssec").error(
            "未捕获异常\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )
        try:
            QMessageBox.critical(
                None,
                "SSsec 发生错误",
                f"应用遇到了未处理的错误：\n\n{exc_value}\n\n"
                "详细信息已写入本地日志。你可以在数据目录的 logs/ 中查看。",
            )
        except Exception:
            pass

    sys.excepthook = handle


def main() -> None:
    setup_logging()
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "SSsec.SecurityAgent"
            )
        except Exception:
            pass
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName("SSsec")
    app.setOrganizationName("SSsec")
    app.setApplicationVersion(__version__)
    app.setQuitOnLastWindowClosed(True)
    data_dir = get_data_dir()
    ensure_data_dirs(data_dir)
    saved_settings = SettingsStore(data_dir).load()
    apply_theme(app, saved_settings.theme)
    app.setWindowIcon(app_icon())
    _install_exception_hook(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
