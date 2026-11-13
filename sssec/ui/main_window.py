"""SSsec 主窗口：会话管理、流式聊天与 Agent 生命周期。"""

from __future__ import annotations

import ctypes
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QByteArray, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import (
    QAction,
    QCloseEvent,
    QColor,
    QDesktopServices,
    QGuiApplication,
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sssec.agent.history import conversation_to_messages
from sssec.agent.llm import ModelConfigError, friendly_error, validate_provider
from sssec.agent.worker import AgentWorker
from sssec.config import (
    AppSettings,
    SettingsStore,
    ensure_data_dirs,
    get_data_dir,
    load_ui_state,
    save_ui_state,
)
from sssec.models import (
    Conversation,
    add_finding,
    append_text,
    assistant_text,
    ensure_tool,
    find_tool,
    now_iso,
    repair_interrupted_messages,
)
from sssec.security.scope import scope_summary
from sssec.store import ConversationStore
from sssec.ui.chat_view import ChatView
from sssec.ui.composer import Composer
from sssec.ui.findings_dialog import FindingsDialog
from sssec.ui.icons import app_icon, icon
from sssec.ui.message_widgets import ApprovalBar
from sssec.ui.scope_dialog import ScopeDialog
from sssec.ui.settings_dialog import SettingsDialog
from sssec.ui.sidebar import Sidebar
from sssec.ui.theme import COLORS, apply_theme, current_theme, is_dark
from sssec.ui.widgets import ElidedLabel, Toast, set_dynamic_property

logger = logging.getLogger("sssec.ui")


def _model_label(provider) -> str:
    if provider.type == "demo":
        return "离线演示"
    return f"{provider.name} · {provider.model}"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SSsec · 授权安全测试 Agent")
        self.setWindowIcon(app_icon())
        self.setMinimumSize(1040, 680)
        screen = QGuiApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.resize(
                min(1320, max(1040, available.width() - 100)),
                min(860, max(680, available.height() - 100)),
            )
        else:
            self.resize(1320, 860)

        self.data_dir = get_data_dir()
        ensure_data_dirs(self.data_dir)
        self.settings_store = SettingsStore(self.data_dir)
        self.settings: AppSettings = self.settings_store.load()
        self.conv_store = ConversationStore(self.data_dir)
        self.ui_state = load_ui_state(self.data_dir)
        self.conversations: dict[str, Conversation] = {
            conversation.id: conversation for conversation in self.conv_store.list_all()
        }
        self.current_id: str | None = None
        self.current_conversation: Conversation | None = None
        self.active_run: dict[str, Any] | None = None
        self._active_worker: AgentWorker | None = None
        self._retired_workers: list[AgentWorker] = []
        self.pending_approval: dict[str, Any] | None = None
        self._pending_conversation_id: str | None = None
        self._drafts: dict[str, str] = {}
        self._dirty = False
        self._closing = False

        self._build_ui()
        self._connect_signals()
        self._install_shortcuts()
        self._restore_window_geometry()

        if not self.conversations:
            conversation = Conversation.create()
            self.conversations[conversation.id] = conversation
            self._save_conversation(conversation)

        last_id = str(self.ui_state.get("last_conversation_id") or "")
        if last_id not in self.conversations:
            last_id = max(
                self.conversations.values(), key=lambda item: item.updated_at
            ).id
        self._select_conversation(last_id, save_previous=False)

        self._autosave_timer = QTimer(self)
        self._autosave_timer.setInterval(5000)
        self._autosave_timer.timeout.connect(self._autosave)
        self._autosave_timer.start()

    # ================================================================ UI
    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("Root")
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.setCentralWidget(central)

        self.sidebar = Sidebar()
        root.addWidget(self.sidebar)

        main = QWidget()
        main.setObjectName("MainPane")
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.header = QFrame()
        self.header.setObjectName("ChatHeader")
        self.header.setFixedHeight(76)
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(27, 0, 22, 0)
        header_layout.setSpacing(8)

        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        self.title_label = ElidedLabel("SSsec")
        self.title_label.setObjectName("PageTitle")
        self.subtitle_label = QLabel("授权安全测试工作台")
        self.subtitle_label.setObjectName("PageSub")
        title_box.addWidget(self.title_label)
        title_box.addWidget(self.subtitle_label)
        header_layout.addLayout(title_box, 1)

        self.access_header = QPushButton("完全权限")
        self.access_header.setObjectName("Chip")
        self.access_header.setCursor(Qt.PointingHandCursor)
        self.access_header.setIcon(icon("bolt", COLORS["muted"], 14))
        self.access_header.setIconSize(QSize(14, 14))
        self.access_header.clicked.connect(self.toggle_full_permission)
        header_layout.addWidget(self.access_header)

        self.scope_header = QPushButton("设置测试目标")
        self.scope_header.setObjectName("Chip")
        self.scope_header.setCursor(Qt.PointingHandCursor)
        self.scope_header.setIcon(icon("target", COLORS["muted"], 14))
        self.scope_header.setIconSize(QSize(14, 14))
        header_layout.addWidget(self.scope_header)

        self.findings_button = QPushButton("发现")
        self.findings_button.setObjectName("Chip")
        self.findings_button.setCursor(Qt.PointingHandCursor)
        self.findings_button.setIcon(icon("file", COLORS["muted"], 14))
        self.findings_button.setIconSize(QSize(14, 14))
        header_layout.addWidget(self.findings_button)

        self.more_button = QToolButton()
        self.more_button.setObjectName("IconButton")
        self.more_button.setIcon(icon("more", COLORS["muted"], 18))
        self.more_button.setFixedSize(34, 34)
        self.more_button.setCursor(Qt.PointingHandCursor)
        self.more_button.setToolTip("更多操作")
        self.more_button.clicked.connect(self._open_more_menu)
        header_layout.addWidget(self.more_button)
        main_layout.addWidget(self.header)

        self.chat_view = ChatView()
        main_layout.addWidget(self.chat_view, 1)

        self.approval_host = QWidget()
        approval_layout = QHBoxLayout(self.approval_host)
        approval_layout.setContentsMargins(26, 8, 26, 0)
        approval_layout.setSpacing(0)
        approval_layout.addStretch(1)
        self.approval_bar = ApprovalBar()
        self.approval_bar.setMaximumWidth(920)
        approval_layout.addWidget(self.approval_bar, 20)
        approval_layout.addStretch(1)
        self.approval_host.setVisible(False)
        main_layout.addWidget(self.approval_host)

        self.composer = Composer()
        main_layout.addWidget(self.composer)
        root.addWidget(main, 1)

        self.toast = Toast(self)
        self.toast.hide()

    def _connect_signals(self) -> None:
        self.sidebar.new_conversation_requested.connect(self.new_conversation)
        self.sidebar.conversation_selected.connect(self._select_conversation)
        self.sidebar.settings_requested.connect(self.open_settings)
        self.sidebar.theme_toggle_requested.connect(self.toggle_theme)
        self.sidebar.rename_requested.connect(self.rename_conversation)
        self.sidebar.delete_requested.connect(self.delete_conversation)
        self.chat_view.scope_requested.connect(self.open_scope_dialog)
        self.chat_view.settings_requested.connect(self.open_settings)
        self.chat_view.prompt_selected.connect(self._use_prompt)
        self.composer.send_requested.connect(self._send_message)
        self.composer.stop_requested.connect(self._stop_active_run)
        self.composer.scope_requested.connect(self.open_scope_dialog)
        self.composer.settings_requested.connect(self.open_settings)
        self.scope_header.clicked.connect(self.open_scope_dialog)
        self.findings_button.clicked.connect(self.open_findings)
        self.approval_bar.approved.connect(lambda: self._resolve_approval(True))
        self.approval_bar.denied.connect(lambda: self._resolve_approval(False))

    def _install_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self.new_conversation)
        QShortcut(QKeySequence("Ctrl+,"), self, activated=self.open_settings)
        QShortcut(
            QKeySequence("Ctrl+K"), self, activated=lambda: self.sidebar.focus_search()
        )

    def _restore_window_geometry(self) -> None:
        geometry = self.ui_state.get("window_geometry")
        if geometry:
            try:
                self.restoreGeometry(QByteArray.fromHex(str(geometry).encode("ascii")))
                return
            except Exception:
                pass
        screen = QGuiApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.move(
                available.left() + max(0, (available.width() - self.width()) // 2),
                available.top() + max(0, (available.height() - self.height()) // 2),
            )

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        QTimer.singleShot(30, self._apply_window_chrome)
        QTimer.singleShot(450, self._post_show)

    def _apply_window_chrome(self) -> None:
        """让 Windows 标题栏跟随当前主题（浅色 / 深色）。"""
        if sys.platform != "win32":
            return
        try:
            hwnd = int(self.winId())
            dark = ctypes.c_int(1 if is_dark() else 0)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark)
            )
            for attribute, color_key in ((35, "bg"), (36, "border")):
                try:
                    color = QColor(COLORS[color_key])
                    value = ctypes.c_int(
                        (color.blue() << 16) | (color.green() << 8) | color.red()
                    )
                    ctypes.windll.dwmapi.DwmSetWindowAttribute(
                        hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)
                    )
                except Exception:
                    pass
        except Exception:
            logger.debug("无法调整 Windows 标题栏颜色", exc_info=True)

    def _post_show(self) -> None:
        if self._closing:
            return
        provider = self.settings.active_provider()
        if provider.type == "demo":
            self.toast.show_message(
                "当前为离线演示模型。点击左下角「设置」接入 DeepSeek、OpenAI、Claude 等模型。",
                5200,
            )
        self.composer.focus_input()

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if hasattr(self, "toast") and self.toast.isVisible():
            self.toast._reposition()

    # ================================================================ state
    def _sorted_conversations(self) -> list[Conversation]:
        return sorted(
            self.conversations.values(), key=lambda item: item.updated_at, reverse=True
        )

    def _save_conversation(self, conversation: Conversation | None = None) -> None:
        conversation = conversation or self.current_conversation
        if conversation is None:
            return
        try:
            self.conv_store.save(conversation)
        except Exception:
            logger.exception("保存会话失败")
            self.toast.show_message("会话保存失败，请检查本地数据目录权限。", 5000)

    def _autosave(self) -> None:
        if not self._dirty:
            return
        if self.current_conversation:
            self._save_conversation(self.current_conversation)
        if self.active_run:
            conversation = self.conversations.get(self.active_run.get("conversation_id"))
            if conversation and conversation is not self.current_conversation:
                self._save_conversation(conversation)
        self._dirty = False

    def _refresh_sidebar(self) -> None:
        running_id = self.active_run.get("conversation_id") if self.active_run else None
        self.sidebar.set_conversations(
            self._sorted_conversations(), self.current_id, running_id
        )

    def _provider(self):
        return self.settings.active_provider()

    def _provider_meta(self) -> str:
        provider = self._provider()
        if provider.type == "demo":
            return "本地模拟 · 无需密钥"
        return f"{provider.type_label} · {provider.model}"

    def _refresh_model_ui(self) -> None:
        provider = self._provider()
        self.sidebar.set_model(provider.name, self._provider_meta())
        label = _model_label(provider)
        self.subtitle_label.setText(
            f"{label}  ·  授权安全测试工作台"
            if provider.type != "demo"
            else "离线演示模式  ·  无需连接外部模型"
        )
        self.composer.set_context(
            model_label=label,
            scope_text=self._scope_text(),
            scope_ok=self._scope_ready(),
            demo=provider.type == "demo",
            full_access=bool(
                self.current_conversation and self.current_conversation.full_permission
            ),
        )

    def _scope_text(self) -> str:
        if not self.current_conversation:
            return "未设置目标（不限制）"
        return scope_summary(
            self.current_conversation.scope, self.current_conversation.authorized
        )

    def _scope_ready(self) -> bool:
        return bool(self.current_conversation and self.current_conversation.scope)

    def _refresh_header(self) -> None:
        conversation = self.current_conversation
        if conversation is None:
            self.title_label.set_full_text("SSsec")
            self.scope_header.hide()
            self.access_header.hide()
            self.findings_button.hide()
            return
        self.title_label.set_full_text(conversation.title)
        self.scope_header.show()
        self.access_header.show()
        self.findings_button.show()

        has_scope = bool(conversation.scope)
        scope_text = scope_summary(conversation.scope, conversation.authorized)
        metrics = self.scope_header.fontMetrics()
        display = (
            metrics.elidedText(f"目标 · {scope_text}", Qt.ElideRight, 210)
            if has_scope
            else "设置测试目标（可选）"
        )
        self.scope_header.setText(display)
        self.scope_header.setIcon(
            icon("target", COLORS["accent_text"] if has_scope else COLORS["muted"], 14)
        )
        set_dynamic_property(self.scope_header, "ok", "true" if has_scope else "false")
        set_dynamic_property(self.scope_header, "warn", "false")
        if has_scope:
            tooltip = "当前记录的目标：\n" + "\n".join(conversation.scope[:30])
            if len(conversation.scope) > 30:
                tooltip += f"\n… 共 {len(conversation.scope)} 项"
            tooltip += "\n\n点击编辑目标、范围策略与完全权限。"
        else:
            tooltip = "尚未设置目标。默认不限制目标，工具可正常执行。点击设置提示范围。"
        self.scope_header.setToolTip(tooltip)

        full_access = bool(conversation.full_permission)
        self.access_header.setText("完全权限 · 开" if full_access else "完全权限")
        self.access_header.setIcon(
            icon("bolt", COLORS["red"] if full_access else COLORS["muted"], 14)
        )
        set_dynamic_property(
            self.access_header, "danger", "true" if full_access else "false"
        )
        set_dynamic_property(self.access_header, "ok", "false")
        set_dynamic_property(self.access_header, "warn", "false")
        self.access_header.setToolTip(
            "本对话完全权限已开启：所有工具免确认，且不按目标范围拦截。点击关闭。"
            if full_access
            else "开启后本对话的所有工具调用都不再人工确认，并且不限制目标。"
        )
        count = len(conversation.findings)
        self.findings_button.setText(f"发现 {count}" if count else "发现")
        self.findings_button.setToolTip(
            f"查看本对话的 {count} 条测试发现" if count else "查看测试发现"
        )

    def _refresh_composer_state(self) -> None:
        if not self.current_conversation:
            self.composer.setEnabled(False)
            return
        self.composer.setEnabled(True)
        if self.active_run:
            if self.active_run.get("conversation_id") == self.current_id:
                self.composer.set_busy_elsewhere(False)
                self.composer.set_running(True)
                self.composer.set_awaiting_approval(bool(self.pending_approval))
            else:
                self.composer.set_running(False)
                self.composer.set_awaiting_approval(False)
                self.composer.set_busy_elsewhere(True)
        else:
            self.composer.set_running(False)
            self.composer.set_awaiting_approval(False)
            self.composer.set_busy_elsewhere(False)

    def _refresh_approval_bar(self) -> None:
        show = bool(
            self.pending_approval
            and self.active_run
            and self.active_run.get("conversation_id") == self.current_id
        )
        if show:
            self.approval_bar.set_payload(self.pending_approval or {})
            self.approval_host.show()
        else:
            self.approval_host.hide()
        self._refresh_composer_state()

    def _refresh_current_view(self, *, rebuild_chat: bool = False) -> None:
        conversation = self.current_conversation
        if conversation is None:
            return
        self._refresh_header()
        self._refresh_model_ui()
        if rebuild_chat:
            self.chat_view.set_conversation(
                conversation, demo_mode=self._provider().type == "demo"
            )
        self._refresh_approval_bar()
        self._refresh_sidebar()

    def _select_conversation(
        self, conversation_id: str, *, save_previous: bool = True
    ) -> None:
        if conversation_id == self.current_id and self.current_conversation is not None:
            return
        conversation = self.conversations.get(conversation_id)
        if conversation is None:
            return
        if save_previous and self.current_id:
            self._drafts[self.current_id] = self.composer.text()
            if self.current_conversation:
                self._save_conversation(self.current_conversation)
        self.current_id = conversation.id
        self.current_conversation = conversation
        draft = self._drafts.pop(conversation.id, "")
        self.chat_view.set_conversation(
            conversation, demo_mode=self._provider().type == "demo"
        )
        self.composer.set_text(draft)
        self._refresh_current_view()
        self.ui_state["last_conversation_id"] = conversation.id
        save_ui_state(self.data_dir, self.ui_state)
        self.composer.focus_input()

    # ================================================================ actions
    def new_conversation(self) -> None:
        if self._closing:
            return
        if self.current_id:
            self._drafts[self.current_id] = self.composer.text()
        conversation = Conversation.create()
        self.conversations[conversation.id] = conversation
        self._save_conversation(conversation)
        self._select_conversation(conversation.id)
        self.toast.show_message("新对话已创建。可设置目标提示，或在顶部开启完全权限。")
        self.composer.focus_input()

    def _use_prompt(self, text: str) -> None:
        self.composer.set_text(text)
        self.composer.focus_input()

    def rename_conversation(self, conversation_id: str | None = None) -> None:
        conversation_id = conversation_id or self.current_id
        conversation = self.conversations.get(conversation_id or "")
        if conversation is None:
            return
        title, ok = QInputDialog.getText(
            self, "重命名对话", "对话名称：", text=conversation.title
        )
        if not ok:
            return
        title = title.strip()
        if not title:
            self.toast.show_message("对话名称不能为空。")
            return
        conversation.title = title[:80]
        conversation.touch()
        self._save_conversation(conversation)
        if conversation.id == self.current_id:
            self._refresh_current_view()
        else:
            self._refresh_sidebar()
        self.toast.show_message("对话已重命名。")

    def delete_conversation(self, conversation_id: str | None = None) -> None:
        conversation_id = conversation_id or self.current_id
        conversation = self.conversations.get(conversation_id or "")
        if conversation is None:
            return
        if self.active_run and self.active_run.get("conversation_id") == conversation.id:
            self.toast.show_message("本轮仍在生成，请先停止后再删除对话。", 4500)
            return
        answer = QMessageBox.question(
            self,
            "删除对话",
            f"确定删除「{conversation.title}」吗？\n\n"
            "会话文件与对应审计日志会被删除，操作不可撤销。",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        self.conv_store.delete(conversation.id)
        self.conversations.pop(conversation.id, None)
        self._drafts.pop(conversation.id, None)
        if conversation.id == self.current_id:
            self.current_id = None
            self.current_conversation = None
            remaining = self._sorted_conversations()
            if remaining:
                self._select_conversation(remaining[0].id, save_previous=False)
            else:
                new_conversation = Conversation.create()
                self.conversations[new_conversation.id] = new_conversation
                self._save_conversation(new_conversation)
                self._select_conversation(new_conversation.id, save_previous=False)
        self._refresh_sidebar()
        self.toast.show_message("对话已删除。")

    def open_scope_dialog(self) -> None:
        if not self.current_conversation:
            return
        if self.active_run and self.active_run.get("conversation_id") == self.current_id:
            self.toast.show_message("本轮正在生成，请先停止后再修改目标与权限。", 4500)
            return
        dialog = ScopeDialog(self.current_conversation, self)
        if dialog.exec() != ScopeDialog.Accepted:
            return
        title, scope, authorized, full_permission = dialog.values
        conversation = self.current_conversation
        conversation.title = title
        conversation.scope = scope
        conversation.authorized = authorized
        conversation.full_permission = full_permission
        conversation.touch()
        self._save_conversation(conversation)
        self.chat_view.update_empty_state(demo_mode=self._provider().type == "demo")
        self._refresh_current_view()
        if full_permission:
            self.toast.show_message(
                "本对话已启用完全权限：工具免确认，且不按目标范围拦截。", 5000
            )
        elif scope:
            self.toast.show_message(f"测试目标已更新：{scope_summary(scope, True)}")
        else:
            self.toast.show_message("未设置目标：默认不限制目标，工具仍可执行。")

    def toggle_full_permission(self) -> None:
        conversation = self.current_conversation
        if conversation is None:
            return
        if self.active_run and self.active_run.get("conversation_id") == self.current_id:
            self.toast.show_message("本轮正在生成，请先停止后再切换完全权限。", 4500)
            return
        if conversation.full_permission:
            conversation.full_permission = False
        else:
            answer = QMessageBox.warning(
                self,
                "开启完全权限？",
                "完全权限会跳过所有工具确认条，并且不再按目标范围拦截网络访问。\n\n"
                "仅在你完全信任当前模型、运行环境与测试目标时开启。确定开启吗？",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if answer != QMessageBox.Yes:
                return
            conversation.full_permission = True
        conversation.touch()
        self._save_conversation(conversation)
        self.chat_view.update_empty_state(demo_mode=self._provider().type == "demo")
        self._refresh_current_view()
        self.toast.show_message(
            "本对话已开启完全权限。" if conversation.full_permission else "已关闭完全权限。",
            3600,
        )

    def toggle_theme(self) -> None:
        new_theme = "dark" if current_theme() == "light" else "light"
        self._apply_theme(new_theme)
        self.settings.theme = new_theme
        try:
            self.settings_store.save(self.settings)
        except Exception:
            logger.exception("保存主题设置失败")
        self.toast.show_message(
            "已切换到深色主题。" if new_theme == "dark" else "已切换到浅色主题。", 2600
        )

    def _apply_theme(self, theme_name: str) -> None:
        """应用主题并重建主界面，保证所有内联颜色同步更新。"""
        app = QApplication.instance()
        if app is not None:
            apply_theme(app, theme_name)
        self._rebuild_ui()

    def _rebuild_ui(self) -> None:
        draft = self.composer.text() if hasattr(self, "composer") else ""
        if hasattr(self, "toast"):
            self.toast.hide()
            self.toast.deleteLater()
        old_central = self.takeCentralWidget()
        if old_central is not None:
            old_central.deleteLater()
        self._build_ui()
        self._connect_signals()
        if self.current_conversation is not None:
            self.chat_view.set_conversation(
                self.current_conversation,
                demo_mode=self._provider().type == "demo",
            )
            self.composer.set_text(draft)
            self._refresh_current_view()
        self._apply_window_chrome()
        self.setWindowIcon(app_icon())

    def open_findings(self) -> None:
        if not self.current_conversation:
            return
        dialog = FindingsDialog(self.current_conversation, self)
        dialog.exec()

    def open_settings(self) -> None:
        previous_theme = self.settings.theme
        dialog = SettingsDialog(self.settings, self.data_dir, self)
        if dialog.exec() != SettingsDialog.Accepted or dialog.result_settings is None:
            return
        self.settings = dialog.result_settings
        try:
            self.settings_store.save(self.settings)
        except Exception:
            logger.exception("保存设置失败")
            QMessageBox.warning(
                self,
                "保存失败",
                "设置已应用到当前会话，但写入本地配置文件失败，请检查数据目录权限。",
            )
        if self.settings.theme != previous_theme:
            self._apply_theme(self.settings.theme)
            self.toast.show_message("设置已保存，主题已切换。")
            return
        self._refresh_model_ui()
        self._refresh_header()
        self.chat_view.update_empty_state(demo_mode=self._provider().type == "demo")
        self._refresh_composer_state()
        self._refresh_sidebar()
        self.toast.show_message("设置已保存。")

    def _open_more_menu(self) -> None:
        menu = QMenu(self)
        rename = QAction(icon("edit", COLORS["text_soft"], 15), "重命名对话", menu)
        rename.triggered.connect(self.rename_conversation)
        scope = QAction(icon("target", COLORS["text_soft"], 15), "目标范围与权限", menu)
        scope.triggered.connect(self.open_scope_dialog)
        access = QAction(
            icon("bolt", COLORS["text_soft"], 15),
            "关闭完全权限" if self.current_conversation and self.current_conversation.full_permission else "开启完全权限",
            menu,
        )
        access.triggered.connect(self.toggle_full_permission)
        findings = QAction(icon("file", COLORS["text_soft"], 15), "查看测试发现", menu)
        findings.triggered.connect(self.open_findings)
        settings = QAction(icon("settings", COLORS["text_soft"], 15), "设置", menu)
        settings.triggered.connect(self.open_settings)
        theme = QAction(
            icon("sun" if is_dark() else "moon", COLORS["text_soft"], 15),
            "切换到浅色主题" if is_dark() else "切换到深色主题",
            menu,
        )
        theme.triggered.connect(self.toggle_theme)
        data = QAction(icon("folder", COLORS["text_soft"], 15), "打开数据目录", menu)
        data.triggered.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.data_dir)))
        )
        delete = QAction(icon("trash", COLORS["red"], 15), "删除对话", menu)
        delete.triggered.connect(self.delete_conversation)
        menu.addAction(rename)
        menu.addAction(scope)
        menu.addAction(access)
        menu.addAction(findings)
        menu.addSeparator()
        menu.addAction(settings)
        menu.addAction(theme)
        menu.addAction(data)
        menu.addSeparator()
        menu.addAction(delete)
        menu.exec(self.more_button.mapToGlobal(self.more_button.rect().bottomLeft()))

    # ================================================================ agent
    def _send_message(self, text: str) -> None:
        if not text.strip() or not self.current_conversation:
            return
        if self.active_run is not None:
            self.toast.show_message(
                "另一个对话仍在生成，请等待完成或先停止它。", 4000
            )
            return
        provider = self._provider()
        try:
            validate_provider(provider)
        except Exception as exc:
            message = str(exc) if isinstance(exc, ModelConfigError) else friendly_error(exc, provider)
            QMessageBox.warning(
                self,
                "模型服务尚未就绪",
                message + "\n\n请在设置中配置当前模型服务。",
            )
            self.open_settings()
            return

        conversation = self.current_conversation
        history = conversation_to_messages(
            conversation,
            max_messages=self.settings.safety.max_history_messages,
        )
        user_message = conversation.add_user(text.strip())
        model_label = _model_label(provider)
        assistant = conversation.add_assistant(model_label)
        self._save_conversation(conversation)
        self.chat_view.set_conversation(
            conversation, demo_mode=provider.type == "demo"
        )
        self.composer.clear()
        self._refresh_header()
        self._refresh_sidebar()

        if conversation.full_permission:
            self.toast.show_message(
                "完全权限已开启：本轮工具调用将直接执行，不再请求确认。", 5000
            )
        elif not conversation.scope:
            self.toast.show_message(
                "未设置目标提示：默认不限制目标，工具仍可执行；可在设置中开启严格拦截。",
                5000,
            )

        active = {
            "conversation_id": conversation.id,
            "assistant_id": assistant["id"],
            "user_id": user_message["id"],
            "model_label": model_label,
        }
        self.active_run = active
        self.pending_approval = None
        self._pending_conversation_id = None
        worker = AgentWorker(
            conversation_id=conversation.id,
            history=history,
            user_input=text.strip(),
            scope=list(conversation.scope),
            authorized=conversation.authorized,
            findings=conversation.findings,
            settings=self.settings,
            provider=provider,
            data_dir=self.data_dir,
            workspace=self.conv_store.workspace(conversation.id),
            full_permission=conversation.full_permission,
            parent=self,
        )
        self._active_worker = worker
        self._retired_workers.append(worker)
        worker.text_delta.connect(self._on_text_delta)
        worker.reasoning_delta.connect(self._on_reasoning_delta)
        worker.commander_delta.connect(self._on_commander_delta)
        worker.tool_started.connect(self._on_tool_started)
        worker.tool_finished.connect(self._on_tool_finished)
        worker.approval_required.connect(self._on_approval_required)
        worker.finding_saved.connect(self._on_finding_saved)
        worker.run_finished.connect(self._on_run_finished)
        worker.finished.connect(lambda: self._on_worker_thread_finished(worker))
        self._refresh_composer_state()
        self._refresh_sidebar()
        self._refresh_approval_bar()
        worker.start()
        self._dirty = True

    def _run_conversation(self) -> Conversation | None:
        if not self.active_run:
            return None
        return self.conversations.get(str(self.active_run.get("conversation_id")))

    def _assistant_message(self) -> dict[str, Any] | None:
        conversation = self._run_conversation()
        if not conversation or not self.active_run:
            return None
        message = conversation.message_by_id(str(self.active_run.get("assistant_id")))
        return message if isinstance(message, dict) else None

    def _on_text_delta(self, text: str) -> None:
        if not text:
            return
        message = self._assistant_message()
        if message is None:
            return
        append_text(message, text, "text")
        self._dirty = True
        if self.current_id == self.active_run.get("conversation_id"):
            self.chat_view.append_delta(str(message["id"]), "text", text)

    def _on_reasoning_delta(self, text: str) -> None:
        if not text:
            return
        message = self._assistant_message()
        if message is None:
            return
        append_text(message, text, "reasoning")
        self._dirty = True

    def _on_commander_delta(self, text: str) -> None:
        if not text:
            return
        message = self._assistant_message()
        if message is None:
            return
        # 指挥官决策不是模型的 reasoning_content，单独标记，避免跨轮误传回模型。
        append_text(message, text, "reasoning", commander=True)
        self._dirty = True

    def _on_tool_started(self, payload: dict) -> None:
        message = self._assistant_message()
        if message is None:
            return
        tool = ensure_tool(
            message,
            str(payload.get("id") or ""),
            str(payload.get("name") or "unknown_tool"),
            payload.get("args") or {},
            bool(payload.get("requires_approval")),
            "running",
        )
        tool["status"] = "running"
        tool["started_at"] = now_iso()
        tool["requires_approval"] = bool(payload.get("requires_approval"))
        self._dirty = True
        if self.current_id == self.active_run.get("conversation_id"):
            self.chat_view.refresh_message(message)
        self._save_conversation(self._run_conversation())

    def _on_tool_finished(self, payload: dict) -> None:
        message = self._assistant_message()
        if message is None:
            return
        tool = ensure_tool(
            message,
            str(payload.get("id") or ""),
            str(payload.get("name") or "unknown_tool"),
            None,
            False,
            "running",
        )
        tool["status"] = str(payload.get("status") or "error")
        tool["result"] = str(payload.get("result") or "")
        tool["duration_ms"] = payload.get("duration_ms")
        tool["finished_at"] = now_iso()
        self._dirty = True
        if self.current_id == self.active_run.get("conversation_id"):
            self.chat_view.refresh_message(message)
        self._save_conversation(self._run_conversation())

    def _on_approval_required(self, payload: dict) -> None:
        message = self._assistant_message()
        if message is None:
            return
        for call in payload.get("calls") or []:
            tool = ensure_tool(
                message,
                str(call.get("id") or ""),
                str(call.get("name") or "unknown_tool"),
                call.get("args") or {},
                bool(call.get("requires_approval")),
                "awaiting_approval",
            )
            tool["status"] = "awaiting_approval"
            tool["requires_approval"] = bool(call.get("requires_approval"))
        message["status"] = "awaiting_approval"
        self.pending_approval = payload
        self._pending_conversation_id = self.active_run.get("conversation_id")
        self._dirty = True
        self._save_conversation(self._run_conversation())
        if self.current_id != self._pending_conversation_id:
            self._select_conversation(str(self._pending_conversation_id))
        else:
            self.chat_view.refresh_message(message)
        self._refresh_approval_bar()
        self._refresh_composer_state()

    def _resolve_approval(self, approved: bool) -> None:
        if not self.active_run or not self._active_worker or self.pending_approval is None:
            return
        self.pending_approval = None
        message = self._assistant_message()
        if message is not None:
            message["status"] = "streaming"
        self.approval_host.hide()
        self._refresh_composer_state()
        self._save_conversation(self._run_conversation())
        self._active_worker.provide_approval(approved, "operator decision")
        self.toast.show_message(
            "已批准本轮工具调用，正在执行。" if approved else "已拒绝本轮工具调用。",
            2600,
        )

    def _on_finding_saved(self, finding: dict) -> None:
        conversation = self._run_conversation()
        if not conversation:
            return
        add_finding(conversation, finding)
        self._dirty = True
        self._save_conversation(conversation)
        if conversation.id == self.current_id:
            self._refresh_header()
        self.toast.show_message(f"已记录测试发现：{finding.get('title', '未命名')}", 3600)

    def _on_run_finished(self, status: str, error: str) -> None:
        if not self.active_run:
            return
        conversation = self._run_conversation()
        assistant = self._assistant_message()
        run_conversation_id = str(self.active_run.get("conversation_id") or "")
        self.pending_approval = None
        self._pending_conversation_id = None
        self.approval_host.hide()
        if conversation is not None and assistant is not None:
            if status == "complete":
                has_text = bool(assistant_text(assistant).strip())
                has_tools = any(
                    segment.get("type") == "tool"
                    for segment in assistant.get("segments") or []
                )
                if not has_text and not has_tools:
                    assistant["status"] = "error"
                    assistant["error"] = (
                        "模型没有返回可显示的内容。请检查模型是否支持当前协议，"
                        "或尝试重新发送。"
                    )
                else:
                    assistant["status"] = "complete"
                    assistant["error"] = None
            elif status == "cancelled":
                assistant["status"] = "cancelled"
                for segment in assistant.get("segments") or []:
                    if segment.get("type") == "tool":
                        tool = segment.get("tool") or {}
                        if tool.get("status") in ("pending", "awaiting_approval", "running"):
                            tool["status"] = "cancelled"
                            tool["finished_at"] = now_iso()
            else:
                assistant["status"] = "error"
                assistant["error"] = error or "Agent 运行失败。"
                for segment in assistant.get("segments") or []:
                    if segment.get("type") == "tool":
                        tool = segment.get("tool") or {}
                        if tool.get("status") in ("pending", "awaiting_approval", "running"):
                            tool["status"] = "cancelled"
                            tool["finished_at"] = now_iso()
            conversation.touch()
            self._save_conversation(conversation)
            title = conversation.title
        else:
            title = "对话"

        self.active_run = None
        self._active_worker = None
        self._dirty = False
        if self.current_id == run_conversation_id and self.current_conversation:
            self.chat_view.set_conversation(
                self.current_conversation, demo_mode=self._provider().type == "demo"
            )
            self._refresh_current_view()
            self.composer.focus_input()
        else:
            self._refresh_sidebar()
            if status == "complete":
                self.toast.show_message(f"「{title}」本轮已完成。", 3000)
            elif status == "error":
                self.toast.show_message(
                    f"「{title}」运行失败：{(error or '未知错误')[:100]}", 5000
                )
            elif status == "cancelled":
                self.toast.show_message(f"「{title}」已停止生成。", 3000)
        self._refresh_approval_bar()

    def _on_worker_thread_finished(self, worker: AgentWorker) -> None:
        try:
            self._retired_workers.remove(worker)
        except ValueError:
            pass
        if self._active_worker is worker:
            self._active_worker = None
        worker.deleteLater()

    def _stop_active_run(self) -> None:
        worker = self._active_worker
        if worker is None or self.active_run is None:
            return
        worker.cancel()
        self.toast.show_message("正在停止本轮生成…", 2500)

    # ================================================================ lifecycle
    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._closing:
            event.accept()
            return
        if self._active_worker is not None and self.active_run is not None:
            answer = QMessageBox.question(
                self,
                "退出 SSsec",
                "当前还有对话正在生成。退出会停止生成并保留已收到的内容，确定退出吗？",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if answer != QMessageBox.Yes:
                event.ignore()
                return
        self._closing = True
        if self._active_worker is not None:
            self._stop_for_close()
        if self.current_id:
            self._drafts[self.current_id] = self.composer.text()
        if self.current_conversation:
            self._save_conversation(self.current_conversation)
        self.ui_state["last_conversation_id"] = self.current_id or ""
        try:
            geometry = bytes(self.saveGeometry().toHex()).decode("ascii")
            self.ui_state["window_geometry"] = geometry
        except Exception:
            pass
        save_ui_state(self.data_dir, self.ui_state)
        event.accept()

    def _stop_for_close(self) -> None:
        worker = self._active_worker
        if worker is None:
            return
        worker.cancel()
        worker.wait(6000)
        conversation = self._run_conversation()
        assistant = self._assistant_message()
        if conversation and assistant:
            if assistant.get("status") in ("streaming", "awaiting_approval"):
                assistant["status"] = "cancelled"
                for segment in assistant.get("segments") or []:
                    if segment.get("type") == "tool":
                        tool = segment.get("tool") or {}
                        if tool.get("status") in ("pending", "awaiting_approval", "running"):
                            tool["status"] = "cancelled"
                            tool["finished_at"] = now_iso()
            self._save_conversation(conversation)
        self.active_run = None
        self._active_worker = None
