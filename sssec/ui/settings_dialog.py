"""模型服务、Agent 安全策略与本地数据设置。"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sssec.agent.llm import friendly_error, test_provider, validate_provider
from sssec.agent.llm import ModelConfigError
from sssec.skills import SkillStore
from sssec.ui.skills_page import SkillsPage
from sssec.config import (
    APP_VERSION,
    APPROVAL_MODES,
    PROVIDER_TYPES,
    SCOPE_MODES,
    THEMES,
    AppSettings,
    ProviderConfig,
    SafetySettings,
    encryption_label,
)
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS, THEMES as UI_THEMES
from sssec.ui.widgets import (
    BrandMark,
    ClickFrame,
    PageHeader,
    divider,
    set_dynamic_property,
)


class ThemeCard(ClickFrame):
    """外观页中的主题选择卡片，带一组配色预览色块。"""

    def __init__(self, theme_name: str, title: str, description: str):
        super().__init__()
        self.theme_name = theme_name
        self.setObjectName("ThemeCard")
        self.setMinimumHeight(84)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(8)
        title_label = QLabel(title)
        title_label.setObjectName("ThemeCardTitle")
        title_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        top.addWidget(title_label)
        top.addStretch(1)
        self.check = QLabel()
        self.check.setPixmap(icon("check", COLORS["accent"], 14).pixmap(14, 14))
        self.check.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        top.addWidget(self.check)
        layout.addLayout(top)

        swatches = QHBoxLayout()
        swatches.setSpacing(4)
        palette = UI_THEMES[theme_name]
        for key in ("accent", "accent_2", "cyan", "violet", "green", "amber", "red"):
            swatch = QLabel()
            swatch.setFixedSize(18, 10)
            swatch.setStyleSheet(
                f"background: {palette[key]}; border: 1px solid {palette['border_strong']};"
                "border-radius: 2px;"
            )
            swatch.setAttribute(Qt.WA_TransparentForMouseEvents, True)
            swatches.addWidget(swatch)
        swatches.addStretch(1)
        layout.addLayout(swatches)

        desc_label = QLabel(description)
        desc_label.setObjectName("ThemeCardDesc")
        desc_label.setWordWrap(True)
        desc_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        layout.addWidget(desc_label)

    def set_selected(self, selected: bool) -> None:
        set_dynamic_property(self, "selected", "true" if selected else "false")
        self.check.setVisible(selected)


class ProviderTestThread(QThread):
    done = Signal(bool, str)

    def __init__(self, provider: ProviderConfig, settings: AppSettings):
        super().__init__()
        self.provider = provider.clone()
        self.settings = settings.clone()

    def run(self) -> None:
        try:
            result = asyncio.run(
                test_provider(self.provider, self.settings.safety)
            )
            self.done.emit(bool(result.get("ok")), str(result.get("message")))
        except Exception as exc:
            self.done.emit(False, friendly_error(exc, self.provider))


def _field_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("FieldLabel")
    return label


def _help_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("HelpText")
    label.setWordWrap(True)
    return label


class SettingsDialog(QDialog):
    def __init__(
        self,
        settings: AppSettings,
        data_dir: Path,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("SettingsDialog")
        self.setWindowTitle("SSsec 设置")
        self.setModal(True)
        self.resize(1000, 720)
        self.setMinimumSize(900, 640)
        self.settings = settings.clone()
        self.data_dir = data_dir
        self.result_settings: AppSettings | None = None
        self._theme = self.settings.theme
        self._theme_cards: dict[str, ThemeCard] = {}
        self._editing_provider_id: str | None = None
        self._loading_provider = False
        self._test_thread: ProviderTestThread | None = None
        self._test_running = False
        self._last_nav_row = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        nav = QWidget()
        nav.setObjectName("SettingsNav")
        nav.setFixedWidth(200)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(12, 16, 12, 12)
        nav_layout.setSpacing(10)
        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(4, 0, 0, 0)
        brand_row.setSpacing(8)
        brand_row.addWidget(BrandMark(24))
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        title = QLabel("设置")
        title.setObjectName("SettingsBrandTitle")
        subtitle = QLabel("SSSEC WORKSPACE")
        subtitle.setObjectName("BrandSub")
        brand_text.addWidget(title)
        brand_text.addWidget(subtitle)
        brand_row.addLayout(brand_text, 1)
        nav_layout.addLayout(brand_row)
        nav_layout.addSpacing(8)
        nav_caption = QLabel("偏好")
        nav_caption.setObjectName("SectionCaption")
        nav_caption.setContentsMargins(6, 0, 0, 0)
        nav_layout.addWidget(nav_caption)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("SettingsNav")
        self.nav_list.setFocusPolicy(Qt.NoFocus)
        self._nav_icons = ["spark", "shield", "bolt", "sun", "folder"]
        for text, icon_name in zip(
            ["模型服务", "Agent 与安全", "技能库", "外观", "数据与关于"],
            self._nav_icons,
        ):
            item = QListWidgetItem(icon(icon_name, COLORS["muted"], 15), text)
            item.setSizeHint(QSize(0, 32))
            self.nav_list.addItem(item)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        nav_layout.addWidget(self.nav_list)
        nav_layout.addStretch(1)
        version = QLabel(f"SSsec v{APP_VERSION}\nLangGraph · PySide6")
        version.setObjectName("Faint")
        version.setContentsMargins(6, 0, 0, 0)
        nav_layout.addWidget(version)
        body.addWidget(nav)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_models_page())
        self.stack.addWidget(self._wrap_scroll(self._build_safety_page()))
        self.stack.addWidget(self._build_skills_page())
        self.stack.addWidget(self._wrap_scroll(self._build_appearance_page()))
        self.stack.addWidget(self._wrap_scroll(self._build_data_page()))
        body.addWidget(self.stack, 1)
        root.addLayout(body, 1)

        footer = QFrame()
        footer.setObjectName("SettingsFooter")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(18, 10, 18, 10)
        footer_layout.setSpacing(10)
        self.status_label = QLabel("")
        self.status_label.setObjectName("HelpText")
        self.status_label.setWordWrap(True)
        footer_layout.addWidget(self.status_label, 1)
        cancel = QPushButton("取消")
        cancel.setObjectName("Secondary")
        cancel.clicked.connect(self.reject)
        save = QPushButton("保存设置")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        footer_layout.addWidget(cancel)
        footer_layout.addWidget(save)
        root.addWidget(footer)

        self.nav_list.setCurrentRow(0)
        self._load_provider(self.settings.active_provider_id)

    # ================================================================ pages
    def _wrap_scroll(self, page: QWidget) -> QScrollArea:
        """把设置页放进滚动区，避免内容把对话框撑到超出小屏幕。"""
        scroll = QScrollArea()
        scroll.setObjectName("SettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(page)
        return scroll

    def _build_models_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(6)
        layout.addWidget(
            PageHeader(
                "spark",
                "模型服务",
                "支持 OpenAI 兼容接口（DeepSeek、Qwen、OpenRouter、Ollama、vLLM 等）"
                "以及 Anthropic Claude。",
                tone="accent",
            )
        )
        layout.addSpacing(12)

        content = QHBoxLayout()
        content.setSpacing(16)

        left = QWidget()
        left.setFixedWidth(232)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(7)
        caption = _field_label("已配置的服务")
        left_layout.addWidget(caption)
        self.provider_list = QListWidget()
        self.provider_list.setObjectName("ProviderList")
        self.provider_list.setMinimumHeight(250)
        self.provider_list.currentItemChanged.connect(self._on_provider_selected)
        left_layout.addWidget(self.provider_list, 1)
        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        add_button = QPushButton("添加服务")
        add_button.setObjectName("Secondary")
        add_button.setIcon(icon("plus", COLORS["text_soft"], 14))
        add_menu = QMenu(add_button)
        action_openai = add_menu.addAction("OpenAI 兼容服务")
        action_anthropic = add_menu.addAction("Anthropic 服务")
        action_openai.triggered.connect(lambda: self._add_provider("openai"))
        action_anthropic.triggered.connect(lambda: self._add_provider("anthropic"))
        add_button.setMenu(add_menu)
        buttons.addWidget(add_button, 1)
        self.delete_button = QToolButton()
        self.delete_button.setIcon(icon("trash", COLORS["red"], 16))
        self.delete_button.setToolTip("删除选中的服务")
        self.delete_button.setFixedSize(34, 34)
        self.delete_button.clicked.connect(self._delete_provider)
        buttons.addWidget(self.delete_button)
        left_layout.addLayout(buttons)
        left_layout.addWidget(
            _help_label("保存后，可勾选“设为当前模型”切换新对话使用的模型。")
        )
        content.addWidget(left)

        scroll = QScrollArea()
        scroll.setObjectName("SettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        editor_host = QWidget()
        editor_layout = QVBoxLayout(editor_host)
        editor_layout.setContentsMargins(4, 0, 8, 12)
        editor_layout.setSpacing(11)
        self.editor_title = QLabel("编辑模型服务")
        self.editor_title.setObjectName("SettingsEditorTitle")
        editor_layout.addWidget(self.editor_title)
        self.active_checkbox = QCheckBox("保存后设为当前模型")
        editor_layout.addWidget(self.active_checkbox)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("例如：生产 DeepSeek、内网 Ollama")
        self.type_combo = QComboBox()
        for key, label in PROVIDER_TYPES.items():
            self.type_combo.addItem(label, key)
        self.type_combo.currentIndexChanged.connect(self._update_type_ui)
        self.model_input = QLineEdit()
        self.model_input.setPlaceholderText("例如：deepseek-chat、qwen3:8b")
        self.base_input = QLineEdit()
        self.base_input.setPlaceholderText("例如：https://api.deepseek.com/v1")
        self.api_input = QLineEdit()
        self.api_input.setEchoMode(QLineEdit.Password)
        self.api_input.setPlaceholderText("sk-…")
        self.show_key_button = QToolButton()
        self.show_key_button.setText("显示")
        self.show_key_button.setCursor(Qt.PointingHandCursor)
        self.show_key_button.setCheckable(True)
        self.show_key_button.toggled.connect(self._toggle_key_visibility)
        api_row = QWidget()
        api_layout = QHBoxLayout(api_row)
        api_layout.setContentsMargins(0, 0, 0, 0)
        api_layout.setSpacing(5)
        api_layout.addWidget(self.api_input, 1)
        api_layout.addWidget(self.show_key_button)
        self.temperature_input = QDoubleSpinBox()
        self.temperature_input.setRange(0.0, 2.0)
        self.temperature_input.setSingleStep(0.1)
        self.temperature_input.setDecimals(1)
        self.max_tokens_input = QSpinBox()
        self.max_tokens_input.setRange(0, 200000)
        self.max_tokens_input.setSingleStep(256)
        self.max_tokens_input.setSpecialValueText("默认")
        for editor in (
            self.name_input,
            self.model_input,
            self.base_input,
            self.api_input,
        ):
            editor.textEdited.connect(self._mark_provider_edited)
        self.type_combo.activated.connect(lambda _index: self._mark_provider_edited())
        self.temperature_input.valueChanged.connect(
            lambda _value: self._mark_provider_edited()
        )
        self.max_tokens_input.valueChanged.connect(
            lambda _value: self._mark_provider_edited()
        )

        self._field_widgets: dict[str, QWidget] = {}
        editor_layout.addWidget(
            self._form_field("服务名称", self.name_input, "用于在界面中识别这个模型服务。")
        )
        editor_layout.addWidget(self._form_field("接口类型", self.type_combo))
        self._field_widgets["model"] = self._form_field(
            "模型 ID", self.model_input, "必须与服务商文档中的模型标识一致。"
        )
        editor_layout.addWidget(self._field_widgets["model"])
        self._base_field = self._form_field(
            "Base URL",
            self.base_input,
            "OpenAI 兼容接口填写到 /v1；Ollama 可填 http://127.0.0.1:11434/v1。",
        )
        self._field_widgets["base"] = self._base_field
        editor_layout.addWidget(self._base_field)
        self._key_field = self._form_field(
            "API Key", api_row, "使用 Windows DPAPI 加密后保存，仅当前用户可解密。"
        )
        self._field_widgets["key"] = self._key_field
        editor_layout.addWidget(self._key_field)
        editor_layout.addWidget(
            self._form_field(
                "温度",
                self.temperature_input,
                "越低越稳定；安全测试建议 0.1–0.3。",
            )
        )
        editor_layout.addWidget(
            self._form_field(
                "最大输出 tokens",
                self.max_tokens_input,
                "0 表示使用服务端默认值。",
            )
        )

        divider_line = divider()
        editor_layout.addWidget(divider_line)
        test_row = QHBoxLayout()
        self.test_button = QPushButton("测试连接")
        self.test_button.setObjectName("Secondary")
        self.test_button.clicked.connect(self._test_connection)
        test_row.addWidget(self.test_button)
        self.test_result = QLabel("")
        self.test_result.setObjectName("HelpText")
        self.test_result.setWordWrap(True)
        test_row.addWidget(self.test_result, 1)
        editor_layout.addLayout(test_row)
        editor_layout.addStretch(1)
        scroll.setWidget(editor_host)
        content.addWidget(scroll, 1)
        layout.addLayout(content, 1)
        return page

    def _build_safety_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(6)
        layout.addWidget(
            PageHeader(
                "shield",
                "Agent 与安全",
                "这些设置会应用到之后启动的每一轮 Agent 运行。",
                tone="green",
            )
        )
        layout.addSpacing(16)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(8)
        approval_label = _field_label("工具审批策略")
        self.approval_combo = QComboBox()
        for key, label in APPROVAL_MODES.items():
            self.approval_combo.addItem(label, key)
        card_layout.addWidget(approval_label)
        card_layout.addWidget(self.approval_combo)
        card_layout.addWidget(
            _help_label(
                "默认为“宽松”：只读工具与普通命令直接执行，仅明显高风险命令"
                "（破坏性、持久化、关机/格式化、管道执行远程脚本等）请求确认。"
                "“仅敏感工具”保留更保守的命令与写请求审批；"
                "“关闭审批”或“完全权限”会让所有工具直接执行。"
            )
        )
        card_layout.addWidget(divider())
        scope_label = _field_label("目标范围策略")
        self.scope_combo = QComboBox()
        for key, label in SCOPE_MODES.items():
            self.scope_combo.addItem(label, key)
        card_layout.addWidget(scope_label)
        card_layout.addWidget(self.scope_combo)
        card_layout.addWidget(
            _help_label(
                "默认“不限制目标”：范围仅作为提示与审计记录，不会阻断任何工具。"
                "可切换为“仅提示”或“严格拦截”；严格模式会拒绝范围外的网络目标。"
            )
        )
        card_layout.addWidget(divider())
        self.enable_shell = QCheckBox("启用命令执行工具（run_command）")
        card_layout.addWidget(self.enable_shell)
        card_layout.addWidget(
            _help_label(
                "命令在会话专属工作目录中运行，并继承当前用户权限。默认宽松模式"
                "只对高风险命令请求确认；保守模式逐条审批；完全权限下直接执行。"
            )
        )
        layout.addWidget(card)
        layout.addSpacing(12)

        limits = QFrame()
        limits.setObjectName("Card")
        limits_layout = QVBoxLayout(limits)
        limits_layout.setContentsMargins(14, 12, 14, 12)
        limits_layout.setSpacing(10)
        caption = QLabel("运行限制")
        caption.setObjectName("FieldLabel")
        limits_layout.addWidget(caption)

        self.rounds_input = QSpinBox()
        self.rounds_input.setRange(0, 500)
        self.rounds_input.setSpecialValueText("不限制")
        self.rounds_input.setToolTip(
            "软预算：只用于提示词中的收敛建议，不会因为轮次到点而中止阶段。0 = 不给提示。"
        )
        self.hard_stop_input = QSpinBox()
        self.hard_stop_input.setRange(0, 5000)
        self.hard_stop_input.setSpecialValueText("关闭")
        self.hard_stop_input.setSuffix(" 轮")
        self.hard_stop_input.setToolTip(
            "安全熔断：模型持续空转时的兜底上限。正常任务不应触达，0 = 关闭。"
        )
        self.command_timeout_input = QSpinBox()
        self.command_timeout_input.setRange(5, 600)
        self.command_timeout_input.setSuffix(" 秒")
        self.network_timeout_input = QSpinBox()
        self.network_timeout_input.setRange(3, 120)
        self.network_timeout_input.setSuffix(" 秒")
        self.history_input = QSpinBox()
        self.history_input.setRange(4, 400)
        self.history_input.setSuffix(" 条")
        rows = QHBoxLayout()
        rows.setSpacing(14)
        for label, widget in [
            ("软轮次提示", self.rounds_input),
            ("安全熔断", self.hard_stop_input),
            ("命令超时", self.command_timeout_input),
            ("网络超时", self.network_timeout_input),
            ("历史消息上限", self.history_input),
        ]:
            column = QVBoxLayout()
            column.setSpacing(4)
            column.addWidget(_field_label(label))
            column.addWidget(widget)
            rows.addLayout(column)
        limits_layout.addLayout(rows)

        self.auto_continue = QCheckBox("目标未达成时自动续跑（同一轮对话内继续）")
        self.auto_continue.setChecked(True)
        limits_layout.addWidget(self.auto_continue)
        auto_row = QHBoxLayout()
        auto_row.setSpacing(14)
        self.max_auto_continue_input = QSpinBox()
        self.max_auto_continue_input.setRange(0, 50)
        self.max_auto_continue_input.setSpecialValueText("不限制")
        self.max_auto_continue_input.setSuffix(" 次")
        self.brake_input = QSpinBox()
        self.brake_input.setRange(0, 1440)
        self.brake_input.setSpecialValueText("关闭")
        self.brake_input.setSuffix(" 分钟")
        for label, widget in [
            ("自动续跑上限", self.max_auto_continue_input),
            ("运行熔断", self.brake_input),
        ]:
            column = QVBoxLayout()
            column.setSpacing(4)
            column.addWidget(_field_label(label))
            column.addWidget(widget)
            auto_row.addLayout(column)
        auto_row.addStretch(1)
        limits_layout.addLayout(auto_row)

        self.skills_enabled = QCheckBox("启用技能库（skill_list / skill_load / skill_unload）")
        self.skills_enabled.setChecked(True)
        limits_layout.addWidget(self.skills_enabled)
        skill_row = QHBoxLayout()
        skill_row.setSpacing(14)
        self.skill_max_input = QSpinBox()
        self.skill_max_input.setRange(1, 3)
        self.skill_max_input.setSuffix(" 张")
        for label, widget in [("每阶段技能上限", self.skill_max_input)]:
            column = QVBoxLayout()
            column.setSpacing(4)
            column.addWidget(_field_label(label))
            column.addWidget(widget)
            skill_row.addLayout(column)
        skill_row.addStretch(1)
        limits_layout.addLayout(skill_row)
        limits_layout.addWidget(
            _help_label(
                "v0.2.1 起轮次不再作为收尾理由：阶段可以连续调用工具直到目标达成；"
                "软轮次只影响提示，安全熔断与运行熔断是模型或任务失控时的兜底。"
                "技能库按需加载，每阶段有上限，可用 skill_unload 换卡。"
            )
        )
        layout.addWidget(limits)
        layout.addSpacing(12)

        boundary = QFrame()
        boundary.setObjectName("Card")
        boundary_layout = QHBoxLayout(boundary)
        boundary_layout.setContentsMargins(14, 12, 14, 12)
        boundary_layout.setSpacing(10)
        shield = QLabel()
        shield.setPixmap(icon("bolt", COLORS["amber"], 20).pixmap(20, 20))
        boundary_layout.addWidget(shield, 0, Qt.AlignTop)
        boundary_text = QLabel(
            "“完全权限”是按对话开启的：在对话顶部或“目标范围”弹窗中勾选后，"
            "该对话的所有工具调用都不再询问，也不按目标范围拦截。它适合受控的本地测试，"
            "请勿在无法承担后果的环境中开启。"
        )
        boundary_text.setObjectName("HelpText")
        boundary_text.setWordWrap(True)
        boundary_layout.addWidget(boundary_text, 1)
        layout.addWidget(boundary)
        layout.addStretch(1)
        return page

    def _build_skills_page(self) -> QWidget:
        self.skills_page = SkillsPage(SkillStore(self.data_dir))
        return self.skills_page

    def _build_appearance_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(6)
        layout.addWidget(
            PageHeader(
                "sun",
                "外观",
                "整套界面遵循 Linear 设计语言：近中性底色、1px 细边框、靛蓝强调色"
                "与紧凑排版；也可以随时在左下角快速切换。",
                tone="violet",
            )
        )
        layout.addSpacing(16)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(8)
        caption = QLabel("界面主题")
        caption.setObjectName("FieldLabel")
        card_layout.addWidget(caption)
        for name, title_text, description in (
            (
                "light",
                "浅色 · Linear Light（默认）",
                "白色画布、浅灰侧栏与靛蓝强调色，适合白天与长时间阅读。",
            ),
            (
                "dark",
                "深色 · Linear Dark",
                "近黑画布、微弱抬升的表面与低饱和文字，适合夜间与安全测试工作台。",
            ),
        ):
            theme_card = ThemeCard(name, title_text, description)
            theme_card.clicked.connect(
                lambda _checked=False, value=name: self._select_theme(value)
            )
            card_layout.addWidget(theme_card)
            self._theme_cards[name] = theme_card
        card_layout.addWidget(
            _help_label(
                "主题在点击“保存设置”后立即应用，主窗口会自动重建，正在编辑的输入草稿会保留。"
            )
        )
        layout.addWidget(card)
        layout.addSpacing(12)

        preview = QFrame()
        preview.setObjectName("Card")
        preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(14, 12, 14, 12)
        preview_layout.setSpacing(8)
        preview_caption = QLabel("设计说明")
        preview_caption.setObjectName("FieldLabel")
        preview_layout.addWidget(preview_caption)
        preview_layout.addWidget(
            _help_label(
                "两套主题共用同一套语义色板（画布、表面、边框、强调色、状态色）与同一套间距、"
                "圆角规则；切换时图标、Markdown、工具卡片、审批条与设置页会同步更新。"
            )
        )
        layout.addWidget(preview)
        layout.addStretch(1)
        return page

    def _select_theme(self, name: str) -> None:
        if name not in self._theme_cards:
            return
        self._theme = name
        for key, card in self._theme_cards.items():
            card.set_selected(key == name)

    def _sync_theme_fields(self) -> None:
        self._select_theme(self.settings.theme if self.settings.theme in UI_THEMES else "light")

    def _build_data_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(6)
        layout.addWidget(
            PageHeader(
                "folder",
                "数据与关于",
                "所有会话、审计日志和密钥都保存在本机，不会上传到 SSsec 服务器。",
                tone="blue",
            )
        )
        layout.addSpacing(16)

        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(8)
        caption = QLabel("本地数据目录")
        caption.setObjectName("FieldLabel")
        card_layout.addWidget(caption)
        path_label = QLabel(str(self.data_dir))
        path_label.setObjectName("PathBox")
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.path_label = path_label
        card_layout.addWidget(path_label)
        button_row = QHBoxLayout()
        open_button = QPushButton("打开数据目录")
        open_button.setObjectName("Secondary")
        open_button.setIcon(icon("folder", COLORS["text_soft"], 15))
        open_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.data_dir)))
        )
        audit_button = QPushButton("打开审计日志")
        audit_button.setObjectName("Secondary")
        audit_button.clicked.connect(
            lambda: QDesktopServices.openUrl(
                QUrl.fromLocalFile(str(self.data_dir / "audit"))
            )
        )
        button_row.addWidget(open_button)
        button_row.addWidget(audit_button)
        button_row.addStretch(1)
        card_layout.addLayout(button_row)
        card_layout.addWidget(
            _help_label(
                "conversations/ 保存会话，audit/ 保存按会话隔离的 JSONL 审计日志，"
                "workspaces/ 是命令工具的工作目录。"
            )
        )
        layout.addWidget(card)
        layout.addSpacing(12)

        security = QFrame()
        security.setObjectName("Card")
        security_layout = QVBoxLayout(security)
        security_layout.setContentsMargins(14, 12, 14, 12)
        security_layout.setSpacing(7)
        security_caption = QLabel("本地密钥保护")
        security_caption.setObjectName("FieldLabel")
        security_layout.addWidget(security_caption)
        encryption = QLabel(encryption_label())
        encryption.setStyleSheet(f"color: {COLORS['accent']}; font-size: 9.5pt;")
        security_layout.addWidget(encryption)
        security_layout.addWidget(
            _help_label(
                "API Key 只写入本地 config.json，并使用当前 Windows 用户的 DPAPI 加密。"
                "请勿在不可信设备上使用生产密钥。"
            )
        )
        layout.addWidget(security)
        layout.addSpacing(12)

        about = QFrame()
        about.setObjectName("Card")
        about_layout = QHBoxLayout(about)
        about_layout.setContentsMargins(14, 12, 14, 12)
        about_layout.setSpacing(12)
        about_layout.addWidget(BrandMark(40), 0, Qt.AlignTop)
        about_text = QVBoxLayout()
        about_text.setSpacing(4)
        about_title = QLabel(f"SSsec v{APP_VERSION}")
        about_title.setObjectName("SettingsEditorTitle")
        about_text.addWidget(about_title)
        desc = QLabel(
            "本地优先的安全测试 Agent Harness，Linear 风格浅色 / 深色双主题。"
            "多 Agent 运行时：LangGraph 指挥官 + 阶段子图；桌面界面：PySide6。"
        )
        desc.setObjectName("HelpText")
        desc.setWordWrap(True)
        about_text.addWidget(desc)
        disclaimer = QLabel(
            "SSsec 只应用于已获得明确授权的安全测试。使用者对测试活动及授权合规负责。"
        )
        disclaimer.setStyleSheet(f"color: {COLORS['amber']}; font-size: 8.5pt;")
        disclaimer.setWordWrap(True)
        about_text.addWidget(disclaimer)
        about_layout.addLayout(about_text, 1)
        layout.addWidget(about)
        layout.addStretch(1)
        return page

    # ================================================================ helpers
    def _form_field(self, label: str, widget: QWidget, hint: str | None = None) -> QWidget:
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        layout.addWidget(_field_label(label))
        layout.addWidget(widget)
        if hint:
            layout.addWidget(_help_label(hint))
        return host

    def _on_nav_changed(self, row: int) -> None:
        if self._last_nav_row == 0 and row != 0:
            self._stash_current_provider()
        self._last_nav_row = row
        for index, icon_name in enumerate(self._nav_icons):
            item = self.nav_list.item(index)
            if item is not None:
                item.setIcon(
                    icon(
                        icon_name,
                        COLORS["accent_text"] if index == row else COLORS["muted"],
                        15,
                    )
                )
        self.stack.setCurrentIndex(row)

    def _load_provider(self, provider_id: str) -> None:
        provider = self.settings.provider_by_id(provider_id)
        if provider is None:
            return
        self._loading_provider = True
        self._editing_provider_id = provider.id
        self._stash_loading = True
        self.name_input.setText(provider.name)
        index = self.type_combo.findData(provider.type)
        self.type_combo.setCurrentIndex(index if index >= 0 else 0)
        self.model_input.setText(provider.model)
        self.base_input.setText(provider.base_url)
        self.api_input.setText(provider.api_key)
        self.temperature_input.setValue(float(provider.temperature))
        self.max_tokens_input.setValue(int(provider.max_tokens))
        self.active_checkbox.setChecked(provider.id == self.settings.active_provider_id)
        self.test_result.setText("")
        self._update_type_ui()
        self._loading_provider = False

    def _refresh_provider_list(self, select_id: str | None = None) -> None:
        self.provider_list.blockSignals(True)
        self.provider_list.clear()
        target_row = 0
        for index, provider in enumerate(self.settings.providers):
            is_active = provider.id == self.settings.active_provider_id
            label = provider.name
            detail = f"{provider.type_label} · {provider.model or '未填写模型'}"
            item = QListWidgetItem(
                icon(
                    "spark" if provider.type != "anthropic" else "lock",
                    COLORS["accent_text"] if is_active else COLORS["muted"],
                    15,
                ),
                label,
            )
            if is_active:
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            item.setData(Qt.UserRole, provider.id)
            item.setToolTip(
                f"{provider.name}\n{detail}" + ("\n当前模型" if is_active else "")
            )
            item.setSizeHint(QSize(0, 34))
            self.provider_list.addItem(item)
            if provider.id == (select_id or self._editing_provider_id):
                target_row = index
        self.provider_list.blockSignals(False)
        if self.provider_list.count():
            self.provider_list.setCurrentRow(min(target_row, self.provider_list.count() - 1))

    def _on_provider_selected(
        self, current: QListWidgetItem | None, previous: QListWidgetItem | None
    ) -> None:
        if current is None or self._loading_provider:
            return
        if previous is not None and self._editing_provider_id:
            self._stash_current_provider()
        provider_id = current.data(Qt.UserRole)
        provider = self.settings.provider_by_id(provider_id)
        if provider:
            self._load_provider(provider.id)

    def _provider_from_fields(self, provider_id: str) -> ProviderConfig:
        provider_type = str(self.type_combo.currentData() or "openai")
        return ProviderConfig(
            id=provider_id,
            name=self.name_input.text().strip() or "未命名服务",
            type=provider_type,
            model=self.model_input.text().strip(),
            base_url=self.base_input.text().strip(),
            api_key=self.api_input.text().strip(),
            temperature=float(self.temperature_input.value()),
            max_tokens=int(self.max_tokens_input.value()),
        )

    def _stash_current_provider(self) -> None:
        if self._loading_provider or not self._editing_provider_id:
            return
        if not hasattr(self, "name_input"):
            return
        provider = self._provider_from_fields(self._editing_provider_id)
        for index, existing in enumerate(self.settings.providers):
            if existing.id == provider.id:
                self.settings.providers[index] = provider
                break

    def _update_type_ui(self) -> None:
        provider_type = str(self.type_combo.currentData() or "openai")
        is_demo = provider_type == "demo"
        self._field_widgets["base"].setVisible(not is_demo)
        self._field_widgets["key"].setVisible(not is_demo)
        self._field_widgets["model"].setVisible(not is_demo)
        if provider_type == "anthropic":
            self.base_input.setPlaceholderText("https://api.anthropic.com（可留空使用默认）")
            if not self.base_input.text():
                self.base_input.setText("https://api.anthropic.com")
        elif provider_type == "openai":
            self.base_input.setPlaceholderText("例如：https://api.deepseek.com/v1")
        self.test_result.setText("")

    def _toggle_key_visibility(self, visible: bool) -> None:
        self.api_input.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
        self.show_key_button.setText("隐藏" if visible else "显示")

    def _mark_provider_edited(self, *_args) -> None:
        if self._loading_provider:
            return
        if not self.active_checkbox.isChecked() and self._editing_provider_id:
            self.active_checkbox.setChecked(True)
            self.status_label.setText(
                "已将该服务标记为当前模型；点击“保存设置”后生效。"
            )
            self.status_label.setStyleSheet(
                f"color: {COLORS['accent']}; font-size: 8.5pt;"
            )

    def _add_provider(self, provider_type: str) -> None:
        self._stash_current_provider()
        is_anthropic = provider_type == "anthropic"
        provider = ProviderConfig(
            id=uuid.uuid4().hex,
            name="新服务",
            type=provider_type,
            model="claude-sonnet-4-5" if is_anthropic else "",
            base_url="https://api.anthropic.com" if is_anthropic else "",
            temperature=0.2,
        )
        self.settings.providers.append(provider)
        self._refresh_provider_list(provider.id)
        self._load_provider(provider.id)
        self.name_input.setFocus()
        self.name_input.selectAll()
        self.status_label.setText("已添加服务，填写完成后点击保存设置。")

    def _delete_provider(self) -> None:
        if not self._editing_provider_id:
            return
        if len(self.settings.providers) <= 1:
            self._show_status("至少需要保留一个模型服务。", error=True)
            return
        provider = self.settings.provider_by_id(self._editing_provider_id)
        if provider is None:
            return
        answer = QMessageBox.question(
            self,
            "删除模型服务",
            f"确定删除「{provider.name}」吗？此操作只影响本地配置。",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        self.settings.providers = [
            item for item in self.settings.providers if item.id != provider.id
        ]
        if self.settings.active_provider_id == provider.id:
            self.settings.active_provider_id = self.settings.providers[0].id
        self._editing_provider_id = self.settings.providers[0].id
        self._refresh_provider_list(self._editing_provider_id)
        self._load_provider(self._editing_provider_id)
        self._show_status("服务已删除。")

    def _test_connection(self) -> None:
        if self._test_running:
            return
        self._stash_current_provider()
        provider = self._provider_from_fields(self._editing_provider_id or "")
        try:
            validate_provider(provider)
        except ModelConfigError as exc:
            self._set_test_result(False, str(exc))
            return
        except Exception as exc:
            self._set_test_result(False, friendly_error(exc, provider))
            return
        self._test_running = True
        self.test_button.setEnabled(False)
        self.test_button.setText("测试中…")
        self.test_result.setStyleSheet(f"color: {COLORS['muted']};")
        self.test_result.setText("正在向模型服务发送最小请求…")
        thread = ProviderTestThread(provider, self.settings)
        self._test_thread = thread
        thread.done.connect(self._on_test_done)
        thread.finished.connect(self._on_test_thread_finished)
        thread.start()

    def _on_test_done(self, ok: bool, message: str) -> None:
        self._test_running = False
        self.test_button.setEnabled(True)
        self.test_button.setText("测试连接")
        self._set_test_result(ok, message)

    def _on_test_thread_finished(self) -> None:
        thread = self._test_thread
        self._test_thread = None
        if thread is not None:
            thread.deleteLater()

    def _set_test_result(self, ok: bool, message: str) -> None:
        color = COLORS["green"] if ok else COLORS["red"]
        self.test_result.setStyleSheet(f"color: {color}; font-size: 8.5pt;")
        self.test_result.setText(message[:500])

    def _show_status(self, message: str, error: bool = False) -> None:
        self.status_label.setStyleSheet(
            f"color: {COLORS['red'] if error else COLORS['green']}; font-size: 8.5pt;"
        )
        self.status_label.setText(message)

    # ================================================================ save
    def _save(self) -> None:
        self._stash_current_provider()
        selected = self.settings.provider_by_id(self._editing_provider_id or "")
        if selected is None:
            self._show_status("请选择一个模型服务。", error=True)
            return
        if self.active_checkbox.isChecked():
            self.settings.active_provider_id = selected.id
        elif self.settings.active_provider_id == selected.id:
            # 当前服务不允许被取消为“无当前模型”
            self.settings.active_provider_id = selected.id
        active_provider = self.settings.provider_by_id(self.settings.active_provider_id)
        if active_provider is None:
            self._show_status("当前模型服务不存在，请重新选择。", error=True)
            self.nav_list.setCurrentRow(0)
            return
        try:
            validate_provider(active_provider)
        except ModelConfigError as exc:
            self._show_status(str(exc), error=True)
            self.nav_list.setCurrentRow(0)
            return
        except Exception as exc:
            self._show_status(friendly_error(exc, active_provider), error=True)
            self.nav_list.setCurrentRow(0)
            return
        safety = SafetySettings(
            approval_mode=str(self.approval_combo.currentData() or "sensitive"),
            scope_mode=str(self.scope_combo.currentData() or "off"),
            enable_shell=self.enable_shell.isChecked(),
            max_tool_rounds=self.rounds_input.value(),
            hard_stop_rounds=self.hard_stop_input.value(),
            auto_continue=self.auto_continue.isChecked(),
            max_auto_continue=self.max_auto_continue_input.value(),
            brake_minutes=self.brake_input.value(),
            skills_enabled=self.skills_enabled.isChecked(),
            skill_max_loaded=self.skill_max_input.value(),
            command_timeout=self.command_timeout_input.value(),
            network_timeout=self.network_timeout_input.value(),
            max_history_messages=self.history_input.value(),
        )
        if safety.approval_mode == "full":
            answer = QMessageBox.warning(
                self,
                "启用全局完全权限？",
                "完全权限会让所有工具直接执行：不弹确认条，也不按目标范围拦截。"
                "这适合隔离环境中的受控测试，但会显著放大误操作或提示注入的后果。"
                "确定启用吗？",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if answer != QMessageBox.Yes:
                return
        elif safety.approval_mode == "off":
            answer = QMessageBox.warning(
                self,
                "关闭工具审批？",
                "关闭审批后，Agent 执行命令不再询问，但仍会遵循目标范围策略。"
                "这会让误操作或提示注入的后果放大。确定关闭吗？",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if answer != QMessageBox.Yes:
                return
        self.settings.safety = safety
        self.settings.theme = self._theme if self._theme in UI_THEMES else "light"
        self.result_settings = self.settings
        self.accept()

    def _sync_safety_fields(self) -> None:
        safety = self.settings.safety
        index = self.approval_combo.findData(safety.approval_mode)
        self.approval_combo.setCurrentIndex(index if index >= 0 else 0)
        scope_index = self.scope_combo.findData(safety.scope_mode)
        self.scope_combo.setCurrentIndex(scope_index if scope_index >= 0 else 0)
        self.enable_shell.setChecked(safety.enable_shell)
        self.rounds_input.setValue(safety.max_tool_rounds)
        self.hard_stop_input.setValue(safety.hard_stop_rounds)
        self.auto_continue.setChecked(safety.auto_continue)
        self.max_auto_continue_input.setValue(safety.max_auto_continue)
        self.skills_enabled.setChecked(safety.skills_enabled)
        self.skill_max_input.setValue(safety.skill_max_loaded)
        self.brake_input.setValue(safety.brake_minutes)
        self.command_timeout_input.setValue(safety.command_timeout)
        self.network_timeout_input.setValue(safety.network_timeout)
        self.history_input.setValue(safety.max_history_messages)

    # ================================================================ lifecycle
    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_safety_fields()
        self._sync_theme_fields()
        self._refresh_provider_list(self._editing_provider_id or self.settings.active_provider_id)
        self._load_provider(self._editing_provider_id or self.settings.active_provider_id)

    def closeEvent(self, event) -> None:  # noqa: N802
        if self._test_running:
            QMessageBox.information(
                self, "请稍候", "连接测试尚未结束，请等待结果返回后再关闭设置。"
            )
            event.ignore()
            return
        super().closeEvent(event)

    def reject(self) -> None:
        if self._test_running:
            QMessageBox.information(
                self, "请稍候", "连接测试尚未结束，请等待结果返回后再关闭设置。"
            )
            return
        super().reject()
