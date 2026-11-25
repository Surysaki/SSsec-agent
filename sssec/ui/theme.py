"""Linear 风格的设计系统：配色、排版、间距与全局 QSS。

设计取向参考 Linear（linear.app）的界面语言：

* **低饱和近中性底色**：大面积使用 ``#08090a``（深色）/ ``#ffffff``（浅色），
  用 1px 低对比边框划分层级，不依赖阴影与渐变；
* **单一强调色**：靛蓝 ``#5e6ad2`` 只用于主操作、选中态与焦点环；
* **紧凑排版**：13px 正文、12px 辅助、11px 元信息、10px 大写分组标题，
  中文回退到微软雅黑 UI；
* **统一圆角**：控件 6px、卡片 8px、浮层 10px，行高 28–32px。

``THEMES`` 保存两套主题的语义色板，``COLORS`` 是指向当前主题的实时字典。
界面代码统一读取 ``COLORS["..."]``；切换主题时 ``apply_theme()`` 原地更新
该字典并重建 QSS，因此各模块无需重新导入即可拿到新配色。
"""

from __future__ import annotations

from pathlib import Path
from string import Template

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

_ASSETS = Path(__file__).resolve().parent.parent / "assets"

THEME_LABELS = {
    "light": "浅色（Linear Light）",
    "dark": "深色（Linear Dark）",
}
DEFAULT_THEME = "light"

# --------------------------------------------------------------------- tokens
# 圆角（px），供 setStyleSheet 之外的内联绘制与 QFrame 复用。
RADIUS = {"xs": 4, "sm": 6, "md": 8, "lg": 10, "xl": 14}
# 垂直节奏（px）：行高、控件高度、段落间距。
SPACE = {"row": 30, "control": 32, "section": 24, "page": 28}
# 字号（pt）：1pt ≈ 1.333px @96dpi。
FONT_SIZES = {
    "micro": 7.5,
    "meta": 8.0,
    "small": 8.5,
    "body_sm": 9.0,
    "body": 9.5,
    "input": 10.5,
    "title": 12.5,
    "display": 17.0,
}
UI_FONT_FAMILIES = (
    # 沿用 DeepSeek Harness 的界面字体栈；Windows 上解析为 Segoe UI + 微软雅黑。
    "-apple-system",
    "BlinkMacSystemFont",
    "Segoe UI",
    "PingFang SC",
    "Hiragino Sans GB",
    "Microsoft YaHei",
    "Helvetica Neue",
    "Helvetica",
    "Arial",
)
MONO_FONT_FAMILIES = (
    # DeepSeek Harness 的代码字体栈；Windows 上解析为 Consolas。
    "SF Mono",
    "JetBrains Mono",
    "Fira Code",
    "Consolas",
    "Liberation Mono",
    "Menlo",
    "Courier",
)
UI_FONT_STACK_QSS = (
    '"Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", '
    '"Helvetica Neue", Helvetica, Arial, sans-serif'
)
MONO_FONT_STACK_QSS = (
    '"SF Mono", "JetBrains Mono", "Fira Code", Consolas, '
    '"Liberation Mono", Menlo, "Microsoft YaHei", monospace'
)

# 深色是 Linear 的标志性形态：近黑画布 + 轻微抬升的侧栏 + 靛蓝强调色。
LIGHT = {
    "bg": "#f3f4f9",
    "sidebar": "#f8f9fd",
    "pane": "#ffffff",
    "pane_tint": "#f6f7ff",
    "surface": "#ffffff",
    "surface_2": "#f1f3f9",
    "surface_3": "#e7eaf3",
    "card": "#ffffff",
    "border": "#e1e4ee",
    "border_soft": "#e9ecf4",
    "border_strong": "#cdd2e2",
    "text": "#242838",
    "heading": "#121527",
    "text_soft": "#4a4f66",
    "muted": "#6b7188",
    "faint": "#9aa0b4",
    "icon": "#6b7188",
    "accent": "#5e6ad2",
    "accent_2": "#8b6cf5",
    "accent_hover": "#4f5bc7",
    "accent_soft": "#eef0ff",
    "accent_soft_hover": "#e4e7ff",
    "accent_border": "#d8dcff",
    "accent_border_hover": "#bfc6fa",
    "on_accent": "#ffffff",
    "accent_text": "#4a55c0",
    "blue": "#2f7fd6",
    "blue_soft": "#eef5ff",
    "blue_border": "#c9dcf7",
    "cyan": "#0e8fa8",
    "cyan_soft": "#eaf9fc",
    "cyan_border": "#bfe9f1",
    "violet": "#7c5ce6",
    "violet_soft": "#f3efff",
    "violet_border": "#e0d6ff",
    "amber": "#a86a12",
    "amber_soft": "#fdf7ea",
    "amber_border": "#efdcb0",
    "green": "#1f8a57",
    "green_soft": "#edf9f2",
    "green_border": "#bfe6d1",
    "red": "#d64550",
    "red_soft": "#fdf2f3",
    "red_border": "#f4ccd0",
    "input_bg": "#ffffff",
    "input_border": "#dfe2ec",
    "input_border_hover": "#c9cede",
    "input_focus": "#5e6ad2",
    "disabled_bg": "#f4f5fa",
    "disabled_text": "#a9aebe",
    "selection_bg": "#dbe0ff",
    "selection_text": "#1b2050",
    "scroll": "#d5d9e5",
    "scroll_hover": "#bcc2d2",
    "menu_bg": "#ffffff",
    "menu_hover": "#f1f3f9",
    "tooltip_bg": "#232838",
    "tooltip_text": "#f7f8ff",
    "user_bubble": "#f1f3ff",
    "user_border": "#dfe3ff",
    "user_text": "#262a45",
    "avatar_bg": "#eef0fa",
    "avatar_text": "#5e6680",
    "avatar_border": "#dde2f0",
    "code_bg": "#f7f8fc",
    "code_border": "#e5e8f2",
    "code_text": "#33405c",
    "code_inline_bg": "#eef1fa",
    "code_inline_text": "#4a55c0",
    "approval_bg": "#fdf8ec",
    "approval_border": "#efdcb0",
    "approval_title": "#8a5a12",
    "approval_text": "#7a6540",
    "error_bg": "#fdf3f4",
    "error_border": "#f3ccd1",
    "error_text": "#b23a45",
    "toast_bg": "#ffffff",
    "toast_border": "#d8dce8",
    "convo_selected_bg": "#edf0fb",
    "convo_selected_border": "#dfe4f7",
    "convo_title_selected": "#141726",
    "nav_bg": "#f8f9fd",
    "nav_selected_bg": "#eef1fb",
    "hover": "#f1f3f9",
    "kbd_bg": "#f5f6fb",
    "kbd_border": "#e2e5ef",
    "kbd_text": "#7a8098",
    "segment_bg": "#f6f7fc",
    "highlight": "#5e6ad2",
}

DARK = {
    "bg": "#08090f",
    "sidebar": "#0d0f17",
    "pane": "#08090f",
    "pane_tint": "#0a0c18",
    "surface": "#11141d",
    "surface_2": "#1a1d28",
    "surface_3": "#232735",
    "card": "#0f121b",
    "border": "#262a38",
    "border_soft": "#1b1e2a",
    "border_strong": "#363c4f",
    "text": "#e7e9f2",
    "heading": "#f6f8ff",
    "text_soft": "#b8bdcf",
    "muted": "#8a90a5",
    "faint": "#5f657b",
    "icon": "#8a90a5",
    "accent": "#6672e8",
    "accent_2": "#a184ff",
    "accent_hover": "#7b86f5",
    "accent_soft": "#161a30",
    "accent_soft_hover": "#1c2140",
    "accent_border": "#2b3158",
    "accent_border_hover": "#414a86",
    "on_accent": "#ffffff",
    "accent_text": "#b3bbff",
    "blue": "#59a8ff",
    "blue_soft": "#0f1c2e",
    "blue_border": "#1f3a5c",
    "cyan": "#4fd1e6",
    "cyan_soft": "#0a1c22",
    "cyan_border": "#174049",
    "violet": "#b18cff",
    "violet_soft": "#1b1530",
    "violet_border": "#362a5c",
    "amber": "#f2c15c",
    "amber_soft": "#1e1810",
    "amber_border": "#4a3a1c",
    "green": "#4fd39a",
    "green_soft": "#0d1c16",
    "green_border": "#1d3f30",
    "red": "#ff6b7a",
    "red_soft": "#241216",
    "red_border": "#4f232a",
    "input_bg": "#0e1018",
    "input_border": "#272b3a",
    "input_border_hover": "#353a4c",
    "input_focus": "#6672e8",
    "disabled_bg": "#0b0d13",
    "disabled_text": "#555b70",
    "selection_bg": "#303a86",
    "selection_text": "#ffffff",
    "scroll": "#2a2e3d",
    "scroll_hover": "#3c4256",
    "menu_bg": "#141722",
    "menu_hover": "#1f2331",
    "tooltip_bg": "#1c2030",
    "tooltip_text": "#e7e9f2",
    "user_bubble": "#151a2e",
    "user_border": "#262d4a",
    "user_text": "#e7eaff",
    "avatar_bg": "#1a1e2e",
    "avatar_text": "#a3a9c0",
    "avatar_border": "#2b3046",
    "code_bg": "#0b0d15",
    "code_border": "#202434",
    "code_text": "#c7d1e6",
    "code_inline_bg": "#1a1d2b",
    "code_inline_text": "#b3bbff",
    "approval_bg": "#1b160c",
    "approval_border": "#47381a",
    "approval_title": "#ffd27a",
    "approval_text": "#cbb994",
    "error_bg": "#211116",
    "error_border": "#51262e",
    "error_text": "#ff9aa4",
    "toast_bg": "#1a1e2b",
    "toast_border": "#303648",
    "convo_selected_bg": "#171b2b",
    "convo_selected_border": "#262c44",
    "convo_title_selected": "#ffffff",
    "nav_bg": "#0b0d14",
    "nav_selected_bg": "#191d2c",
    "hover": "#1a1d28",
    "kbd_bg": "#1e2230",
    "kbd_border": "#303548",
    "kbd_text": "#9ba1b5",
    "segment_bg": "#0e1119",
    "highlight": "#6672e8",
}

THEMES = {"light": LIGHT, "dark": DARK}

# 当前主题的实时颜色表。模块通过 ``from ...theme import COLORS`` 持有同一个
# dict 引用，切换主题时原地更新即可让所有组件读取到新值。
COLORS: dict[str, str] = dict(LIGHT)
_current_theme = DEFAULT_THEME


APP_QSS_TEMPLATE = """
* {
    outline: none;
}
QWidget {
    color: $text;
    font-family: $font_ui;
    font-size: 9.5pt;
}
QMainWindow, QWidget#Root {
    background: $bg;
}
QWidget#Sidebar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 $sidebar, stop:1 $bg);
    border-right: 1px solid $border_soft;
}
QWidget#MainPane {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $pane, stop:0.55 $pane, stop:1 $pane_tint);
}
QWidget#ChatCanvas, QScrollArea#ChatScroll, QScrollArea#SettingsScroll {
    background: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QFrame#ChatHeader {
    background: transparent;
    border-bottom: 1px solid $border_soft;
}
QFrame#ComposerArea {
    background: transparent;
    border-top: 1px solid $border_soft;
}
QFrame#ComposerCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 10px;
}
QFrame#ComposerCard[focused="true"] {
    border: 1px solid $accent;
}
QFrame#TopDivider, QFrame#Divider {
    background: $border_soft;
    border: none;
    min-height: 1px;
    max-height: 1px;
}
QWidget#VerticalRule, QFrame#VerticalRule {
    background: $border;
    border: none;
    min-width: 1px;
    max-width: 1px;
}
QLabel {
    background: transparent;
}
QLabel#BrandName {
    color: $heading;
    font-size: 12pt;
    font-weight: 600;
}
QLabel#BrandSub {
    color: $faint;
    font-size: 7pt;
    font-weight: 600;
}
QLabel#SectionCaption {
    color: $faint;
    font-size: 8pt;
    font-weight: 600;
}
QLabel#SectionCount {
    color: $faint;
    font-size: 8pt;
}
QLabel#Muted {
    color: $muted;
}
QLabel#Faint {
    color: $faint;
    font-size: 8.5pt;
}
QLabel#Mono {
    font-family: $font_mono;
    font-size: 8.5pt;
}
QLabel#PageTitle {
    color: $heading;
    font-size: 12.5pt;
    font-weight: 600;
}
QLabel#PageSub {
    color: $muted;
    font-size: 9pt;
}
QLabel#EmptyHeading {
    color: $heading;
    font-size: 17pt;
    font-weight: 600;
}
QLabel#EmptyDisclaimer {
    color: $faint;
    font-size: 7.8pt;
}
QLabel#CardTitle {
    color: $text;
    font-size: 9pt;
    font-weight: 600;
}
QLabel#SuggestionTitle {
    color: $text;
    font-size: 9pt;
    font-weight: 500;
}
QLabel#SuggestionSub {
    color: $muted;
    font-size: 8.3pt;
}
QLabel#KbdHint {
    color: $kbd_text;
    background: $kbd_bg;
    border: 1px solid $kbd_border;
    border-radius: 4px;
    padding: 1px 5px;
    font-size: 7.5pt;
}
QLabel#MetaDot {
    color: $faint;
    font-size: 8pt;
}
QPushButton {
    border: none;
    background: transparent;
    color: $text_soft;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 9pt;
}
QPushButton:hover {
    background: $surface_2;
}
QPushButton:pressed {
    background: $surface_3;
}
QPushButton:disabled {
    color: $disabled_text;
    background: transparent;
}
QPushButton#NewChat {
    background: $surface;
    border: 1px solid $border;
    color: $text;
    padding: 0px 10px;
    font-size: 9pt;
    font-weight: 500;
    text-align: left;
}
QPushButton#NewChat:hover {
    background: $surface_2;
    border-color: $border_strong;
}
QPushButton#Primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $accent, stop:1 $accent_2);
    color: $on_accent;
    padding: 7px 14px;
    border-radius: 6px;
    font-size: 9pt;
    font-weight: 600;
}
QPushButton#Primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $accent_hover, stop:1 $accent_2);
}
QPushButton#Primary:pressed {
    background: $accent_hover;
}
QPushButton#Primary:disabled {
    background: $surface_2;
    color: $faint;
}
QPushButton#Secondary {
    background: $surface;
    border: 1px solid $border;
    color: $text_soft;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 9pt;
    font-weight: 500;
}
QPushButton#Secondary:hover {
    background: $surface_2;
    border-color: $border_strong;
    color: $text;
}
QPushButton#Secondary:disabled {
    color: $disabled_text;
    background: $disabled_bg;
    border-color: $border_soft;
}
QPushButton#Danger {
    background: $red_soft;
    border: 1px solid $red_border;
    color: $red;
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 9pt;
    font-weight: 500;
}
QPushButton#Danger:hover {
    border-color: $red;
}
QPushButton#Suggestion {
    background: $surface;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 8px 10px;
    text-align: left;
    color: $text_soft;
    font-size: 9pt;
}
QPushButton#Suggestion:hover {
    background: $surface_2;
    border-color: $border_strong;
}
QPushButton#SendButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $accent, stop:1 $accent_2);
    border-radius: 8px;
    padding: 0px;
}
QPushButton#SendButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $accent_hover, stop:1 $accent_2);
}
QPushButton#SendButton:disabled {
    background: $surface_2;
    border: 1px solid $border;
}
QPushButton#StopButton {
    background: $red_soft;
    border: 1px solid $red_border;
    border-radius: 8px;
    padding: 0px;
}
QPushButton#StopButton:hover {
    border-color: $red;
}
QPushButton#Chip {
    background: transparent;
    border: 1px solid $border;
    border-radius: 6px;
    padding: 3px 8px;
    color: $muted;
    font-size: 8.5pt;
}
QPushButton#Chip:hover {
    background: $surface_2;
    border-color: $border_strong;
    color: $text;
}
QPushButton#Chip[ok="true"] {
    color: $accent_text;
    border-color: $accent_border;
    background: $accent_soft;
}
QPushButton#Chip[ok="true"]:hover {
    border-color: $accent_border_hover;
}
QPushButton#Chip[warn="true"] {
    color: $amber;
    border-color: $amber_border;
    background: $amber_soft;
}
QPushButton#Chip[danger="true"] {
    color: $red;
    border-color: $red_border;
    background: $red_soft;
}
QPushButton#Chip[danger="true"]:hover {
    border-color: $red;
}
QPushButton#FooterLink {
    color: $muted;
    font-size: 8.5pt;
    padding: 4px 6px;
}
QPushButton#FooterLink:hover {
    color: $text;
    background: $surface_2;
}
QToolButton {
    background: transparent;
    border: none;
    border-radius: 6px;
    padding: 4px;
}
QToolButton:hover {
    background: $surface_2;
}
QToolButton#IconButton {
    padding: 5px;
}
QToolButton#Ghost {
    padding: 4px;
    border: 1px solid transparent;
}
QToolButton#Ghost:hover {
    border-color: $accent_border;
    background: $accent_soft;
}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: $input_bg;
    border: 1px solid $input_border;
    border-radius: 6px;
    padding: 6px 9px;
    color: $text;
    font-size: 9pt;
    selection-background-color: $selection_bg;
    selection-color: $selection_text;
}
QLineEdit:hover, QPlainTextEdit:hover, QTextEdit:hover, QComboBox:hover {
    border-color: $input_border_hover;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid $input_focus;
}
QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled {
    color: $disabled_text;
    background: $disabled_bg;
}
QComboBox {
    padding-right: 24px;
}
QComboBox::drop-down {
    border: none;
    width: 22px;
}
QComboBox::down-arrow {
    image: url("__ASSET_CHEVRON_DOWN__");
    width: 10px;
    height: 10px;
}
QComboBox QAbstractItemView {
    background: $menu_bg;
    border: 1px solid $border;
    border-radius: 6px;
    selection-background-color: $surface_2;
    selection-color: $text;
    padding: 4px;
    outline: none;
}
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    width: 17px;
    border: none;
    background: transparent;
    margin-right: 2px;
}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
    image: url("__ASSET_CHEVRON_UP__");
    width: 8px;
    height: 8px;
}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
    image: url("__ASSET_CHEVRON_DOWN__");
    width: 8px;
    height: 8px;
}
QCheckBox {
    color: $text_soft;
    spacing: 8px;
    font-size: 9pt;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border: 1px solid $input_border;
    border-radius: 4px;
    background: $input_bg;
}
QCheckBox::indicator:hover {
    border-color: $accent;
}
QCheckBox::indicator:checked {
    background: $accent;
    border-color: $accent;
    image: url("__ASSET_CHECK__");
}
QPlainTextEdit#ChatInput {
    background: transparent;
    border: none;
    padding: 2px;
    color: $text;
    font-size: 10.5pt;
}
QPlainTextEdit#SearchInput {
    background: $surface_2;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 9pt;
}
QLineEdit#SearchInput {
    background: $surface_2;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 9pt;
}
QLineEdit#SearchInput:hover {
    border-color: $border;
}
QLineEdit#SearchInput:focus {
    background: $input_bg;
    border-color: $accent;
}
QTextBrowser {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: $scroll;
    min-height: 24px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: $scroll_hover;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}
QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: $scroll;
    min-width: 24px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal:hover {
    background: $scroll_hover;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QFrame#ConversationRow {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
}
QFrame#ConversationRow:hover {
    background: $surface_2;
}
QFrame#ConversationRow[selected="true"] {
    background: $convo_selected_bg;
    border: 1px solid $convo_selected_border;
}
QLabel#ConvoTitle {
    color: $text_soft;
    font-size: 9pt;
    font-weight: 500;
}
QLabel#ConvoTitle[selected="true"] {
    color: $convo_title_selected;
    font-weight: 600;
}
QLabel#ConvoPreview {
    color: $muted;
    font-size: 8.2pt;
}
QLabel#ConvoTime {
    color: $faint;
    font-size: 7.5pt;
}
QFrame#UserBubble {
    background: $user_bubble;
    border: 1px solid $user_border;
    border-radius: 8px;
}
QLabel#UserText {
    color: $user_text;
    font-size: 9.8pt;
}
QLabel#UserAvatar {
    background: $avatar_bg;
    color: $avatar_text;
    border: 1px solid $avatar_border;
    border-radius: 11px;
    font-size: 8pt;
}
QFrame#ToolCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 8px;
}
QFrame#ToolCard:hover {
    border-color: $border_strong;
}
QFrame#ToolCard[status="awaiting"] {
    background: $amber_soft;
    border: 1px solid $amber_border;
}
QFrame#ToolCard[status="running"] {
    border: 1px solid $blue_border;
}
QFrame#ToolCard[status="error"], QFrame#ToolCard[status="denied"] {
    background: $red_soft;
    border: 1px solid $red_border;
}
QFrame#ToolCard[status="done"] {
    border: 1px solid $border;
}
QLabel#ToolName {
    color: $text;
    font-size: 9pt;
    font-weight: 500;
}
QLabel#ToolMono {
    color: $faint;
    font-family: $font_mono;
    font-size: 7.8pt;
}
QLabel#ToolSummary {
    color: $muted;
    font-size: 8.5pt;
}
QLabel#ToolMeta {
    color: $faint;
    font-size: 7.8pt;
}
QLabel#ToolStatus {
    font-size: 8pt;
    font-weight: 500;
}
QLabel#ToolStatus[status="done"] { color: $green; }
QLabel#ToolStatus[status="error"], QLabel#ToolStatus[status="denied"] { color: $red; }
QLabel#ToolStatus[status="running"] { color: $blue; }
QLabel#ToolStatus[status="awaiting"] { color: $amber; }
QLabel#ToolStatus[status="cancelled"] { color: $faint; }
QPlainTextEdit#CodeBlock {
    background: $code_bg;
    border: 1px solid $code_border;
    border-radius: 6px;
    color: $code_text;
    font-family: $font_mono;
    font-size: 8.3pt;
    padding: 8px;
}
QFrame#ApprovalBar {
    background: $approval_bg;
    border: 1px solid $approval_border;
    border-radius: 10px;
}
QLabel#ApprovalTitle {
    color: $approval_title;
    font-weight: 600;
    font-size: 9.8pt;
}
QLabel#ApprovalBody {
    color: $approval_text;
    font-size: 8.7pt;
}
QFrame#ErrorCard {
    background: $error_bg;
    border: 1px solid $error_border;
    border-radius: 8px;
}
QLabel#ErrorText {
    color: $error_text;
    font-size: 8.8pt;
}
QLabel#AssistantName {
    color: $heading;
    font-size: 9pt;
    font-weight: 600;
}
QLabel#AssistantMeta {
    color: $faint;
    font-size: 8pt;
}
QLabel#StreamingHint {
    color: $muted;
    font-size: 8.3pt;
}
QLabel#ToolToggle, QToolButton#ReasoningToggle {
    color: $muted;
    font-size: 8.3pt;
    padding: 2px 3px;
}
QToolButton#ReasoningToggle:hover {
    color: $text_soft;
    background: transparent;
}
QLabel#ReasoningText {
    color: $text_soft;
    font-size: 8.8pt;
    background: $surface_2;
    border: 1px solid $border_soft;
    border-radius: 6px;
    padding: 8px 10px;
}
QFrame#SidebarFooter {
    background: transparent;
    border-top: 1px solid $border_soft;
}
QFrame#ModelCard {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
}
QFrame#ModelCard:hover {
    background: $surface_2;
    border-color: $border_soft;
}
QLabel#ModelName {
    color: $text_soft;
    font-size: 8.8pt;
    font-weight: 500;
}
QLabel#ModelMeta {
    color: $muted;
    font-size: 7.8pt;
}
QDialog {
    background: $pane;
}
QDialog#SettingsDialog {
    background: $pane;
}
QWidget#SettingsNav {
    background: $nav_bg;
    border-right: 1px solid $border_soft;
}
QListWidget#SettingsNav {
    background: transparent;
    border: none;
    padding: 0px;
}
QListWidget#SettingsNav::item {
    color: $muted;
    padding: 7px 9px;
    border-radius: 6px;
    margin-bottom: 2px;
    font-size: 9pt;
}
QListWidget#SettingsNav::item:hover {
    background: $surface_2;
    color: $text;
}
QListWidget#SettingsNav::item:selected {
    background: $nav_selected_bg;
    color: $accent_text;
}
QListWidget#SettingsNav::item:selected:hover {
    background: $nav_selected_bg;
    color: $accent_text;
}
QListWidget#ProviderList {
    background: $surface;
    border: 1px solid $border_soft;
    border-radius: 8px;
    padding: 4px;
}
QListWidget#ProviderList::item {
    color: $text_soft;
    padding: 7px 8px;
    border-radius: 5px;
    margin: 1px;
    font-size: 9pt;
}
QListWidget#ProviderList::item:hover {
    background: $surface_2;
}
QListWidget#ProviderList::item:selected {
    background: $accent_soft;
    color: $accent_text;
}
QFrame#SettingsPanel {
    background: $pane;
}
QFrame#SettingsFooter {
    background: $pane;
    border-top: 1px solid $border_soft;
}
QLabel#SettingsSection {
    color: $heading;
    font-size: 14pt;
    font-weight: 600;
}
QLabel#SettingsBrandTitle {
    color: $heading;
    font-size: 11pt;
    font-weight: 600;
}
QLabel#SettingsEditorTitle {
    color: $heading;
    font-size: 10pt;
    font-weight: 600;
}
QLabel#FieldLabel {
    color: $text_soft;
    font-size: 8.8pt;
    font-weight: 500;
}
QLabel#HelpText {
    color: $muted;
    font-size: 8.3pt;
}
QLabel#PathBox {
    color: $text_soft;
    background: $code_bg;
    border: 1px solid $border;
    border-radius: 6px;
    padding: 8px;
    font-family: $font_mono;
    font-size: 8.3pt;
}
QFrame#Card {
    background: $card;
    border: 1px solid $border;
    border-radius: 8px;
}
QFrame#ThemeCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 8px;
}
QFrame#ThemeCard:hover {
    border-color: $border_strong;
}
QFrame#ThemeCard[selected="true"] {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 $accent_soft, stop:1 $violet_soft);
    border: 1px solid $accent;
}
QLabel#ThemeCardTitle {
    color: $text;
    font-size: 9.5pt;
    font-weight: 600;
}
QLabel#ThemeCardDesc {
    color: $muted;
    font-size: 8.5pt;
}
QFrame#SuggestionCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 7px;
}
QFrame#SuggestionCard:hover {
    background: $surface_2;
    border-color: $border_strong;
}
QFrame#Toast {
    background: $toast_bg;
    border: 1px solid $toast_border;
    border-radius: 8px;
}
QFrame#Toast QLabel {
    color: $text;
    font-size: 8.8pt;
}
QMenu {
    background: $menu_bg;
    border: 1px solid $border;
    border-radius: 7px;
    padding: 4px;
}
QMenu::item {
    padding: 6px 22px 6px 10px;
    border-radius: 4px;
    color: $text_soft;
    font-size: 9pt;
}
QMenu::item:selected {
    background: $menu_hover;
    color: $text;
}
QMenu::separator {
    height: 1px;
    background: $border_soft;
    margin: 4px 7px;
}
QToolTip {
    background: $tooltip_bg;
    color: $tooltip_text;
    border: 1px solid $tooltip_bg;
    padding: 4px 7px;
    border-radius: 5px;
    font-size: 8.5pt;
}
QDialogButtonBox QPushButton {
    min-width: 70px;
}
QMessageBox {
    background: $card;
}
QMessageBox QLabel {
    color: $text;
}
QListWidget#SkillList {
    background: $surface;
    border: 1px solid $border_soft;
    border-radius: 8px;
    padding: 4px;
}
QListWidget#SkillList::item {
    color: $text_soft;
    padding: 6px 8px;
    border-radius: 5px;
    margin: 1px;
    font-size: 8.8pt;
}
QListWidget#SkillList::item:hover {
    background: $surface_2;
}
QListWidget#SkillList::item:selected {
    background: $accent_soft;
    color: $accent_text;
}
"""


def _asset_url(name: str) -> str:
    return (_ASSETS / name).as_posix().replace('"', "%22")


def _build_qss() -> str:
    palette = THEMES.get(_current_theme, LIGHT)
    values = dict(palette)
    values["font_ui"] = UI_FONT_STACK_QSS
    values["font_mono"] = MONO_FONT_STACK_QSS
    qss = Template(APP_QSS_TEMPLATE).substitute(values)
    suffix = "_light" if _current_theme == "light" else ""
    return (
        qss.replace("__ASSET_CHEVRON_DOWN__", _asset_url(f"chevron_down{suffix}.svg"))
        .replace("__ASSET_CHEVRON_UP__", _asset_url(f"chevron_up{suffix}.svg"))
        .replace("__ASSET_CHECK__", _asset_url(f"check{suffix}.svg"))
    )


def theme_names() -> list[str]:
    return list(THEMES)


def theme_label(name: str) -> str:
    return THEME_LABELS.get(name, THEME_LABELS[DEFAULT_THEME])


def normalize_theme(name: str | None) -> str:
    value = str(name or "").strip().lower()
    return value if value in THEMES else DEFAULT_THEME


def current_theme() -> str:
    return _current_theme


def is_dark() -> bool:
    return _current_theme == "dark"


def ui_font_family() -> str:
    """返回系统可用的界面字体，优先沿用 DeepSeek Harness 的字体栈。"""
    try:
        families = set(QFontDatabase.families())
    except Exception:
        return "Segoe UI"
    for family in UI_FONT_FAMILIES:
        if family in families:
            return family
    return "Segoe UI"


def mono_font_family() -> str:
    try:
        families = set(QFontDatabase.families())
    except Exception:
        return "Consolas"
    for family in MONO_FONT_FAMILIES:
        if family in families:
            return family
    return "Consolas"


def _build_palette(colors: dict[str, str]) -> QPalette:
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(colors["pane"]))
    palette.setColor(QPalette.Base, QColor(colors["input_bg"]))
    palette.setColor(QPalette.AlternateBase, QColor(colors["surface_2"]))
    palette.setColor(QPalette.Text, QColor(colors["text"]))
    palette.setColor(QPalette.WindowText, QColor(colors["text"]))
    palette.setColor(QPalette.Button, QColor(colors["surface"]))
    palette.setColor(QPalette.ButtonText, QColor(colors["text"]))
    palette.setColor(QPalette.Highlight, QColor(colors["selection_bg"]))
    palette.setColor(QPalette.HighlightedText, QColor(colors["selection_text"]))
    palette.setColor(QPalette.ToolTipBase, QColor(colors["tooltip_bg"]))
    palette.setColor(QPalette.ToolTipText, QColor(colors["tooltip_text"]))
    palette.setColor(QPalette.PlaceholderText, QColor(colors["faint"]))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(colors["disabled_text"]))
    palette.setColor(
        QPalette.Disabled, QPalette.WindowText, QColor(colors["disabled_text"])
    )
    return palette


def apply_theme(app: QApplication, theme: str | None = None) -> str:
    """应用指定主题，返回实际生效的主题名。

    该函数可重复调用；``COLORS`` 原地更新，已导入该字典的模块会自动看到新颜色。
    """
    global _current_theme
    _current_theme = normalize_theme(theme) if theme else _current_theme
    colors = THEMES[_current_theme]
    COLORS.clear()
    COLORS.update(colors)

    app.setStyle("Fusion")
    app.setPalette(_build_palette(colors))
    app.setStyleSheet(_build_qss())

    font = QFont(ui_font_family(), 10)
    font.setHintingPreference(QFont.PreferFullHinting)
    font.setStyleStrategy(QFont.PreferAntialias)
    app.setFont(font)
    return _current_theme


__all__ = [
    "COLORS",
    "DARK",
    "DEFAULT_THEME",
    "FONT_SIZES",
    "LIGHT",
    "MONO_FONT_FAMILIES",
    "RADIUS",
    "SPACE",
    "THEMES",
    "THEME_LABELS",
    "UI_FONT_FAMILIES",
    "apply_theme",
    "current_theme",
    "is_dark",
    "mono_font_family",
    "normalize_theme",
    "theme_label",
    "theme_names",
    "ui_font_family",
]
