"""应用配色、字体与全局 QSS。

SSsec 提供两套主题：

* ``light`` —— 以白色为主的浅色主题，默认启用；
* ``dark``  —— 深色安全测试工作台主题。

主题颜色集中保存在 ``THEMES`` 中，``COLORS`` 是指向当前主题的实时字典。
界面代码统一读取 ``COLORS["..."]``，切换主题时 ``apply_theme()`` 会原地更新
该字典并重建 QSS，因此各模块无需重新导入即可拿到新配色。
"""

from __future__ import annotations

from pathlib import Path
from string import Template

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QApplication

_ASSETS = Path(__file__).resolve().parent.parent / "assets"

THEME_LABELS = {
    "light": "浅色（白色主题）",
    "dark": "深色（安全测试工作台）",
}
DEFAULT_THEME = "light"

LIGHT = {
    "bg": "#f4f6fa",
    "sidebar": "#ffffff",
    "pane": "#f7f9fc",
    "surface": "#ffffff",
    "surface_2": "#f2f5f9",
    "surface_3": "#eaf0f6",
    "card": "#ffffff",
    "border": "#dce4ed",
    "border_soft": "#eaf0f6",
    "border_strong": "#c4d1df",
    "text": "#1b2838",
    "heading": "#0e1b2a",
    "text_soft": "#42566b",
    "muted": "#6c8095",
    "faint": "#93a3b5",
    "icon": "#788ca0",
    "accent": "#0e9f8c",
    "accent_hover": "#0b8575",
    "accent_soft": "#e7f7f3",
    "accent_soft_hover": "#dcf2ed",
    "accent_border": "#bde7df",
    "accent_border_hover": "#93d8cc",
    "on_accent": "#ffffff",
    "accent_text": "#0a7c6d",
    "blue": "#2f7fdb",
    "blue_border": "#bbd5f2",
    "amber": "#b3741b",
    "amber_soft": "#fff8ea",
    "amber_border": "#edd6a4",
    "green": "#1a8b5e",
    "green_border": "#bfe5d5",
    "red": "#d24550",
    "red_soft": "#fff3f4",
    "red_border": "#f1c7cb",
    "input_bg": "#ffffff",
    "input_border": "#d6e0ea",
    "input_border_hover": "#bccbda",
    "input_focus": "#0e9f8c",
    "disabled_bg": "#f2f5f9",
    "disabled_text": "#a3b1c0",
    "selection_bg": "#cbede6",
    "selection_text": "#0c3d35",
    "scroll": "#c6d2df",
    "scroll_hover": "#a9bbce",
    "menu_bg": "#ffffff",
    "menu_hover": "#eef7f5",
    "tooltip_bg": "#1e2b3a",
    "tooltip_text": "#f4f8fc",
    "user_bubble": "#e9f2fe",
    "user_border": "#d3e3f8",
    "user_text": "#163252",
    "avatar_bg": "#edf2f8",
    "avatar_text": "#5d7489",
    "avatar_border": "#dce5ee",
    "code_bg": "#f4f7fa",
    "code_border": "#e2e9f1",
    "code_text": "#2c4761",
    "code_inline_bg": "#edf5f2",
    "code_inline_text": "#0a7c6d",
    "approval_bg": "#fffaee",
    "approval_border": "#e9d3a2",
    "approval_title": "#8a5a12",
    "approval_text": "#77633f",
    "error_bg": "#fff5f5",
    "error_border": "#f0ccd0",
    "error_text": "#b03944",
    "toast_bg": "#ffffff",
    "toast_border": "#cbe7e1",
    "convo_selected_bg": "#e8f7f3",
    "convo_selected_border": "#bce5dc",
    "convo_title_selected": "#0a6b5e",
    "nav_bg": "#fafbfd",
    "nav_selected_bg": "#e8f7f3",
}

DARK = {
    "bg": "#080d13",
    "sidebar": "#0a1017",
    "pane": "#0b1118",
    "surface": "#101822",
    "surface_2": "#141e29",
    "surface_3": "#182431",
    "card": "#0e1620",
    "border": "#1e2b38",
    "border_soft": "#17232e",
    "border_strong": "#2a3a4a",
    "text": "#e7eef7",
    "heading": "#f2f8ff",
    "text_soft": "#b6c5d6",
    "muted": "#8396aa",
    "faint": "#5b6d80",
    "icon": "#9fb2c4",
    "accent": "#35d6c0",
    "accent_hover": "#5be8d4",
    "accent_soft": "#0e2a29",
    "accent_soft_hover": "#123633",
    "accent_border": "#1d4c49",
    "accent_border_hover": "#286b64",
    "on_accent": "#062622",
    "accent_text": "#9df5e7",
    "blue": "#67a7ff",
    "blue_border": "#2a5360",
    "amber": "#f0b85d",
    "amber_soft": "#1c1710",
    "amber_border": "#4b3b21",
    "green": "#62da9e",
    "green_border": "#1f3b32",
    "red": "#f17b82",
    "red_soft": "#2b1619",
    "red_border": "#5c2b31",
    "input_bg": "#0d151e",
    "input_border": "#233241",
    "input_border_hover": "#304353",
    "input_focus": "#2e7a71",
    "disabled_bg": "#0b1219",
    "disabled_text": "#5e7184",
    "selection_bg": "#1f655e",
    "selection_text": "#ffffff",
    "scroll": "#263744",
    "scroll_hover": "#375162",
    "menu_bg": "#111a24",
    "menu_hover": "#172b31",
    "tooltip_bg": "#17232e",
    "tooltip_text": "#dce8f4",
    "user_bubble": "#142d3d",
    "user_border": "#23475d",
    "user_text": "#e8f3fb",
    "avatar_bg": "#162736",
    "avatar_text": "#94aec3",
    "avatar_border": "#223a4c",
    "code_bg": "#0a1118",
    "code_border": "#1a2732",
    "code_text": "#b9d1e6",
    "code_inline_bg": "#0d1721",
    "code_inline_text": "#8fe8d9",
    "approval_bg": "#1b1711",
    "approval_border": "#5a4724",
    "approval_title": "#ffd796",
    "approval_text": "#cdbb96",
    "error_bg": "#1d1315",
    "error_border": "#4d282d",
    "error_text": "#f3a0a6",
    "toast_bg": "#162430",
    "toast_border": "#315062",
    "convo_selected_bg": "#11211f",
    "convo_selected_border": "#20433f",
    "convo_title_selected": "#eafffa",
    "nav_bg": "#090f15",
    "nav_selected_bg": "#12201f",
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
    font-family: "Microsoft YaHei UI", "Segoe UI", "PingFang SC", sans-serif;
    font-size: 10.5pt;
}
QMainWindow, QWidget#Root {
    background: $bg;
}
QWidget#Sidebar {
    background: $sidebar;
    border-right: 1px solid $border_soft;
}
QWidget#MainPane {
    background: $pane;
}
QWidget#ChatCanvas, QScrollArea#ChatScroll, QScrollArea#SettingsScroll {
    background: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QFrame#ChatHeader {
    background: $pane;
    border-bottom: 1px solid $border_soft;
}
QFrame#ComposerArea {
    background: $pane;
    border-top: 1px solid $border_soft;
}
QFrame#ComposerCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 14px;
}
QFrame#ComposerCard[focused="true"] {
    border: 1px solid $accent;
}
QLabel {
    background: transparent;
}
QLabel#BrandName {
    color: $heading;
    font-size: 17pt;
    font-weight: 700;
    letter-spacing: 0.5px;
}
QLabel#BrandSub {
    color: $muted;
    font-size: 7.5pt;
    font-weight: 600;
    letter-spacing: 1.2px;
}
QLabel#SectionCaption {
    color: $faint;
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.6px;
}
QLabel#Muted {
    color: $muted;
}
QLabel#Faint {
    color: $faint;
    font-size: 9pt;
}
QLabel#Mono {
    font-family: "Cascadia Code", "JetBrains Mono", Consolas, monospace;
    font-size: 9pt;
}
QLabel#PageTitle {
    color: $heading;
    font-size: 14pt;
    font-weight: 700;
}
QLabel#PageSub {
    color: $muted;
    font-size: 9.5pt;
}
QLabel#EmptyHeading {
    color: $heading;
    font-size: 20pt;
    font-weight: 700;
}
QLabel#EmptyDisclaimer {
    color: $faint;
    font-size: 8pt;
}
QLabel#CardTitle {
    color: $text;
    font-size: 9.5pt;
    font-weight: 600;
}
QLabel#SuggestionTitle {
    color: $text;
    font-size: 9.5pt;
    font-weight: 600;
}
QLabel#SuggestionSub {
    color: $muted;
    font-size: 8.5pt;
}
QPushButton {
    border: none;
    background: transparent;
    color: $text_soft;
    padding: 7px 12px;
    border-radius: 8px;
}
QPushButton:hover {
    background: $surface_2;
}
QPushButton:pressed {
    background: $surface_3;
}
QPushButton:disabled {
    color: $disabled_text;
}
QPushButton#NewChat {
    background: $accent_soft;
    border: 1px solid $accent_border;
    color: $accent_text;
    padding: 10px 12px;
    font-weight: 600;
    text-align: left;
}
QPushButton#NewChat:hover {
    background: $accent_soft_hover;
    border-color: $accent_border_hover;
}
QPushButton#Primary {
    background: $accent;
    color: $on_accent;
    padding: 9px 18px;
    border-radius: 8px;
    font-weight: 700;
}
QPushButton#Primary:hover {
    background: $accent_hover;
}
QPushButton#Primary:disabled {
    background: $accent_soft;
    color: $faint;
}
QPushButton#Secondary {
    background: $surface_2;
    border: 1px solid $border;
    color: $text_soft;
    padding: 8px 14px;
    border-radius: 8px;
}
QPushButton#Secondary:hover {
    background: $surface_3;
    border-color: $border_strong;
    color: $text;
}
QPushButton#Danger {
    background: $red_soft;
    border: 1px solid $red_border;
    color: $red;
    padding: 8px 14px;
    border-radius: 8px;
}
QPushButton#Danger:hover {
    border-color: $red;
}
QPushButton#Suggestion {
    background: $surface;
    border: 1px solid $border;
    border-radius: 10px;
    padding: 12px 14px;
    text-align: left;
    color: $text_soft;
    font-size: 9.5pt;
}
QPushButton#Suggestion:hover {
    background: $surface_2;
    border-color: $accent_border_hover;
}
QPushButton#SendButton {
    background: $accent;
    border-radius: 9px;
    padding: 0px;
}
QPushButton#SendButton:hover {
    background: $accent_hover;
}
QPushButton#SendButton:disabled {
    background: $accent_soft;
}
QPushButton#StopButton {
    background: $red_soft;
    border: 1px solid $red_border;
    border-radius: 9px;
    padding: 0px;
}
QPushButton#StopButton:hover {
    border-color: $red;
}
QPushButton#Chip {
    background: $surface;
    border: 1px solid $border;
    border-radius: 9px;
    padding: 5px 10px;
    color: $muted;
    font-size: 9pt;
}
QPushButton#Chip:hover {
    border-color: $accent_border_hover;
    color: $text;
}
QPushButton#Chip[ok="true"] {
    color: $accent_text;
    border-color: $accent_border;
    background: $accent_soft;
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
    padding: 4px 7px;
}
QPushButton#FooterLink:hover {
    color: $text;
    background: $surface_2;
}
QToolButton {
    background: transparent;
    border: none;
    border-radius: 7px;
    padding: 5px;
}
QToolButton:hover {
    background: $surface_2;
}
QToolButton#IconButton {
    padding: 7px;
}
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: $input_bg;
    border: 1px solid $input_border;
    border-radius: 8px;
    padding: 7px 9px;
    color: $text;
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
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox::down-arrow {
    image: url("__ASSET_CHEVRON_DOWN__");
    width: 11px;
    height: 11px;
}
QComboBox QAbstractItemView {
    background: $menu_bg;
    border: 1px solid $border_strong;
    selection-background-color: $accent_soft;
    selection-color: $text;
    padding: 4px;
    outline: none;
}
QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    width: 18px;
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
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid $input_border;
    border-radius: 4px;
    background: $input_bg;
}
QCheckBox::indicator:hover {
    border-color: $input_border_hover;
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
    font-size: 11pt;
}
QPlainTextEdit#SearchInput {
    background: $surface;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 6px 9px;
    font-size: 9.5pt;
}
QTextBrowser {
    background: transparent;
    border: none;
}
QScrollBar:vertical {
    background: transparent;
    width: 9px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: $scroll;
    min-height: 26px;
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
    height: 9px;
    margin: 2px;
}
QScrollBar::handle:horizontal {
    background: $scroll;
    min-width: 26px;
    border-radius: 4px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QFrame#ConversationRow {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 9px;
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
    font-size: 9.5pt;
    font-weight: 600;
}
QLabel#ConvoTitle[selected="true"] {
    color: $convo_title_selected;
}
QLabel#ConvoPreview {
    color: $muted;
    font-size: 8.5pt;
}
QLabel#ConvoTime {
    color: $faint;
    font-size: 7.5pt;
}
QFrame#UserBubble {
    background: $user_bubble;
    border: 1px solid $user_border;
    border-radius: 12px;
}
QLabel#UserText {
    color: $user_text;
    font-size: 10.5pt;
}
QLabel#UserAvatar {
    background: $avatar_bg;
    color: $avatar_text;
    border: 1px solid $avatar_border;
    border-radius: 14px;
    font-size: 8.5pt;
}
QFrame#ToolCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 10px;
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
    border: 1px solid $green_border;
}
QLabel#ToolName {
    color: $text;
    font-family: "Cascadia Code", Consolas, monospace;
    font-size: 9pt;
    font-weight: 600;
}
QLabel#ToolMono {
    color: $faint;
    font-family: Consolas, monospace;
    font-size: 8pt;
}
QLabel#ToolSummary {
    color: $muted;
    font-size: 8.5pt;
}
QLabel#ToolMeta {
    color: $faint;
    font-size: 7.5pt;
}
QLabel#ToolStatus {
    font-size: 8pt;
    font-weight: 600;
}
QLabel#ToolStatus[status="done"] { color: $green; }
QLabel#ToolStatus[status="error"], QLabel#ToolStatus[status="denied"] { color: $red; }
QLabel#ToolStatus[status="running"] { color: $blue; }
QLabel#ToolStatus[status="awaiting"] { color: $amber; }
QLabel#ToolStatus[status="cancelled"] { color: $faint; }
QPlainTextEdit#CodeBlock {
    background: $code_bg;
    border: 1px solid $code_border;
    border-radius: 7px;
    color: $code_text;
    font-family: "Cascadia Code", Consolas, monospace;
    font-size: 8.5pt;
    padding: 8px;
}
QFrame#ApprovalBar {
    background: $approval_bg;
    border: 1px solid $approval_border;
    border-radius: 12px;
}
QLabel#ApprovalTitle {
    color: $approval_title;
    font-weight: 700;
    font-size: 10.5pt;
}
QLabel#ApprovalBody {
    color: $approval_text;
    font-size: 9pt;
}
QFrame#ErrorCard {
    background: $error_bg;
    border: 1px solid $error_border;
    border-radius: 9px;
}
QLabel#ErrorText {
    color: $error_text;
    font-size: 9pt;
}
QLabel#AssistantName {
    color: $text;
    font-size: 9.5pt;
    font-weight: 700;
}
QLabel#AssistantMeta {
    color: $faint;
    font-size: 8pt;
}
QLabel#StreamingHint {
    color: $muted;
    font-size: 8.5pt;
}
QLabel#ToolToggle, QToolButton#ReasoningToggle {
    color: $muted;
    font-size: 8.5pt;
    padding: 2px 4px;
}
QToolButton#ReasoningToggle:hover {
    color: $text_soft;
    background: transparent;
}
QLabel#ReasoningText {
    color: $text_soft;
    font-size: 8.8pt;
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 7px;
    padding: 8px 10px;
}
QFrame#SidebarFooter {
    background: $sidebar;
    border-top: 1px solid $border_soft;
}
QFrame#ModelCard {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: 9px;
}
QLabel#ModelName {
    color: $text_soft;
    font-size: 8.5pt;
    font-weight: 600;
}
QLabel#ModelMeta {
    color: $muted;
    font-size: 7.5pt;
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
    background: $nav_bg;
    border: none;
    padding: 8px;
}
QListWidget#SettingsNav::item {
    color: $muted;
    padding: 10px 12px;
    border-radius: 7px;
    margin-bottom: 3px;
}
QListWidget#SettingsNav::item:hover {
    background: $surface_2;
    color: $text;
}
QListWidget#SettingsNav::item:selected {
    background: $nav_selected_bg;
    color: $accent_text;
}
QListWidget#ProviderList {
    background: $surface;
    border: 1px solid $border;
    border-radius: 9px;
    padding: 5px;
}
QListWidget#ProviderList::item {
    color: $text_soft;
    padding: 9px 10px;
    border-radius: 6px;
    margin: 2px;
}
QListWidget#ProviderList::item:hover {
    background: $surface_2;
}
QListWidget#ProviderList::item:selected {
    background: $accent_soft;
    color: $accent_text;
    border: 1px solid $accent_border;
}
QFrame#SettingsPanel {
    background: $pane;
}
QFrame#SettingsFooter {
    background: $sidebar;
    border-top: 1px solid $border_soft;
}
QLabel#SettingsSection {
    color: $heading;
    font-size: 12pt;
    font-weight: 700;
}
QLabel#SettingsBrandTitle {
    color: $heading;
    font-size: 13pt;
    font-weight: 700;
}
QLabel#SettingsEditorTitle {
    color: $heading;
    font-size: 11pt;
    font-weight: 700;
}
QLabel#FieldLabel {
    color: $text_soft;
    font-size: 9pt;
}
QLabel#HelpText {
    color: $muted;
    font-size: 8.5pt;
}
QLabel#PathBox {
    color: $text_soft;
    background: $code_bg;
    border: 1px solid $border;
    border-radius: 7px;
    padding: 9px;
}
QFrame#Divider {
    background: $border_soft;
    max-height: 1px;
    min-height: 1px;
    border: none;
}
QFrame#Card {
    background: $card;
    border: 1px solid $border;
    border-radius: 10px;
}
QFrame#ThemeCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 12px;
}
QFrame#ThemeCard:hover {
    border-color: $accent_border_hover;
}
QFrame#ThemeCard[selected="true"] {
    background: $accent_soft;
    border: 1px solid $accent;
}
QLabel#ThemeCardTitle {
    color: $text;
    font-size: 10.5pt;
    font-weight: 700;
}
QLabel#ThemeCardDesc {
    color: $muted;
    font-size: 8.8pt;
}
QFrame#SuggestionCard {
    background: $surface;
    border: 1px solid $border;
    border-radius: 11px;
}
QFrame#SuggestionCard:hover {
    background: $surface_2;
    border-color: $accent_border_hover;
}
QFrame#Toast {
    background: $toast_bg;
    border: 1px solid $toast_border;
    border-radius: 9px;
}
QFrame#Toast QLabel {
    color: $text;
    font-size: 9pt;
}
QMenu {
    background: $menu_bg;
    border: 1px solid $border_strong;
    border-radius: 8px;
    padding: 5px;
}
QMenu::item {
    padding: 7px 24px 7px 12px;
    border-radius: 5px;
    color: $text_soft;
}
QMenu::item:selected {
    background: $menu_hover;
    color: $text;
}
QMenu::separator {
    height: 1px;
    background: $border;
    margin: 5px 8px;
}
QToolTip {
    background: $tooltip_bg;
    color: $tooltip_text;
    border: 1px solid $border_strong;
    padding: 5px 8px;
    border-radius: 5px;
}
QDialogButtonBox QPushButton {
    min-width: 72px;
}
QMessageBox {
    background: $card;
}
QMessageBox QLabel {
    color: $text;
}
"""


def _asset_url(name: str) -> str:
    return (_ASSETS / name).as_posix().replace('"', "%22")


def _build_qss() -> str:
    palette = THEMES.get(_current_theme, LIGHT)
    qss = Template(APP_QSS_TEMPLATE).substitute(palette)
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


def _build_palette(colors: dict[str, str]) -> QPalette:
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(colors["bg"]))
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

    families = set(QFontDatabase.families())
    family = "Microsoft YaHei UI" if "Microsoft YaHei UI" in families else "Segoe UI"
    font = QFont(family, 10)
    font.setHintingPreference(QFont.PreferFullHinting)
    app.setFont(font)
    return _current_theme


__all__ = [
    "COLORS",
    "DARK",
    "DEFAULT_THEME",
    "LIGHT",
    "THEMES",
    "THEME_LABELS",
    "apply_theme",
    "current_theme",
    "is_dark",
    "normalize_theme",
    "theme_label",
    "theme_names",
]
