"""设置 → 技能库：浏览、启停、编辑用户技能（Linear 风格）。"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sssec.skills import STAGES, Skill, SkillStore
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS
from sssec.ui.widgets import PageHeader, render_markdown


class SkillsPage(QWidget):
    """技能库管理页：左侧列表 + 右侧预览/编辑。"""

    skills_changed = Signal()

    def __init__(self, store: SkillStore, parent: QWidget | None = None):
        super().__init__(parent)
        self.store = store
        self._editing: Skill | None = None
        self._builtin_view = False
        self._loading = False
        self._build_ui()
        self.reload()

    # ------------------------------------------------------------------ ui
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 22, 28, 18)
        layout.setSpacing(8)

        layout.addWidget(
            PageHeader(
                "bolt",
                "技能库",
                "内置技能随版本提供，只读；可以停用或复制成“我的技能”再修改。"
                "子 Agent 通过 skill_load 按需加载，每阶段最多一张。",
                tone="amber",
            )
        )
        layout.addSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(7)
        self.search = QLineEdit()
        self.search.setObjectName("SearchInput")
        self.search.setPlaceholderText("搜索名称 / 触发条件 / id")
        self.search.addAction(
            icon("search", COLORS["faint"], 14), QLineEdit.LeadingPosition
        )
        self.search.setFixedHeight(30)
        self.search.textChanged.connect(self._refresh_list)
        toolbar.addWidget(self.search, 1)
        self.filter_combo = QComboBox()
        for label, key in (
            ("全部", "all"),
            ("内置", "builtin"),
            ("我的", "user"),
            ("已启用", "enabled"),
        ):
            self.filter_combo.addItem(label, key)
        self.filter_combo.setFixedWidth(96)
        self.filter_combo.currentIndexChanged.connect(self._refresh_list)
        toolbar.addWidget(self.filter_combo)
        self.category_combo = QComboBox()
        self.category_combo.addItem("全部分类", "all")
        self.category_combo.setFixedWidth(126)
        self.category_combo.currentIndexChanged.connect(self._refresh_list)
        toolbar.addWidget(self.category_combo)
        layout.addLayout(toolbar)

        body = QHBoxLayout()
        body.setSpacing(12)

        self.list_widget = QListWidget()
        self.list_widget.setObjectName("SkillList")
        self.list_widget.setMinimumWidth(262)
        self.list_widget.setMaximumWidth(342)
        self.list_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.list_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.list_widget.setWordWrap(True)
        self.list_widget.setTextElideMode(Qt.ElideNone)
        self.list_widget.currentItemChanged.connect(self._on_select)
        self.list_widget.itemChanged.connect(self._on_item_changed)
        body.addWidget(self.list_widget, 0)

        panel = QFrame()
        panel.setObjectName("Card")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(14, 12, 14, 12)
        panel_layout.setSpacing(8)

        self.meta_label = QLabel("选择左侧技能查看详情")
        self.meta_label.setObjectName("FieldLabel")
        self.meta_label.setWordWrap(True)
        panel_layout.addWidget(self.meta_label)

        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(False)
        self.preview.setStyleSheet("QTextBrowser { background: transparent; border: none; }")
        panel_layout.addWidget(self.preview, 1)

        self.editor = QWidget()
        editor_layout = QVBoxLayout(self.editor)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(7)
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("名称，例如：上传校验与落点")
        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("id，例如：upload-bypass（小写字母/数字/短横线）")
        self.when_input = QLineEdit()
        self.when_input.setPlaceholderText("触发条件，一行说明")
        self.category_input = QLineEdit()
        self.category_input.setPlaceholderText("分类，例如：漏洞扫描 / 后渗透 / 通用")
        self.stages_input = QLineEdit()
        self.stages_input.setPlaceholderText("适用阶段，逗号分隔：" + ", ".join(STAGES))
        self.body_input = QPlainTextEdit()
        self.body_input.setPlaceholderText("技能正文（Markdown，不超过 8000 字符）")
        for label, widget in (
            ("名称", self.name_input),
            ("ID", self.id_input),
            ("触发条件", self.when_input),
            ("分类", self.category_input),
            ("适用阶段", self.stages_input),
        ):
            row = QHBoxLayout()
            row.setSpacing(8)
            tag = QLabel(label)
            tag.setObjectName("FieldLabel")
            tag.setFixedWidth(62)
            row.addWidget(tag)
            row.addWidget(widget, 1)
            editor_layout.addLayout(row)
        editor_layout.addWidget(self.body_input, 1)
        self.editor.setVisible(False)
        panel_layout.addWidget(self.editor, 1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.new_button = QPushButton("新建")
        self.new_button.setObjectName("Secondary")
        self.new_button.setIcon(icon("plus", COLORS["text_soft"], 14))
        self.new_button.clicked.connect(self._start_new)
        self.save_button = QPushButton("保存")
        self.save_button.setObjectName("Primary")
        self.save_button.clicked.connect(self._save)
        self.delete_button = QPushButton("删除")
        self.delete_button.setObjectName("Secondary")
        self.delete_button.setIcon(icon("trash", COLORS["red"], 14))
        self.delete_button.clicked.connect(self._delete)
        self.copy_button = QPushButton("复制")
        self.copy_button.setObjectName("Secondary")
        self.copy_button.setIcon(icon("copy", COLORS["text_soft"], 14))
        self.copy_button.setToolTip("把当前内置技能复制为“我的技能”，以便修改")
        self.copy_button.clicked.connect(self._copy_builtin)
        self.import_button = QPushButton("导入")
        self.import_button.setObjectName("Secondary")
        self.import_button.setIcon(icon("download", COLORS["text_soft"], 14))
        self.import_button.clicked.connect(self._import)
        self.export_button = QPushButton("导出")
        self.export_button.setObjectName("Secondary")
        self.export_button.setIcon(icon("upload", COLORS["text_soft"], 14))
        self.export_button.clicked.connect(self._export)
        for button in (
            self.new_button,
            self.save_button,
            self.delete_button,
        ):
            button.setCursor(Qt.PointingHandCursor)
            button.setFixedHeight(30)
            actions.addWidget(button)
        actions.addStretch(1)
        for button in (
            self.copy_button,
            self.import_button,
            self.export_button,
        ):
            button.setCursor(Qt.PointingHandCursor)
            button.setFixedHeight(30)
            actions.addWidget(button)
        panel_layout.addLayout(actions)

        body.addWidget(panel, 1)
        layout.addLayout(body, 1)

    # ----------------------------------------------------------------- data
    def reload(self) -> None:
        self.store.reload()
        current = self.category_combo.currentData()
        self.category_combo.blockSignals(True)
        self.category_combo.clear()
        self.category_combo.addItem("全部分类", "all")
        for category in self.store.categories():
            self.category_combo.addItem(category, category)
        index = self.category_combo.findData(current)
        self.category_combo.setCurrentIndex(max(0, index))
        self.category_combo.blockSignals(False)
        self._refresh_list()

    def _filtered(self) -> list[Skill]:
        keyword = self.search.text().strip().lower()
        mode = str(self.filter_combo.currentData() or "all")
        category = str(self.category_combo.currentData() or "all")
        items: list[Skill] = []
        for skill in self.store.list(include_disabled=True):
            if mode == "builtin" and not skill.builtin:
                continue
            if mode == "user" and skill.builtin:
                continue
            if mode == "enabled" and not skill.enabled:
                continue
            if category != "all" and (skill.category or "其他") != category:
                continue
            haystack = f"{skill.id} {skill.name} {skill.when}".lower()
            if keyword and keyword not in haystack:
                continue
            items.append(skill)
        return items

    def _refresh_list(self) -> None:
        current = self._selected_id()
        self._loading = True
        self.list_widget.clear()
        for skill in self._filtered():
            badge = "内置" if skill.builtin else "我的"
            state = "" if skill.enabled else " · 已停用"
            item = QListWidgetItem(
                f"{skill.name}\n"
                f"{badge} · {skill.category or '其他'} · {skill.id}{state}"
            )
            item.setData(Qt.UserRole, skill.id)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if skill.enabled else Qt.Unchecked)
            item.setToolTip(f"{skill.name}\n{skill.when}")
            item.setSizeHint(QSize(0, 48))
            self.list_widget.addItem(item)
        self._loading = False
        if current:
            self._select_by_id(current)
        elif self.list_widget.count():
            self.list_widget.setCurrentRow(0)
        else:
            self._show_empty()

    def _selected_id(self) -> str:
        item = self.list_widget.currentItem()
        return str(item.data(Qt.UserRole)) if item else ""

    def _select_by_id(self, skill_id: str) -> None:
        for row in range(self.list_widget.count()):
            item = self.list_widget.item(row)
            if item and str(item.data(Qt.UserRole)) == skill_id:
                self.list_widget.setCurrentRow(row)
                return

    def _show_empty(self) -> None:
        self.meta_label.setText("技能库为空")
        self.preview.setPlainText("点击“新建”或“导入”添加技能。")
        self.editor.setVisible(False)
        self._editing = None

    # ----------------------------------------------------------------- select
    def _on_select(self, current: QListWidgetItem | None, _previous=None) -> None:
        if self._loading or current is None:
            return
        skill = self.store.get(str(current.data(Qt.UserRole)))
        if skill is None:
            return
        self._builtin_view = skill.builtin
        self._editing = None
        self.preview.setVisible(True)
        self.editor.setVisible(False)
        self.meta_label.setText(
            f"{skill.name}（{skill.id}） · {skill.category or '其他'}"
            f" · {'内置只读' if skill.builtin else '我的技能'}"
            f" · {skill.stage_text} · v{skill.version}"
        )
        source = f"\n\n来源：{skill.source}" if skill.source else ""
        license_text = f" · {skill.license}" if skill.license else ""
        self.preview.setHtml(
            render_markdown(
                f"# {skill.name}\n\n**触发**：{skill.when}\n\n{skill.body}{source}{license_text}"
            )
        )
        self.delete_button.setEnabled(not skill.builtin)
        self.copy_button.setEnabled(skill.builtin)
        self.save_button.setEnabled(False)

    def _on_item_changed(self, item: QListWidgetItem) -> None:
        if self._loading or item is None:
            return
        skill_id = str(item.data(Qt.UserRole))
        enabled = item.checkState() == Qt.Checked
        if self.store.set_enabled(skill_id, enabled):
            self.skills_changed.emit()
            self._refresh_list()

    # ----------------------------------------------------------------- edit
    def _start_new(self) -> None:
        self._editing = Skill(id="", name="", when="", stages=["any"])
        self._builtin_view = False
        self._fill_editor(self._editing)
        self.meta_label.setText("新建技能")
        self.preview.setVisible(False)
        self.editor.setVisible(True)
        self.save_button.setEnabled(True)
        self.delete_button.setEnabled(False)
        self.copy_button.setEnabled(False)
        self.name_input.setFocus()

    def _fill_editor(self, skill: Skill) -> None:
        self.name_input.setText(skill.name)
        self.id_input.setText(skill.id)
        self.when_input.setText(skill.when)
        self.category_input.setText(skill.category or "其他")
        self.stages_input.setText(", ".join(skill.stages))
        self.body_input.setPlainText(skill.body)

    def _save(self) -> None:
        skill = self._editing
        if skill is None:
            return
        stages = [item.strip() for item in self.stages_input.text().split(",") if item.strip()]
        candidate = Skill(
            id=self.id_input.text().strip().lower(),
            name=self.name_input.text().strip(),
            when=self.when_input.text().strip(),
            category=self.category_input.text().strip() or "其他",
            stages=stages or ["any"],
            body=self.body_input.toPlainText().strip(),
            version=skill.version,
            source=skill.source,
            license=skill.license,
        )
        try:
            saved = self.store.save_user(candidate)
        except Exception as exc:
            QMessageBox.warning(self, "保存失败", str(exc))
            return
        self._editing = None
        self.skills_changed.emit()
        self.reload()
        self._select_by_id(saved.id)

    def _delete(self) -> None:
        item = self.list_widget.currentItem()
        if item is None:
            return
        skill = self.store.get(str(item.data(Qt.UserRole)))
        if skill is None or skill.builtin:
            QMessageBox.information(self, "内置技能", "内置技能不能删除，只能停用。")
            return
        answer = QMessageBox.question(
            self,
            "删除技能",
            f"确定删除“{skill.name}”（{skill.id}）？",
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if answer != QMessageBox.Yes:
            return
        if self.store.delete_user(skill.id):
            self.skills_changed.emit()
            self.reload()
            self._show_empty()

    def _copy_builtin(self) -> None:
        item = self.list_widget.currentItem()
        if item is None:
            return
        skill = self.store.get(str(item.data(Qt.UserRole)))
        if skill is None:
            return
        try:
            copy = self.store.copy_as_user(skill.id)
        except Exception as exc:
            QMessageBox.warning(self, "复制失败", str(exc))
            return
        self.skills_changed.emit()
        self.reload()
        self._select_by_id(copy.id)

    def _import(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "导入技能", "", "Markdown (*.md)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
            skill = self.store.import_markdown(text, overwrite=True)
        except Exception as exc:
            QMessageBox.warning(self, "导入失败", str(exc))
            return
        self.skills_changed.emit()
        self.reload()
        self._select_by_id(skill.id)

    def _export(self) -> None:
        item = self.list_widget.currentItem()
        if item is None:
            return
        skill = self.store.get(str(item.data(Qt.UserRole)))
        if skill is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出技能", f"{skill.id}.md", "Markdown (*.md)"
        )
        if not path:
            return
        try:
            Path(path).write_text(self.store.export_markdown(skill.id), encoding="utf-8")
        except Exception as exc:
            QMessageBox.warning(self, "导出失败", str(exc))


__all__ = ["SkillsPage"]
