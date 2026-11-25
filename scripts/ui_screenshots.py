"""SSsec 界面截图生成脚本（Linear 风格 UI）。

用法（在项目根目录）：

    .\\.venv\\Scripts\\python.exe scripts\\ui_screenshots.py
    .\\.venv\\Scripts\\python.exe scripts\\ui_screenshots.py --output docs\\images

脚本使用临时 SSsec 数据目录与离线演示 / 脚本化模型，不会访问网络，也不会
影响真实会话文件。图片默认写入 ``docs/images/``，按 1x 逻辑像素保存，便于
README 直接引用。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage, SystemMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from pydantic import PrivateAttr  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from sssec.models import (  # noqa: E402
    Conversation,
    add_finding,
    append_text,
)
from sssec.ui.findings_dialog import FindingsDialog  # noqa: E402
from sssec.ui.main_window import MainWindow  # noqa: E402
from sssec.ui.message_widgets import (  # noqa: E402
    AssistantMessageWidget,
    ReasoningBlock,
    ToolCallCard,
)
from sssec.ui.scope_dialog import ScopeDialog  # noqa: E402
from sssec.ui.settings_dialog import SettingsDialog  # noqa: E402
from sssec.ui.theme import apply_theme  # noqa: E402


class ScreenshotToolModel(BaseChatModel):
    """一次无害命令 + 收尾文本，用来演示工具卡片与审批条。"""

    _calls: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "screenshot-tool"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(
        self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs
    ) -> ChatResult:
        system = "\n".join(
            str(item.content) for item in messages if isinstance(item, SystemMessage)
        )
        if "指挥官（Supervisor）" in system:
            finished = "已完成阶段: 无" not in system
            reply = json.dumps(
                {
                    "next": "finish" if finished else "exploit",
                    "task": "" if finished else "执行一次无害命令验证",
                    "reason": "截图脚本的指挥官调度",
                    "summary": "多 Agent 流程验证完成。" if finished else "",
                },
                ensure_ascii=False,
            )
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=reply))])

        self._calls += 1
        if self._calls == 1:
            message = AIMessage(
                content="先执行一次无害的本地验证命令，确认工具审批链路正常。",
                tool_calls=[
                    {
                        "name": "run_command",
                        "args": {"command": "echo SSsec-UI-Test"},
                        "id": "call_demo_command",
                        "type": "tool_call",
                    }
                ],
            )
        else:
            tool_messages = [item for item in messages if isinstance(item, ToolMessage)]
            message = AIMessage(
                content=(
                    "命令已回显 `SSsec-UI-Test`，审批链路与工作目录都正常。"
                    "接下来可以按目标范围继续做只读信息收集。"
                )
                + (f"（累计 {len(tool_messages)} 条工具结果）" if tool_messages else "")
            )
        return ChatResult(generations=[ChatGeneration(message=message)])


def wait_for(app: QApplication, condition, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.03)
    return False


def settle(app: QApplication, seconds: float = 0.3) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)


def capture(widget, output: Path, name: str) -> None:
    """按屏幕设备像素比保存截图（HiDPI 下为 2x），README 中缩放显示仍然清晰。"""
    output.mkdir(parents=True, exist_ok=True)
    path = output / name
    pixmap = widget.grab()
    logical = widget.size()
    # 不移到 1x：保留 Qt 在 DPR=2 下渲染出的物理像素（主窗口 2640x1720）。
    pixmap.setDevicePixelRatio(1.0)
    pixmap.save(str(path))
    print(
        f"截图: {path}  "
        f"({pixmap.width()}x{pixmap.height()}, 逻辑 {logical.width()}x{logical.height()})"
    )


def _message_widgets(window: MainWindow):
    layout = window.chat_view._column_layout
    if layout is None:
        return []
    widgets = []
    for index in range(layout.count()):
        widget = layout.itemAt(index).widget()
        if isinstance(widget, AssistantMessageWidget):
            widgets.append(widget)
    return widgets


def expand_details(window: MainWindow, *, reasoning: bool = True) -> None:
    for message_widget in _message_widgets(window):
        layout = message_widget._body_layout
        for index in range(layout.count()):
            child = layout.itemAt(index).widget()
            if reasoning and isinstance(child, ReasoningBlock):
                child._toggle()
            elif isinstance(child, ToolCallCard):
                child._toggle()


def collapse_details(window: MainWindow) -> None:
    for message_widget in _message_widgets(window):
        layout = message_widget._body_layout
        for index in range(layout.count()):
            child = layout.itemAt(index).widget()
            if isinstance(child, ReasoningBlock) and child._expanded:
                child._toggle()
            elif isinstance(child, ToolCallCard) and child._expanded:
                child._toggle()


def scroll_to_top(app: QApplication, window: MainWindow) -> None:
    window.chat_view._stick_to_bottom = False
    window.chat_view.verticalScrollBar().setValue(0)
    settle(app, 0.2)


def polish_tool_result(conversation) -> None:
    """把截图里的临时工作目录换成可读的示意路径。"""
    for message in conversation.messages:
        for segment in message.get("segments") or []:
            tool = segment.get("tool") or {}
            raw = tool.get("result")
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except Exception:
                continue
            data = parsed.get("data") if isinstance(parsed, dict) else None
            if isinstance(data, dict) and data.get("cwd"):
                data["cwd"] = r"C:\SSsec\workspaces\example.com"
                tool["result"] = json.dumps(parsed, ensure_ascii=False)


def seed_workspace(window: MainWindow) -> str:
    """给工作区栏准备几条示例会话，返回其中一条的 id（用于“运行中”圆点）。"""
    from datetime import datetime, timedelta

    samples = [
        (
            "api.example.com · JWT 审计",
            "jsmith",
            "已完成只读探测，发现 /api/v2/users 在未携带 token 时返回 401，"
            "下一步验证 alg=none 是否被接受。",
            timedelta(minutes=4),
        ),
        (
            "10.10.0.0/24 内网资产梳理",
            "chloe",
            "22/80/3306 端口开放，80 端口返回 nginx 默认页；继续做目录与服务指纹。",
            timedelta(hours=3),
        ),
        (
            "upload 绕过与落点验证",
            "alex",
            "上传校验只检查 Content-Type，已把 PoC 写入工作区并记录证据。",
            timedelta(days=1, hours=2),
        ),
        (
            "crackme · 静态反汇编",
            "sam",
            "定位到 main 的比较分支，准备用约束求解器还原注册码。",
            timedelta(days=2, hours=5),
        ),
    ]
    now = datetime.now().astimezone()
    added: list[Conversation] = []
    for title, question, answer, delta in samples:
        conversation = Conversation.create()
        conversation.add_user(question)
        assistant = conversation.add_assistant("离线演示")
        append_text(assistant, answer, "text")
        assistant["status"] = "complete"
        conversation.title = title
        conversation.scope = ["example.com"]
        conversation.authorized = True
        stamp = (now - delta).isoformat(timespec="seconds")
        conversation.created_at = stamp
        conversation.updated_at = stamp
        window._save_conversation(conversation)
        window.conversations[conversation.id] = conversation
        added.append(conversation)
    window._refresh_sidebar()
    return added[0].id


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "docs" / "images"))
    parser.add_argument("--offscreen", action="store_true")
    args = parser.parse_args()
    if args.offscreen:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    home = tempfile.mkdtemp(prefix="sssec-shots-")
    os.environ["SSSEC_HOME"] = home
    output = Path(args.output)

    app = QApplication(sys.argv)
    apply_theme(app, "light")
    window = MainWindow()
    window.resize(1320, 860)
    window.show()
    settle(app, 1.0)
    window.toast.hide()
    capture(window, output, "startup.png")

    # 工作区示意：多条会话、按日期分组，并显示一个“正在生成”圆点。
    running_id = seed_workspace(window)
    window.sidebar.set_conversations(
        window._sorted_conversations(), window.current_id, running_id
    )
    settle(app, 0.4)
    capture(window, output, "workspace.png")
    window._refresh_sidebar()

    # ------------------------------------------------------------ 对话与工具
    window._send_message("介绍一下你的能力，并给我一个测试起步清单。")
    wait_for(app, lambda: window.active_run is None, 25)
    settle(app, 0.8)
    window.toast.hide()
    scroll_to_top(app, window)
    capture(window, output, "chat.png")

    window.new_conversation()
    conversation = window.current_conversation
    conversation.scope = ["example.com"]
    conversation.authorized = True
    conversation.title = "example.com 测试目标"
    window._save_conversation(conversation)
    window._refresh_current_view()

    import sssec.agent.graph as graph_module

    # 保守审批让“命令 → 审批条 → 执行”链路可见；默认宽松模式会直接执行。
    window.settings.safety.approval_mode = "sensitive"
    graph_module.build_chat_model = lambda *a, **k: ScreenshotToolModel()
    window._send_message("执行一次无害的命令验证。")
    wait_for(app, lambda: window.pending_approval is not None, 15)
    settle(app, 0.5)
    window.toast.hide()
    capture(window, output, "approval.png")
    window.approval_bar.approve_button.click()
    wait_for(app, lambda: window.active_run is None, 25)
    settle(app, 0.6)
    window.toast.hide()
    scroll_to_top(app, window)
    capture(window, output, "tools.png")

    polish_tool_result(conversation)
    window._save_conversation(conversation)
    window.chat_view.set_conversation(conversation, demo_mode=True)
    settle(app, 0.3)
    expand_details(window)
    settle(app, 0.4)
    window.chat_view.scroll_to_bottom()
    settle(app, 0.3)
    capture(window, output, "tool-detail.png")
    collapse_details(window)
    settle(app, 0.2)

    # ------------------------------------------------------------ 测试发现
    add_finding(
        conversation,
        {
            "title": "示例：响应缺少 Content-Security-Policy",
            "severity": "medium",
            "description": "在测试中观察到响应未设置 CSP，可降低 XSS 的纵深防御能力。",
            "target": "example.com",
            "evidence": "Content-Security-Policy: (missing)",
        },
    )
    add_finding(
        conversation,
        {
            "title": "示例：TLS 证书即将过期",
            "severity": "low",
            "description": "证书剩余有效期不足 30 天，建议在测试窗口内更换。",
            "target": "example.com",
            "evidence": "notAfter=2025-12-01T00:00:00Z",
        },
    )
    window._save_conversation(conversation)
    window._refresh_header()
    findings = FindingsDialog(conversation, window)
    findings.resize(760, 640)
    findings.show()
    settle(app, 0.4)
    capture(findings, output, "findings.png")
    findings.close()

    # ------------------------------------------------------------ 设置页（浅色）
    window.settings.safety.approval_mode = "relaxed"
    settings = SettingsDialog(window.settings, window.data_dir, window)
    settings.resize(1000, 720)
    settings.show()
    settle(app, 0.5)
    capture(settings, output, "settings-models.png")
    settings.nav_list.setCurrentRow(1)
    settle(app, 0.3)
    capture(settings, output, "settings-safety.png")
    settings.nav_list.setCurrentRow(2)
    settle(app, 0.4)
    capture(settings, output, "settings-skills.png")
    settings.nav_list.setCurrentRow(3)
    settle(app, 0.3)
    capture(settings, output, "settings-appearance.png")
    settings.nav_list.setCurrentRow(4)
    # 截图里展示一个正常的安装路径，而不是本次运行使用的临时目录。
    settings.path_label.setText(r"C:\Users\you\AppData\Roaming\SSsec")
    settle(app, 0.3)
    capture(settings, output, "settings-data.png")
    settings.close()
    settle(app, 0.2)

    # ------------------------------------------------------------ 目标与权限
    scope = ScopeDialog(conversation, window)
    scope.resize(680, 640)
    scope.show()
    settle(app, 0.4)
    capture(scope, output, "scope.png")
    scope.close()
    settle(app, 0.2)

    # ------------------------------------------------------------ 完全权限状态
    conversation.full_permission = True
    window._save_conversation(conversation)
    window._refresh_current_view()
    settle(app, 0.4)
    window.toast.hide()
    capture(window, output, "full-permission.png")
    conversation.full_permission = False
    window._save_conversation(conversation)
    window._refresh_current_view()
    settle(app, 0.2)

    # ------------------------------------------------------------ 深色主题
    window._apply_theme("dark")
    settle(app, 0.7)
    window.toast.hide()
    scroll_to_top(app, window)
    capture(window, output, "dark.png")

    dark_settings = SettingsDialog(window.settings, window.data_dir, window)
    dark_settings.resize(1000, 720)
    dark_settings.show()
    settle(app, 0.4)
    dark_settings.nav_list.setCurrentRow(2)
    settle(app, 0.4)
    capture(dark_settings, output, "dark-settings.png")
    dark_settings.close()
    settle(app, 0.2)

    window._apply_theme("light")
    settle(app, 0.4)
    window.close()
    settle(app, 0.2)
    app.quit()
    print(f"临时数据目录: {home}")


if __name__ == "__main__":
    main()
