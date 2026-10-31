"""SSsec UI 冒烟测试与截图脚本。

用法（在项目根目录）：

    .\\.venv\\Scripts\\python.exe scripts\\ui_smoke.py

截图默认写入 artifacts/。脚本使用临时 SSsec 数据目录，不会影响真实会话。
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from pydantic import PrivateAttr  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from sssec.models import add_finding  # noqa: E402
from sssec.ui.findings_dialog import FindingsDialog  # noqa: E402
from sssec.ui.main_window import MainWindow  # noqa: E402
from sssec.ui.scope_dialog import ScopeDialog  # noqa: E402
from sssec.ui.settings_dialog import SettingsDialog  # noqa: E402
from sssec.ui.theme import apply_theme  # noqa: E402


class ScreenshotToolModel(BaseChatModel):
    _calls: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "screenshot-tool"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(
        self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs
    ) -> ChatResult:
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
            it = [item for item in messages if isinstance(item, ToolMessage)]
            message = AIMessage(content="界面端到端验证完成。" + (it[-1].content[:120] if it else ""))
        return ChatResult(generations=[ChatGeneration(message=message)])


def wait_for(app: QApplication, condition, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.03)
    return False


def settle(app: QApplication, seconds: float = 0.25) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)


def capture(window, output: Path, name: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    path = output / name
    window.grab().save(str(path))
    print(f"截图: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "artifacts"))
    parser.add_argument("--offscreen", action="store_true")
    args = parser.parse_args()
    if args.offscreen:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    home = tempfile.mkdtemp(prefix="sssec-smoke-")
    os.environ["SSSEC_HOME"] = home
    output = Path(args.output)

    app = QApplication(sys.argv)
    apply_theme(app, "light")
    window = MainWindow()
    window.resize(1320, 860)
    window.show()
    settle(app, 1.0)
    window.toast.hide()
    capture(window, output, "01-startup.png")

    window._send_message("介绍一下你的能力，并给我一个测试起步清单。")
    wait_for(app, lambda: window.active_run is None, 25)
    settle(app, 0.8)
    window.toast.hide()
    window.chat_view._stick_to_bottom = False
    window.chat_view.verticalScrollBar().setValue(0)
    settle(app, 0.2)
    capture(window, output, "02-demo-chat.png")

    # 新建对话，注入一个脚本化模型，走完整的工具审批流程。
    window.new_conversation()
    conversation = window.current_conversation
    conversation.scope = ["example.com"]
    conversation.authorized = True
    conversation.title = "example.com 测试目标"
    window._save_conversation(conversation)
    window._refresh_current_view()

    import sssec.agent.graph as graph_module

    graph_module.build_chat_model = lambda *a, **k: ScreenshotToolModel()
    window._send_message("执行一次无害的命令验证。")
    wait_for(app, lambda: window.pending_approval is not None, 15)
    settle(app, 0.5)
    window.toast.hide()
    capture(window, output, "03-approval.png")
    window.approval_bar.approve_button.click()
    wait_for(app, lambda: window.active_run is None, 25)
    settle(app, 0.5)
    window.toast.hide()
    capture(window, output, "04-tools.png")

    # 添加一条示例发现用于截图。
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
    window._save_conversation(conversation)
    window._refresh_header()
    findings = FindingsDialog(conversation, window)
    findings.resize(760, 620)
    findings.show()
    settle(app, 0.4)
    capture(findings, output, "05-findings.png")
    findings.close()

    settings = SettingsDialog(window.settings, window.data_dir, window)
    settings.resize(980, 710)
    settings.show()
    settle(app, 0.4)
    capture(settings, output, "06-settings-models.png")
    settings.nav_list.setCurrentRow(1)
    settle(app, 0.2)
    capture(settings, output, "07-settings-safety.png")
    settings.nav_list.setCurrentRow(2)
    settle(app, 0.2)
    capture(settings, output, "08-settings-appearance.png")
    settings.close()

    scope = ScopeDialog(conversation, window)
    scope.resize(640, 660)
    scope.full_checkbox.setChecked(True)
    scope.show()
    settle(app, 0.4)
    capture(scope, output, "09-scope-full.png")
    scope.close()

    # 完全权限状态下的主界面。
    conversation.full_permission = True
    window._save_conversation(conversation)
    window.chat_view.update_empty_state(demo_mode=False)
    window._refresh_current_view()
    settle(app, 0.3)
    window.toast.hide()
    capture(window, output, "10-full-permission.png")
    conversation.full_permission = False
    window._save_conversation(conversation)
    window._refresh_current_view()

    # 深色主题。
    window._apply_theme("dark")
    settle(app, 0.6)
    window.toast.hide()
    capture(window, output, "11-dark-theme.png")
    window._apply_theme("light")
    settle(app, 0.4)

    window.close()
    settle(app, 0.2)
    app.quit()
    print(f"临时数据目录: {home}")


if __name__ == "__main__":
    main()
