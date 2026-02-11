# main.py - 听澜启动入口
# -*- coding: utf-8 -*-
import sys
import os
import traceback

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

CORE_PATH = os.path.join(PROJECT_ROOT, "core")
if CORE_PATH not in sys.path:
    sys.path.insert(0, CORE_PATH)

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from gui.main_window import MainWindow


    def main():
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        app = QApplication(sys.argv)
        app.setApplicationName("TingLan 听澜")
        app.setOrganizationName("TingLan")
        app.setApplicationVersion("1.0.0")

        font = QFont("Microsoft YaHei", 10)
        app.setFont(font)

        # --mock 走假数据，方便调UI
        service = None
        if "--mock" in sys.argv:
            from services.mock_service import MockAnalysisService
            service = MockAnalysisService()
            print("[Mock] mock模式")
        else:
            from services.analysis_service import AnalysisService
            service = AnalysisService()
            print("[Real] 真实分析服务")

        window = MainWindow(service=service)
        window.show()
        sys.exit(app.exec())


    if __name__ == "__main__":
        main()

except Exception as e:
    error_msg = f"启动失败:\n\n{str(e)}\n\n{traceback.format_exc()}"
    print(error_msg)

    with open(os.path.join(PROJECT_ROOT, "error.log"), "w", encoding="utf-8") as f:
        f.write(error_msg)

    input("按回车退出...")
