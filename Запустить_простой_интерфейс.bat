@echo off
chcp 65001 >nul
cd /d "%~dp0"

REM Виртуальное окружение (если есть)
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

echo Установка зависимостей GUI (при первом запуске может занять время)...
python -m pip install -r requirements-gui.txt -q
if errorlevel 1 (
  echo Не удалось вызвать python. Установите Python и добавьте в PATH.
  pause
  exit /b 1
)

echo.
echo Откроется браузер. Остановить: Ctrl+C в этом окне.
echo.
python -m streamlit run gui\streamlit_app.py

pause
