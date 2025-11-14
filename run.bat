@echo off
if not exist venv (
    echo Error: Virtual environment not found!
    echo Please run setup.bat first to create the virtual environment.
    pause
    exit /b 1
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

if errorlevel 1 (
    echo Error: Failed to activate virtual environment.
    pause
    exit /b 1
)

echo.
echo Starting Phishing URL Checker...
echo Server will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server.
echo.
python app.py

