@echo off
echo ========================================
echo Phishing URL Checker - Setup
echo ========================================
echo.

if exist venv (
    echo Virtual environment already exists.
    echo Skipping venv creation...
) else (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment.
        echo Please make sure Python is installed and in your PATH.
        pause
        exit /b 1
    )
)

echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

if errorlevel 1 (
    echo Error: Failed to activate virtual environment.
    pause
    exit /b 1
)

echo.
echo Upgrading pip...
python -m pip install --upgrade pip

echo.
echo Installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

echo.
echo ========================================
echo Setup complete!
echo ========================================
echo.
echo To run the application, use:
echo   run.bat
echo.
echo Or manually activate and run:
echo   venv\Scripts\activate
echo   python app.py
echo.

pause

