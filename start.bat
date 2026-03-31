@echo off
echo Starting Security Advisory Notifier
echo.

REM Check if .env exists
if not exist .env (
    echo ERROR: .env file not found!
    echo Please copy .env.example to .env and configure your Slack credentials
    exit /b 1
)

echo [OK] Environment file found
echo.

echo Starting services with Docker Compose...
docker-compose up --build -d

echo.
echo Services started!
echo.
echo Check status:
echo   docker-compose ps
echo.
echo View logs:
echo   docker-compose logs -f app
echo.
echo Health check:
echo   curl http://localhost:3000/health/ready
echo.
echo Stop services:
echo   docker-compose down
echo.
pause
