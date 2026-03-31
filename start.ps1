Write-Host "🚀 Starting Security Advisory Notifier" -ForegroundColor Cyan
Write-Host ""

# Check if .env exists
if (!(Test-Path .env)) {
    Write-Host "❌ .env file not found!" -ForegroundColor Red
    Write-Host "Please copy .env.example to .env and configure your Slack credentials" -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ Environment file found" -ForegroundColor Green

# Check if Docker is running
try {
    docker info *>$null
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and try again" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Starting services..." -ForegroundColor Cyan
docker-compose up --build -d

Write-Host ""
Write-Host "✅ Services started!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Check status:" -ForegroundColor Yellow
Write-Host "   docker-compose ps"
Write-Host ""
Write-Host "📝 View logs:" -ForegroundColor Yellow
Write-Host "   docker-compose logs -f app"
Write-Host ""
Write-Host "🔍 Health check:" -ForegroundColor Yellow
Write-Host "   curl http://localhost:3000/health/ready"
Write-Host ""
Write-Host "🛑 Stop services:" -ForegroundColor Yellow
Write-Host "   docker-compose down"
Write-Host ""
