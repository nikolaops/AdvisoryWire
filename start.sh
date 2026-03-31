#!/bin/bash

echo "🚀 Starting Security Advisory Notifier"
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ .env file not found!"
    echo "Please copy .env.example to .env and configure your Slack credentials"
    exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running!"
    echo "Please start Docker Desktop and try again"
    exit 1
fi

echo "✓ Environment file found"
echo "✓ Docker is running"
echo ""

# Start application
echo "Starting services..."
docker-compose up --build -d

echo ""
echo "✅ Services started!"
echo ""
echo "📊 Check status:"
echo "   docker-compose ps"
echo ""
echo "📝 View logs:"
echo "   docker-compose logs -f app"
echo ""
echo "🔍 Health check:"
echo "   curl http://localhost:3000/health/ready"
echo ""
echo "🛑 Stop services:"
echo "   docker-compose down"
