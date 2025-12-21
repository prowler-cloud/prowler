#!/bin/bash
set -e

echo "🚀 Starting Prowler App..."
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if database containers are running
echo "📦 Checking database containers..."
if ! docker compose ps | grep -q "postgres.*Up.*healthy" || ! docker compose ps | grep -q "valkey.*Up.*healthy"; then
    echo "${YELLOW}Starting database containers...${NC}"
    docker compose up postgres valkey -d
    echo "Waiting for containers to be healthy..."
    sleep 5
fi
echo "${GREEN}✓ Database containers running${NC}"
echo ""

# Run migrations
echo "🔄 Running database migrations..."
cd api/src/backend
set -a && source ../../.env
poetry run python manage.py migrate 2>&1 | grep -E "(Applying|No migrations|Operations)" || true
cd /Users/master/git/prowler
echo "${GREEN}✓ Migrations complete${NC}"
echo ""

# Create logs directory
mkdir -p logs

# Start API server in background
echo "🌐 Starting API server on port 8080..."
cd api/src/backend
set -a && source ../../.env
nohup poetry run python manage.py runserver 0.0.0.0:8080 > /Users/master/git/prowler/logs/api.log 2>&1 &
API_PID=$!
echo "${GREEN}✓ API server started (PID: $API_PID)${NC}"
cd /Users/master/git/prowler
echo ""

# Start Celery worker in background
echo "⚙️  Starting Celery worker..."
cd api/src/backend
set -a && source ../../.env
nohup poetry run celery -A config.celery worker -l info > /Users/master/git/prowler/logs/celery.log 2>&1 &
CELERY_PID=$!
echo "${GREEN}✓ Celery worker started (PID: $CELERY_PID)${NC}"
cd /Users/master/git/prowler
echo ""

# Start UI dev server in background
echo "🎨 Starting UI dev server on port 3000..."
cd ui
nohup npm run dev > /Users/master/git/prowler/logs/ui.log 2>&1 &
UI_PID=$!
echo "${GREEN}✓ UI server started (PID: $UI_PID)${NC}"
cd /Users/master/git/prowler
echo ""

# Save PIDs to file for stopping later
echo "$API_PID" > logs/api.pid
echo "$CELERY_PID" > logs/celery.pid
echo "$UI_PID" > logs/ui.pid

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Prowler App is starting up!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📍 Services:"
echo "   • Web UI:       http://localhost:3000"
echo "   • API:          http://localhost:8080"
echo "   • API Docs:     http://localhost:8080/api/v1/docs"
echo ""
echo "📝 Logs:"
echo "   • API:          tail -f logs/api.log"
echo "   • Celery:       tail -f logs/celery.log"
echo "   • UI:           tail -f logs/ui.log"
echo ""
echo "⏱️  Wait 10-15 seconds for all services to fully start"
echo ""
echo "🛑 To stop all services: ./stop-prowler.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
