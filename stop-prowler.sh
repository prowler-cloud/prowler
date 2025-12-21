#!/bin/bash

echo "🛑 Stopping Prowler App..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Kill processes if PID files exist
if [ -f logs/api.pid ]; then
    API_PID=$(cat logs/api.pid)
    if ps -p $API_PID > /dev/null 2>&1; then
        echo "Stopping API server (PID: $API_PID)..."
        kill $API_PID 2>/dev/null || true
        echo "${GREEN}✓ API server stopped${NC}"
    fi
    rm logs/api.pid
fi

if [ -f logs/celery.pid ]; then
    CELERY_PID=$(cat logs/celery.pid)
    if ps -p $CELERY_PID > /dev/null 2>&1; then
        echo "Stopping Celery worker (PID: $CELERY_PID)..."
        kill $CELERY_PID 2>/dev/null || true
        echo "${GREEN}✓ Celery worker stopped${NC}"
    fi
    rm logs/celery.pid
fi

if [ -f logs/ui.pid ]; then
    UI_PID=$(cat logs/ui.pid)
    if ps -p $UI_PID > /dev/null 2>&1; then
        echo "Stopping UI server (PID: $UI_PID)..."
        kill $UI_PID 2>/dev/null || true
        echo "${GREEN}✓ UI server stopped${NC}"
    fi
    rm logs/ui.pid
fi

# Also kill any stray processes
echo "Cleaning up any remaining processes..."
pkill -f "manage.py runserver" 2>/dev/null || true
pkill -f "celery.*config.celery" 2>/dev/null || true
pkill -f "next-server" 2>/dev/null || true

echo ""
echo "${GREEN}✓ All Prowler services stopped${NC}"
echo ""
echo "Database containers are still running."
echo "To stop them: docker compose down"
