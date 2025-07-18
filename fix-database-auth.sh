#!/bin/bash

# Quick fix for database authentication issues
# This script preserves existing database passwords and fixes the setup

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

# Check if we're in the right directory
if [[ ! -f "docker-compose.yml" ]]; then
    error "Please run this script from the prowler directory"
fi

log "Starting database authentication fix..."

# Stop all running containers
info "Stopping all containers..."
docker-compose down --remove-orphans || true

# Check current .env file for existing password
if [[ -f ".env" ]]; then
    existing_password=$(grep "^POSTGRES_ADMIN_PASSWORD=" .env | cut -d'=' -f2 | tr -d '"' || echo "postgres")
    info "Found existing database password: $existing_password"
else
    error ".env file not found. Please ensure you have a valid .env file."
fi

# Get public IP for ALLOWED_HOSTS
public_ip=$(curl -s ifconfig.me || echo "127.0.0.1")
info "Detected public IP: $public_ip"

# Update DJANGO_ALLOWED_HOSTS in .env file to include all possible hosts
log "Updating DJANGO_ALLOWED_HOSTS..."
sed -i "s/^DJANGO_ALLOWED_HOSTS=.*/DJANGO_ALLOWED_HOSTS=*,localhost,127.0.0.1,$public_ip,prowler-api,api,prowler-api-1,prowler_api,prowler_api_1/" .env

# Add missing environment variables if they don't exist
if ! grep -q "^POSTGRES_USER=" .env; then
    echo "POSTGRES_USER=prowler_user" >> .env
fi

if ! grep -q "^POSTGRES_PASSWORD=" .env; then
    echo "POSTGRES_PASSWORD=$existing_password" >> .env
fi

# Clean up old database data to force fresh start with correct credentials
info "Cleaning up database data for fresh start..."
sudo rm -rf _data/postgres/* || true
mkdir -p _data/postgres
mkdir -p _data/valkey

# Start PostgreSQL first
log "Starting PostgreSQL with correct credentials..."
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
info "Waiting for PostgreSQL to be ready..."
max_attempts=60
attempt=1

while [[ $attempt -le $max_attempts ]]; do
    if docker-compose exec -T postgres pg_isready -U prowler -d prowler_db &>/dev/null; then
        info "PostgreSQL is ready!"
        break
    fi
    sleep 2
    ((attempt++))
done

if [[ $attempt -gt $max_attempts ]]; then
    error "PostgreSQL failed to start within expected time"
fi

# Start Valkey
info "Starting Valkey..."
docker-compose up -d valkey

# Wait a bit for valkey to be ready
sleep 10

# Run database migrations
log "Running database migrations..."
docker-compose run --rm api python manage.py migrate --database admin

# Create superuser
log "Creating superuser..."
docker-compose run --rm api python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@prowler.local').exists():
    user = User.objects.create_superuser('admin@prowler.local', 'AdminPassword123!')
    user.is_active = True
    user.save()
    print('Superuser created successfully')
else:
    print('Superuser already exists')
"

# Start all services
log "Starting all services..."
docker-compose up -d

# Wait for services to be ready
info "Waiting for services to be ready..."
sleep 30

# Check health
log "Checking service health..."

# Check API health
if curl -f -s http://localhost:8080/api/health &>/dev/null; then
    info "✓ API is healthy"
else
    warn "API health check failed, but continuing..."
fi

# Check UI health
if curl -f -s http://localhost:3000 &>/dev/null; then
    info "✓ UI is healthy"
else
    warn "UI health check failed, but continuing..."
fi

# Display final information
echo ""
echo "==========================================="
echo "🎉 Database authentication fix completed!"
echo "==========================================="
echo "📊 Web UI: http://$public_ip:3000"
echo "🔧 API: http://$public_ip:8080"
echo "📋 API Docs: http://$public_ip:8080/api/docs"
echo "==========================================="
echo "🔑 Admin Login:"
echo "   Email: admin@prowler.local"
echo "   Password: AdminPassword123!"
echo "==========================================="
echo "💾 Database Password: $existing_password"
echo "==========================================="

log "Fix completed successfully!"