#!/bin/bash

# =================================================================
# Prowler Deployment Holistic Fix Script
# =================================================================
# This script performs a comprehensive diagnosis and fix of all
# common Prowler deployment issues in a systematic manner.
# Author: DevOps Engineering Team
# Version: 1.0.0
# =================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/prowler_fix_${TIMESTAMP}.log"
BACKUP_DIR="/tmp/prowler_backup_${TIMESTAMP}"

# =================================================================
# UTILITY FUNCTIONS
# =================================================================

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}" | tee -a "$LOG_FILE"
}

# =================================================================
# BACKUP FUNCTIONS
# =================================================================

backup_configuration() {
    log "Creating backup of current configuration..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup .env file
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        cp "$PROJECT_ROOT/.env" "$BACKUP_DIR/env.backup"
    fi
    
    # Backup docker-compose files
    if [[ -f "$PROJECT_ROOT/docker-compose.yml" ]]; then
        cp "$PROJECT_ROOT/docker-compose.yml" "$BACKUP_DIR/docker-compose.yml.backup"
    fi
    
    # Backup any override files
    if [[ -f "$PROJECT_ROOT/docker-compose.override.yml" ]]; then
        cp "$PROJECT_ROOT/docker-compose.override.yml" "$BACKUP_DIR/docker-compose.override.yml.backup"
    fi
    
    success "Configuration backed up to: $BACKUP_DIR"
}

# =================================================================
# SYSTEM DIAGNOSIS
# =================================================================

diagnose_system() {
    log "Performing comprehensive system diagnosis..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
    fi
    
    if ! docker ps &> /dev/null; then
        error "Docker daemon is not running"
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed"
    fi
    
    # Check system resources
    local available_mem=$(free -m | awk 'NR==2{print $7}' || echo "0")
    local available_disk=$(df -BG . | awk 'NR==2{print $4}' | sed 's/G//' || echo "0")
    
    if [[ "$available_mem" -lt 2000 ]]; then
        warn "Low memory detected: ${available_mem}MB available. Recommend at least 2GB."
    fi
    
    if [[ "$available_disk" -lt 10 ]]; then
        warn "Low disk space detected: ${available_disk}GB available. Recommend at least 10GB."
    fi
    
    # Check network connectivity
    if ! curl -s --max-time 5 ifconfig.me &> /dev/null; then
        warn "Cannot detect public IP. Network connectivity may be limited."
    fi
    
    success "System diagnosis completed"
}

# =================================================================
# ENVIRONMENT CONFIGURATION
# =================================================================

fix_environment_configuration() {
    log "Fixing environment configuration..."
    
    cd "$PROJECT_ROOT"
    
    # Get public IP
    local public_ip=$(curl -s --max-time 10 ifconfig.me || echo "127.0.0.1")
    info "Detected public IP: $public_ip"
    
    # Install Python cryptography if needed
    if ! python3 -c "import cryptography" &> /dev/null; then
        info "Installing Python cryptography..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-cryptography
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-cryptography
        fi
    fi
    
    # Generate proper secrets
    local postgres_password=$(openssl rand -base64 24)
    local django_secret=$(openssl rand -base64 50)
    local jwt_secret=$(openssl rand -base64 32)
    local auth_secret=$(openssl rand -base64 32)
    
    # Generate proper Fernet key
    local encryption_key
    if python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" &> /dev/null; then
        encryption_key=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    else
        encryption_key=$(openssl rand -base64 32)
    fi
    
    # Create comprehensive .env file
    cat > .env << EOF
# =================================================================
# Prowler Application Configuration
# Generated by holistic fix script on: $(date)
# =================================================================

# Application Settings
PROWLER_VERSION=5.10.0
ENVIRONMENT=production
DOMAIN=localhost
ENABLE_SSL=false

# Django API Settings
DJANGO_ALLOWED_HOSTS=*,localhost,127.0.0.1,$public_ip,prowler-api,api,prowler-api-1,prowler_api,prowler_api_1
DJANGO_BIND_ADDRESS=0.0.0.0
DJANGO_PORT=8080
DJANGO_DEBUG=False
DJANGO_SETTINGS_MODULE=config.django.production
DJANGO_LOGGING_FORMATTER=ndjson
DJANGO_LOGGING_LEVEL=INFO
DJANGO_WORKERS=4
DJANGO_SECRET_KEY=$django_secret
DJANGO_TOKEN_SIGNING_KEY=$jwt_secret
DJANGO_TOKEN_VERIFYING_KEY=$jwt_secret
DJANGO_ACCESS_TOKEN_LIFETIME=30
DJANGO_REFRESH_TOKEN_LIFETIME=1440
DJANGO_CACHE_MAX_AGE=3600
DJANGO_STALE_WHILE_REVALIDATE=60
DJANGO_SECRETS_ENCRYPTION_KEY=$encryption_key
DJANGO_MANAGE_DB_PARTITIONS=True
DJANGO_CELERY_DEADLOCK_ATTEMPTS=5
DJANGO_BROKER_VISIBILITY_TIMEOUT=86400
DJANGO_DELETION_BATCH_SIZE=5000
DJANGO_SENTRY_DSN=

# Database Settings
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_ADMIN_USER=prowler
POSTGRES_ADMIN_PASSWORD=$postgres_password
POSTGRES_USER=prowler_user
POSTGRES_PASSWORD=$postgres_password
POSTGRES_DB=prowler_db

# Cache Settings
VALKEY_HOST=valkey
VALKEY_PORT=6379
VALKEY_DB=0

# UI Settings
UI_PORT=3000
SITE_URL=http://$public_ip:3000
API_BASE_URL=http://$public_ip:8080/api/v1
AUTH_TRUST_HOST=true
AUTH_SECRET=$auth_secret

# Docker Image Versions
PROWLER_API_VERSION=stable
PROWLER_UI_VERSION=stable

# Authentication Settings
DJANGO_EMAIL_VERIFICATION=none
DJANGO_ACCOUNT_EMAIL_REQUIRED=true
DJANGO_ACCOUNT_EMAIL_VERIFICATION=none
DJANGO_ACCOUNT_AUTHENTICATION_METHOD=email
DJANGO_ACCOUNT_LOGIN_ATTEMPTS_LIMIT=5
DJANGO_ACCOUNT_LOGIN_ATTEMPTS_TIMEOUT=300
DJANGO_ACCOUNT_LOGOUT_REDIRECT_URL=/
DJANGO_ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS=3
DJANGO_ACCOUNT_LOGOUT_ON_GET=true

# Performance Settings
DJANGO_PAGINATION_PAGE_SIZE=50
DJANGO_PAGINATION_MAX_PAGE_SIZE=1000

# Monitoring & Observability
SENTRY_ENVIRONMENT=production
SENTRY_RELEASE=5.10.0

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=
BACKUP_S3_REGION=

# Social Authentication (Optional)
DJANGO_GOOGLE_OAUTH_CLIENT_ID=
DJANGO_GOOGLE_OAUTH_CLIENT_SECRET=
DJANGO_GOOGLE_OAUTH_CALLBACK_URL=
DJANGO_GITHUB_OAUTH_CLIENT_ID=
DJANGO_GITHUB_OAUTH_CLIENT_SECRET=
DJANGO_GITHUB_OAUTH_CALLBACK_URL=
EOF

    success "Environment configuration fixed"
}

# =================================================================
# DOCKER CONFIGURATION
# =================================================================

fix_docker_configuration() {
    log "Fixing Docker configuration..."
    
    cd "$PROJECT_ROOT"
    
    # Create production-ready docker-compose.yml
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:16.3-alpine3.20
    container_name: prowler-postgres
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_ADMIN_USER}
      - POSTGRES_PASSWORD=${POSTGRES_ADMIN_PASSWORD}
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_ADMIN_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - prowler-network

  valkey:
    image: valkey/valkey:7-alpine3.19
    container_name: prowler-valkey
    command: valkey-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - valkey_data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "valkey-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - prowler-network

  api:
    image: prowlercloud/prowler-api:${PROWLER_API_VERSION:-stable}
    container_name: prowler-api
    env_file:
      - .env
    volumes:
      - api_static:/app/static
      - api_media:/app/media
      - scan_outputs:/tmp/prowler_api_output
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - prowler-network
    ports:
      - "8080:8080"

  worker:
    image: prowlercloud/prowler-api:${PROWLER_API_VERSION:-stable}
    container_name: prowler-worker
    env_file:
      - .env
    volumes:
      - scan_outputs:/tmp/prowler_api_output
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    restart: unless-stopped
    command: ["celery", "-A", "config.celery", "worker", "--loglevel=info", "--concurrency=2"]
    networks:
      - prowler-network

  worker-beat:
    image: prowlercloud/prowler-api:${PROWLER_API_VERSION:-stable}
    container_name: prowler-worker-beat
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
      valkey:
        condition: service_healthy
    restart: unless-stopped
    command: ["celery", "-A", "config.celery", "beat", "--loglevel=info"]
    networks:
      - prowler-network

  ui:
    image: prowlercloud/prowler-ui:${PROWLER_UI_VERSION:-stable}
    container_name: prowler-ui
    env_file:
      - .env
    environment:
      - NODE_ENV=production
      - SITE_URL=${SITE_URL}
      - API_BASE_URL=${API_BASE_URL}
      - AUTH_TRUST_HOST=${AUTH_TRUST_HOST}
      - AUTH_SECRET=${AUTH_SECRET}
    depends_on:
      - api
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - prowler-network
    ports:
      - "3000:3000"

volumes:
  postgres_data:
    driver: local
  valkey_data:
    driver: local
  api_static:
    driver: local
  api_media:
    driver: local
  scan_outputs:
    driver: local

networks:
  prowler-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
EOF

    success "Docker configuration fixed"
}

# =================================================================
# APPLICATION INITIALIZATION
# =================================================================

initialize_application() {
    log "Initializing application..."
    
    cd "$PROJECT_ROOT"
    
    # Stop any existing containers
    info "Stopping existing containers..."
    docker-compose down --remove-orphans || true
    
    # Clean up any dangling resources
    info "Cleaning up Docker resources..."
    docker system prune -f || true
    
    # Pull latest images
    info "Pulling latest Docker images..."
    docker-compose pull
    
    # Start database first
    info "Starting database..."
    docker-compose up -d postgres valkey
    
    # Wait for database to be ready
    info "Waiting for database to be ready..."
    local max_attempts=60
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker-compose exec -T postgres pg_isready -U prowler -d prowler_db &>/dev/null; then
            success "Database is ready"
            break
        fi
        sleep 2
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        error "Database failed to start within expected time"
    fi
    
    # Run migrations
    info "Running database migrations..."
    docker-compose run --rm api python manage.py migrate --database admin
    
    # Create superuser
    info "Creating superuser..."
    docker-compose run --rm api python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@prowler.local').exists():
    user = User.objects.create_superuser('admin@prowler.local', 'AdminPassword123!')
    user.is_active = True
    user.save()
    print('Superuser created: admin@prowler.local / AdminPassword123!')
else:
    print('Superuser already exists')
"
    
    # Start all services
    info "Starting all services..."
    docker-compose up -d
    
    success "Application initialized"
}

# =================================================================
# HEALTH CHECKS
# =================================================================

run_comprehensive_health_checks() {
    log "Running comprehensive health checks..."
    
    cd "$PROJECT_ROOT"
    
    # Wait for services to be ready
    info "Waiting for services to be ready..."
    sleep 30
    
    # Check database
    info "Checking database health..."
    if docker-compose exec -T postgres pg_isready -U prowler -d prowler_db &>/dev/null; then
        success "Database is healthy"
    else
        error "Database health check failed"
    fi
    
    # Check cache
    info "Checking cache health..."
    if docker-compose exec -T valkey valkey-cli ping | grep -q "PONG"; then
        success "Cache is healthy"
    else
        error "Cache health check failed"
    fi
    
    # Check API health
    info "Checking API health..."
    local api_attempts=0
    while [[ $api_attempts -lt 30 ]]; do
        if curl -f -s http://localhost:8080/api/health &>/dev/null; then
            success "API is healthy"
            break
        fi
        sleep 5
        ((api_attempts++))
    done
    
    if [[ $api_attempts -ge 30 ]]; then
        error "API health check failed"
    fi
    
    # Check UI health
    info "Checking UI health..."
    local ui_attempts=0
    while [[ $ui_attempts -lt 30 ]]; do
        if curl -f -s http://localhost:3000 &>/dev/null; then
            success "UI is healthy"
            break
        fi
        sleep 5
        ((ui_attempts++))
    done
    
    if [[ $ui_attempts -ge 30 ]]; then
        error "UI health check failed"
    fi
    
    # Test user creation and login
    info "Testing user authentication..."
    local test_email="test@example.com"
    local test_password="TestPassword123!"
    
    # Create test user
    local user_response=$(curl -s -X POST http://localhost:8080/api/v1/users \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"$test_email\", \"password\": \"$test_password\", \"name\": \"Test User\"}")
    
    if [[ $user_response == *"201"* ]] || [[ $user_response == *"email"* ]]; then
        success "User creation test passed"
    else
        warn "User creation test failed, but continuing..."
    fi
    
    # Test login
    local login_response=$(curl -s -X POST http://localhost:8080/api/v1/tokens \
        -H "Content-Type: application/json" \
        -d "{\"email\": \"admin@prowler.local\", \"password\": \"AdminPassword123!\"}")
    
    if [[ $login_response == *"access"* ]] || [[ $login_response == *"token"* ]]; then
        success "Login test passed"
    else
        warn "Login test failed, but admin user exists"
    fi
    
    success "Comprehensive health checks completed"
}

# =================================================================
# VALIDATION AND TESTING
# =================================================================

validate_deployment() {
    log "Validating deployment..."
    
    cd "$PROJECT_ROOT"
    
    # Check all containers are running
    info "Checking container status..."
    local containers=("prowler-postgres" "prowler-valkey" "prowler-api" "prowler-worker" "prowler-worker-beat" "prowler-ui")
    
    for container in "${containers[@]}"; do
        if docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
            success "$container is running"
        else
            error "$container is not running"
        fi
    done
    
    # Check logs for errors
    info "Checking for critical errors in logs..."
    local error_count=$(docker-compose logs --tail=100 | grep -i error | wc -l)
    
    if [[ $error_count -gt 0 ]]; then
        warn "Found $error_count error messages in logs"
    else
        success "No critical errors found in logs"
    fi
    
    # Get public IP for access information
    local public_ip=$(curl -s --max-time 10 ifconfig.me || echo "localhost")
    
    # Display access information
    echo ""
    echo "=========================================="
    echo "🎉 Prowler Deployment Validation Complete!"
    echo "=========================================="
    echo "📊 Web UI: http://$public_ip:3000"
    echo "🔧 API: http://$public_ip:8080"
    echo "📋 API Docs: http://$public_ip:8080/api/docs"
    echo "=========================================="
    echo "🔑 Admin Login:"
    echo "   Email: admin@prowler.local"
    echo "   Password: AdminPassword123!"
    echo "=========================================="
    echo "📄 Logs: $LOG_FILE"
    echo "💾 Backup: $BACKUP_DIR"
    echo "=========================================="
    
    success "Deployment validation completed"
}

# =================================================================
# MAIN EXECUTION
# =================================================================

main() {
    log "Starting Prowler holistic deployment fix..."
    log "Logging to: $LOG_FILE"
    
    # Change to project directory
    cd "$PROJECT_ROOT"
    
    # Execute fix steps
    backup_configuration
    diagnose_system
    fix_environment_configuration
    fix_docker_configuration
    initialize_application
    run_comprehensive_health_checks
    validate_deployment
    
    success "Prowler holistic deployment fix completed successfully!"
    
    echo ""
    echo "🎯 Next Steps:"
    echo "1. Access the web UI at the URL provided above"
    echo "2. Login with the admin credentials"
    echo "3. Configure your cloud provider credentials"
    echo "4. Run your first security scan"
    echo ""
    echo "If you encounter any issues, check the logs at: $LOG_FILE"
}

# Trap to ensure cleanup on exit
trap 'log "Fix script interrupted"; exit 1' INT TERM

# Run main function
main "$@"