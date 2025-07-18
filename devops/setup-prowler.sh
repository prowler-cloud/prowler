#!/bin/bash

# =================================================================
# Prowler Application Setup & Deployment Script
# =================================================================
# Professional DevOps automation for Prowler security platform
# Supports: Local Development, Docker, Cloud Deployment
# Author: DevOps Engineering Team
# Version: 1.0.0
# =================================================================

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/tmp/prowler_setup_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROWLER_VERSION="5.10.0"
NODE_VERSION="18"
PYTHON_VERSION="3.11"
POSTGRES_VERSION="16"
REDIS_VERSION="7"

# Default values
DEPLOYMENT_TYPE="local"
ENVIRONMENT="development"
DOMAIN="localhost"
ENABLE_SSL=false
ENABLE_MONITORING=false
BACKUP_ENABLED=false
AUTO_SCALE=false

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

spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        error "Command '$1' not found. Please install it first."
    fi
}

generate_password() {
    local length=${1:-32}
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# =================================================================
# SYSTEM REQUIREMENTS CHECK
# =================================================================

check_system_requirements() {
    log "Checking system requirements..."

    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        DISTRO=$(lsb_release -si 2>/dev/null || echo "unknown")
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    else
        error "Unsupported operating system: $OSTYPE"
    fi

    info "Detected OS: $OS ($DISTRO)"

    # Check required tools
    local required_tools=("curl" "git" "docker" "docker-compose")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            warn "$tool not found. Installing..."
            install_tool "$tool"
        else
            info "$tool is installed"
        fi
    done

    # Check Docker
    if ! docker ps &> /dev/null; then
        error "Docker is not running. Please start Docker and try again."
    fi

    # Check available resources
    local available_mem=$(free -m 2>/dev/null | awk 'NR==2{print $7}' || echo "unknown")
    local available_disk=$(df -h . | awk 'NR==2{print $4}' || echo "unknown")
    
    info "Available memory: ${available_mem}MB"
    info "Available disk space: $available_disk"

    if [[ "$available_mem" != "unknown" && "$available_mem" -lt 4000 ]]; then
        warn "Low memory detected. Recommend at least 4GB for optimal performance."
    fi

    log "System requirements check completed"
}

install_tool() {
    local tool="$1"
    
    case "$tool" in
        "docker")
            if [[ "$OS" == "linux" ]]; then
                curl -fsSL https://get.docker.com -o get-docker.sh
                sudo sh get-docker.sh
                sudo usermod -aG docker "$USER"
                rm get-docker.sh
            elif [[ "$OS" == "macos" ]]; then
                error "Please install Docker Desktop for Mac from https://docker.com/products/docker-desktop"
            fi
            ;;
        "docker-compose")
            if [[ "$OS" == "linux" ]]; then
                sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                sudo chmod +x /usr/local/bin/docker-compose
            fi
            ;;
        "curl"|"git")
            if [[ "$OS" == "linux" ]]; then
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update && sudo apt-get install -y "$tool"
                elif command -v yum &> /dev/null; then
                    sudo yum install -y "$tool"
                fi
            elif [[ "$OS" == "macos" ]]; then
                if command -v brew &> /dev/null; then
                    brew install "$tool"
                else
                    error "Please install Homebrew first: https://brew.sh"
                fi
            fi
            ;;
    esac
}

# =================================================================
# CONFIGURATION MANAGEMENT
# =================================================================

generate_configuration() {
    log "Generating configuration files..."

    # Create necessary directories
    mkdir -p "$PROJECT_ROOT/devops/config"
    mkdir -p "$PROJECT_ROOT/devops/scripts"
    mkdir -p "$PROJECT_ROOT/devops/monitoring"
    mkdir -p "$PROJECT_ROOT/_data/postgres"
    mkdir -p "$PROJECT_ROOT/_data/valkey"
    mkdir -p "$PROJECT_ROOT/_data/backups"

    # Generate secrets
    local postgres_password=$(generate_password 24)
    local django_secret=$(generate_password 50)
    local jwt_secret=$(generate_password 32)
    local encryption_key=$(generate_password 32)
    local auth_secret=$(generate_password 32)

    # Generate main .env file
    cat > "$PROJECT_ROOT/.env" << EOF
# =================================================================
# Prowler Application Configuration
# Generated on: $(date)
# Environment: $ENVIRONMENT
# =================================================================

# Application Settings
PROWLER_VERSION=$PROWLER_VERSION
ENVIRONMENT=$ENVIRONMENT
DOMAIN=$DOMAIN
ENABLE_SSL=$ENABLE_SSL

# Django API Settings
DJANGO_ALLOWED_HOSTS=$DOMAIN,localhost,127.0.0.1,api
DJANGO_BIND_ADDRESS=0.0.0.0
DJANGO_PORT=8080
DJANGO_DEBUG=$([[ "$ENVIRONMENT" == "development" ]] && echo "True" || echo "False")
DJANGO_SETTINGS_MODULE=config.django.$([[ "$ENVIRONMENT" == "development" ]] && echo "devel" || echo "production")
DJANGO_LOGGING_FORMATTER=ndjson
DJANGO_LOGGING_LEVEL=$([[ "$ENVIRONMENT" == "development" ]] && echo "DEBUG" || echo "INFO")
DJANGO_WORKERS=4
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
DJANGO_SENTRY_DSN=

# Database Settings
POSTGRES_HOST=postgres-db
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
SITE_URL=http://$DOMAIN:3000
API_BASE_URL=http://$DOMAIN:8080/api/v1
AUTH_TRUST_HOST=true
AUTH_SECRET=$auth_secret

# Docker Image Versions
PROWLER_API_VERSION=stable
PROWLER_UI_VERSION=stable

# Optional: Social Authentication
DJANGO_GOOGLE_OAUTH_CLIENT_ID=
DJANGO_GOOGLE_OAUTH_CLIENT_SECRET=
DJANGO_GOOGLE_OAUTH_CALLBACK_URL=

DJANGO_GITHUB_OAUTH_CLIENT_ID=
DJANGO_GITHUB_OAUTH_CLIENT_SECRET=
DJANGO_GITHUB_OAUTH_CALLBACK_URL=

# Monitoring & Observability
SENTRY_ENVIRONMENT=$ENVIRONMENT
SENTRY_RELEASE=$PROWLER_VERSION

# Performance Tuning
DJANGO_DELETION_BATCH_SIZE=5000

# Backup Configuration
BACKUP_ENABLED=$BACKUP_ENABLED
BACKUP_RETENTION_DAYS=30
BACKUP_S3_BUCKET=
BACKUP_S3_REGION=
EOF

    # Generate Docker override for development
    if [[ "$ENVIRONMENT" == "development" ]]; then
        cat > "$PROJECT_ROOT/docker-compose.override.yml" << EOF
version: '3.8'
services:
  api:
    volumes:
      - ./api:/app/api
      - ./prowler:/app/prowler
    environment:
      - DJANGO_DEBUG=True
      - DJANGO_LOGGING_LEVEL=DEBUG
    ports:
      - "8080:8080"
      - "5678:5678"  # Debug port

  ui:
    volumes:
      - ./ui:/app
      - /app/node_modules
    environment:
      - NODE_ENV=development
    ports:
      - "3000:3000"

  postgres:
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_LOG_STATEMENT=all

  valkey:
    ports:
      - "6379:6379"
EOF
    fi

    # Generate nginx configuration for production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        generate_nginx_config
    fi

    log "Configuration files generated successfully"
}

generate_nginx_config() {
    cat > "$PROJECT_ROOT/devops/config/nginx.conf" << EOF
events {
    worker_connections 1024;
}

http {
    upstream api {
        server api:8080;
    }

    upstream ui {
        server ui:3000;
    }

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone \$binary_remote_addr zone=ui:10m rate=30r/s;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    server {
        listen 80;
        server_name $DOMAIN;

        # API routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://api;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # UI routes
        location / {
            limit_req zone=ui burst=50 nodelay;
            proxy_pass http://ui;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\\n";
        }
    }
}
EOF
}

# =================================================================
# DOCKER SETUP
# =================================================================

setup_docker_environment() {
    log "Setting up Docker environment..."

    cd "$PROJECT_ROOT"

    # Pull latest images
    info "Pulling Docker images..."
    docker-compose pull

    # Build custom images if needed
    if [[ -f "api/Dockerfile" ]]; then
        info "Building API image..."
        docker-compose build api
    fi

    if [[ -f "ui/Dockerfile" ]]; then
        info "Building UI image..."
        docker-compose build ui
    fi

    # Create networks
    docker network create prowler-network 2>/dev/null || true

    log "Docker environment setup completed"
}

# =================================================================
# DATABASE SETUP
# =================================================================

setup_database() {
    log "Setting up database..."

    # Start only PostgreSQL first
    info "Starting PostgreSQL..."
    docker-compose up -d postgres

    # Wait for PostgreSQL to be ready
    info "Waiting for PostgreSQL to be ready..."
    local max_attempts=60
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker-compose exec -T postgres pg_isready -U prowler -d prowler_db &>/dev/null; then
            break
        fi
        sleep 2
        ((attempt++))
    done

    if [[ $attempt -gt $max_attempts ]]; then
        error "PostgreSQL failed to start within expected time"
    fi

    # Run migrations
    info "Running database migrations..."
    docker-compose run --rm api python manage.py migrate --database admin

    # Create superuser if in development
    if [[ "$ENVIRONMENT" == "development" ]]; then
        info "Creating development superuser..."
        docker-compose run --rm api python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(email='admin@prowler.local').exists():
    User.objects.create_superuser('admin@prowler.local', 'admin', 'admin@123')
    print('Superuser created: admin@prowler.local / admin@123')
"
    fi

    log "Database setup completed"
}

# =================================================================
# APPLICATION DEPLOYMENT
# =================================================================

deploy_application() {
    log "Deploying Prowler application..."

    cd "$PROJECT_ROOT"

    # Start all services
    info "Starting all services..."
    docker-compose up -d

    # Wait for all services to be healthy
    info "Waiting for services to be healthy..."
    local services=("postgres" "valkey" "api" "ui")
    
    for service in "${services[@]}"; do
        local max_attempts=30
        local attempt=1
        
        while [[ $attempt -le $max_attempts ]]; do
            if docker-compose ps "$service" | grep -q "healthy\|Up"; then
                info "$service is healthy"
                break
            fi
            sleep 5
            ((attempt++))
        done
        
        if [[ $attempt -gt $max_attempts ]]; then
            warn "$service may not be fully healthy"
        fi
    done

    # Run post-deployment tasks
    info "Running post-deployment tasks..."
    docker-compose exec -T api python manage.py collectstatic --noinput
    docker-compose exec -T api python manage.py check --deploy

    log "Application deployment completed"
}

# =================================================================
# MONITORING & OBSERVABILITY
# =================================================================

setup_monitoring() {
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        log "Setting up monitoring stack..."

        # Create monitoring configuration
        cat > "$PROJECT_ROOT/devops/monitoring/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'prowler-api'
    static_configs:
      - targets: ['api:8080']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'prowler-ui'
    static_configs:
      - targets: ['ui:3000']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:5432']
    scrape_interval: 30s

  - job_name: 'valkey'
    static_configs:
      - targets: ['valkey:6379']
    scrape_interval: 30s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

        # Create monitoring docker-compose
        cat > "$PROJECT_ROOT/devops/monitoring/docker-compose.monitoring.yml" << EOF
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3001:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml

volumes:
  prometheus_data:
  grafana_data:
EOF

        log "Monitoring setup completed"
    fi
}

# =================================================================
# BACKUP SYSTEM
# =================================================================

setup_backup_system() {
    if [[ "$BACKUP_ENABLED" == "true" ]]; then
        log "Setting up backup system..."

        # Create backup script
        cat > "$PROJECT_ROOT/devops/scripts/backup.sh" << 'EOF'
#!/bin/bash

set -euo pipefail

BACKUP_DIR="/tmp/prowler_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
echo "Creating database backup..."
docker-compose exec -T postgres pg_dump -U prowler -d prowler_db > "$BACKUP_DIR/prowler_db_$TIMESTAMP.sql"

# Application data backup
echo "Creating application data backup..."
tar -czf "$BACKUP_DIR/prowler_data_$TIMESTAMP.tar.gz" -C /var/lib/docker/volumes .

# Upload to S3 if configured
if [[ -n "${BACKUP_S3_BUCKET:-}" ]]; then
    echo "Uploading to S3..."
    aws s3 cp "$BACKUP_DIR/prowler_db_$TIMESTAMP.sql" "s3://$BACKUP_S3_BUCKET/backups/database/"
    aws s3 cp "$BACKUP_DIR/prowler_data_$TIMESTAMP.tar.gz" "s3://$BACKUP_S3_BUCKET/backups/data/"
fi

# Clean up old backups
find "$BACKUP_DIR" -name "*.sql" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $TIMESTAMP"
EOF

        chmod +x "$PROJECT_ROOT/devops/scripts/backup.sh"

        # Create restore script
        cat > "$PROJECT_ROOT/devops/scripts/restore.sh" << 'EOF'
#!/bin/bash

set -euo pipefail

BACKUP_FILE="$1"

if [[ -z "$BACKUP_FILE" ]]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Restoring from backup: $BACKUP_FILE"

# Stop services
docker-compose down

# Restore database
echo "Restoring database..."
docker-compose up -d postgres
sleep 10
docker-compose exec -T postgres psql -U prowler -d prowler_db < "$BACKUP_FILE"

# Start services
docker-compose up -d

echo "Restore completed"
EOF

        chmod +x "$PROJECT_ROOT/devops/scripts/restore.sh"

        log "Backup system setup completed"
    fi
}

# =================================================================
# HEALTH CHECKS
# =================================================================

run_health_checks() {
    log "Running health checks..."

    local health_check_url="http://localhost:8080/health"
    local ui_check_url="http://localhost:3000"

    # API health check
    info "Checking API health..."
    local api_attempts=0
    while [[ $api_attempts -lt 30 ]]; do
        if curl -f "$health_check_url" &>/dev/null; then
            info "API is healthy"
            break
        fi
        sleep 5
        ((api_attempts++))
    done

    if [[ $api_attempts -ge 30 ]]; then
        error "API health check failed"
    fi

    # UI health check
    info "Checking UI health..."
    local ui_attempts=0
    while [[ $ui_attempts -lt 30 ]]; do
        if curl -f "$ui_check_url" &>/dev/null; then
            info "UI is healthy"
            break
        fi
        sleep 5
        ((ui_attempts++))
    done

    if [[ $ui_attempts -ge 30 ]]; then
        error "UI health check failed"
    fi

    # Database connectivity check
    info "Checking database connectivity..."
    if docker-compose exec -T postgres pg_isready -U prowler -d prowler_db &>/dev/null; then
        info "Database is accessible"
    else
        error "Database connectivity check failed"
    fi

    # Cache connectivity check
    info "Checking cache connectivity..."
    if docker-compose exec -T valkey valkey-cli ping | grep -q "PONG"; then
        info "Cache is accessible"
    else
        error "Cache connectivity check failed"
    fi

    log "All health checks passed"
}

# =================================================================
# MAIN EXECUTION
# =================================================================

show_usage() {
    cat << EOF
Prowler Application Setup & Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    -t, --type TYPE         Deployment type (local|docker|cloud) [default: local]
    -e, --environment ENV   Environment (development|staging|production) [default: development]
    -d, --domain DOMAIN     Domain name [default: localhost]
    -s, --ssl               Enable SSL/TLS
    -m, --monitoring        Enable monitoring stack
    -b, --backup            Enable backup system
    -a, --auto-scale        Enable auto-scaling (cloud only)
    -h, --help              Show this help message

EXAMPLES:
    $0                                    # Local development setup
    $0 -t docker -e production -d app.example.com -s -m -b
    $0 -t cloud -e production -d app.example.com -s -m -b -a

ENVIRONMENT VARIABLES:
    PROWLER_VERSION         Prowler version to deploy
    POSTGRES_PASSWORD       Custom PostgreSQL password
    DJANGO_SECRET_KEY       Custom Django secret key
    BACKUP_S3_BUCKET        S3 bucket for backups
    BACKUP_S3_REGION        S3 region for backups
EOF
}

main() {
    log "Starting Prowler setup and deployment..."
    log "Logging to: $LOG_FILE"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -d|--domain)
                DOMAIN="$2"
                shift 2
                ;;
            -s|--ssl)
                ENABLE_SSL=true
                shift
                ;;
            -m|--monitoring)
                ENABLE_MONITORING=true
                shift
                ;;
            -b|--backup)
                BACKUP_ENABLED=true
                shift
                ;;
            -a|--auto-scale)
                AUTO_SCALE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done

    # Validate parameters
    if [[ ! "$DEPLOYMENT_TYPE" =~ ^(local|docker|cloud)$ ]]; then
        error "Invalid deployment type: $DEPLOYMENT_TYPE"
    fi

    if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
        error "Invalid environment: $ENVIRONMENT"
    fi

    # Execute setup steps
    check_system_requirements
    generate_configuration
    setup_docker_environment
    setup_database
    deploy_application
    setup_monitoring
    setup_backup_system
    run_health_checks

    # Display completion message
    log "Prowler setup completed successfully!"
    echo ""
    echo "=========================================="
    echo "🎉 Prowler is now running!"
    echo "=========================================="
    echo "📊 Web UI: http://$DOMAIN:3000"
    echo "🔧 API: http://$DOMAIN:8080"
    echo "📋 API Docs: http://$DOMAIN:8080/api/docs"
    echo "=========================================="
    
    if [[ "$ENVIRONMENT" == "development" ]]; then
        echo "🔑 Admin Login: admin@prowler.local / admin@123"
        echo "🗄️  Database: localhost:5432 (prowler/$(grep POSTGRES_ADMIN_PASSWORD "$PROJECT_ROOT/.env" | cut -d'=' -f2))"
        echo "🚀 Cache: localhost:6379"
    fi
    
    if [[ "$ENABLE_MONITORING" == "true" ]]; then
        echo "📈 Grafana: http://$DOMAIN:3001 (admin/admin123)"
        echo "🔍 Prometheus: http://$DOMAIN:9090"
    fi
    
    echo "=========================================="
    echo "📄 Logs: $LOG_FILE"
    echo "🛠️  Config: $PROJECT_ROOT/.env"
    echo "=========================================="
}

# Trap to ensure cleanup on exit
trap 'log "Setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"