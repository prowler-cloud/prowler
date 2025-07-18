# Prowler Simple EC2 Deployment Guide

This guide shows how to deploy Prowler on a single AWS EC2 instance using Docker Compose - **no Terraform required**!

## 🚀 Quick Start

1. **Launch EC2 instance** (Ubuntu 24.04 LTS)
2. **Clone and run**: 
   ```bash
   git clone https://github.com/prowler-cloud/prowler.git
   cd prowler
   chmod +x devops/setup-prowler.sh
   ./devops/setup-prowler.sh -t docker -e production -m -b
   ```
3. **Access via**: `http://YOUR_EC2_PUBLIC_IP:3000`

## 📋 Prerequisites

- AWS account with EC2 access
- Basic knowledge of AWS EC2 console

## 🖥️ Step 1: Create EC2 Instance

### 1.1 Launch Instance via AWS Console

1. Go to **EC2 Dashboard** → **Launch Instance**
2. Configure:
   - **Name**: `prowler-server`
   - **OS**: Ubuntu 24.04 LTS (free tier eligible)
   - **Instance Type**: `t3.medium` (minimum recommended)
   - **Key Pair**: Create new or use existing
   - **Security Group**: Create new with these rules:

### 1.2 Security Group Rules

| Type | Port | Source | Description |
|------|------|--------|-------------|
| SSH | 22 | Your IP | SSH access |
| HTTP | 80 | 0.0.0.0/0 | Nginx proxy |
| Custom | 3000 | 0.0.0.0/0 | Prowler UI |
| Custom | 8080 | 0.0.0.0/0 | Prowler API |
| Custom | 3001 | 0.0.0.0/0 | Grafana (optional) |
| Custom | 9090 | 0.0.0.0/0 | Prometheus (optional) |

### 1.3 Storage Configuration

- **Root volume**: 30-50 GB gp3 (recommended)
- **Additional volume**: Optional for backups

## 🔧 Step 2: Connect and Setup

### 2.1 Connect to Instance

```bash
# Connect via SSH
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP

# Or use EC2 Instance Connect from AWS Console
```

### 2.2 Update System

```bash
# Update packages
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y curl git htop unzip
```

## 🐳 Step 3: Install Docker

```bash
# Install Docker using official script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Re-login to apply group changes
exit
# SSH back in
```

## 🚀 Step 4: Deploy Prowler

### 4.1 Clone Repository

```bash
# Clone Prowler
git clone https://github.com/prowler-cloud/prowler.git
cd prowler

# Make setup script executable
chmod +x devops/setup-prowler.sh
```

### 4.2 Run Automated Setup

```bash
# Simple deployment (no monitoring)
./devops/setup-prowler.sh -t docker -e production

# With monitoring (Grafana + Prometheus)
./devops/setup-prowler.sh -t docker -e production -m

# With monitoring and backups
./devops/setup-prowler.sh -t docker -e production -m -b
```

### 4.3 Manual Setup (Alternative)

If you prefer manual control:

```bash
# Create necessary directories
mkdir -p _data/{postgres,valkey,backups,grafana,prometheus}

# Generate environment file
cat > .env << 'EOF'
# Database
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=prowler_db
POSTGRES_ADMIN_USER=prowler
POSTGRES_ADMIN_PASSWORD=$(openssl rand -base64 32)
POSTGRES_USER=prowler_user
POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Cache
VALKEY_HOST=valkey
VALKEY_PORT=6379
VALKEY_DB=0

# Django API
DJANGO_SECRET_KEY=$(openssl rand -base64 50)
DJANGO_ALLOWED_HOSTS=*
DJANGO_DEBUG=False
DJANGO_SETTINGS_MODULE=config.django.production
DJANGO_TOKEN_SIGNING_KEY=$(openssl rand -base64 32)
DJANGO_TOKEN_VERIFYING_KEY=$(openssl rand -base64 32)
DJANGO_SECRETS_ENCRYPTION_KEY=$(openssl rand -base64 32)

# UI
SITE_URL=http://$(curl -s ifconfig.me):3000
API_BASE_URL=http://$(curl -s ifconfig.me):8080/api/v1
AUTH_SECRET=$(openssl rand -base64 32)
EOF

# Start services
docker-compose -f docker-compose.yml up -d
```

## 🌐 Step 5: Access Your Application

### 5.1 Get Your Public IP

```bash
# Get your EC2 public IP
PUBLIC_IP=$(curl -s ifconfig.me)
echo "Your EC2 Public IP: $PUBLIC_IP"
```

### 5.2 Access URLs

```bash
echo "🌐 Prowler Application Access:"
echo "   Web UI: http://$PUBLIC_IP:3000"
echo "   API: http://$PUBLIC_IP:8080"
echo "   API Docs: http://$PUBLIC_IP:8080/api/docs"
echo ""
echo "📊 Monitoring (if enabled):"
echo "   Grafana: http://$PUBLIC_IP:3001"
echo "   Prometheus: http://$PUBLIC_IP:9090"
echo ""
echo "🔧 Admin Access:"
echo "   Username: admin@prowler.local"
echo "   Password: admin@123"
```

## 🔍 Step 6: Verify Deployment

### 6.1 Check Services

```bash
# Check all services are running
docker-compose ps

# Check logs
docker-compose logs -f api
docker-compose logs -f ui
```

### 6.2 Health Checks

```bash
# Test API
curl -f http://localhost:8080/api/health

# Test UI
curl -f http://localhost:3000

# Check database
docker-compose exec postgres pg_isready -U prowler -d prowler_db
```

## 📊 Step 7: Configure Monitoring (Optional)

If you enabled monitoring, access Grafana:

1. Go to `http://YOUR_EC2_IP:3001`
2. Login: `admin` / `admin123`
3. Import Prowler dashboards from `/devops/monitoring/dashboards/`

## 🔧 Step 8: Configuration

### 8.1 Configure Cloud Providers

1. Access UI at `http://YOUR_EC2_IP:3000`
2. Login with admin credentials
3. Go to **Settings** → **Providers**
4. Add your cloud provider credentials (AWS, Azure, GCP)

### 8.2 Environment Variables

Edit the `.env` file to customize:

```bash
# Edit configuration
nano .env

# Restart services to apply changes
docker-compose down && docker-compose up -d
```

## 🔄 Step 9: Backup and Maintenance

### 9.1 Database Backup

```bash
# Manual backup
docker-compose exec postgres pg_dump -U prowler prowler_db > backup_$(date +%Y%m%d).sql

# Automated backup (if enabled)
./devops/scripts/backup.sh
```

### 9.2 System Updates

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Update Prowler
cd prowler
git pull origin main
docker-compose pull
docker-compose up -d
```

### 9.3 Monitoring Resources

```bash
# Check system resources
htop

# Check disk usage
df -h

# Check Docker stats
docker stats
```

## 🛠️ Troubleshooting

### Common Issues

1. **Services not starting**:
   ```bash
   # Check logs
   docker-compose logs
   
   # Restart services
   docker-compose restart
   ```

2. **Port conflicts**:
   ```bash
   # Check what's using ports
   sudo netstat -tlnp | grep :3000
   sudo netstat -tlnp | grep :8080
   ```

3. **Memory issues**:
   ```bash
   # Check memory usage
   free -h
   
   # If low memory, upgrade instance to t3.large
   ```

4. **Database connection issues**:
   ```bash
   # Check database logs
   docker-compose logs postgres
   
   # Restart database
   docker-compose restart postgres
   ```

## 📈 Performance Optimization

### For Better Performance

1. **Upgrade instance type**:
   - t3.large (2 vCPU, 8GB RAM) - recommended
   - t3.xlarge (4 vCPU, 16GB RAM) - for heavy usage

2. **Add swap space**:
   ```bash
   # Create 4GB swap
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

3. **Optimize Docker**:
   ```bash
   # Clean up unused containers and images
   docker system prune -a
   ```

## 🔐 Security Considerations

1. **Update Security Groups**: Restrict SSH access to your IP only
2. **Use SSL**: Consider using Let's Encrypt for HTTPS
3. **Regular Updates**: Keep system and containers updated
4. **Backup Strategy**: Regular automated backups to S3
5. **Monitoring**: Enable CloudWatch monitoring for the EC2 instance

## 💰 Cost Estimation

**Monthly costs (approximate)**:
- EC2 t3.medium: $30-40
- EBS storage (50GB): $5
- Data transfer: $5-10
- **Total**: ~$40-55/month

**vs Full ALB setup**: $200-400/month

## 🎯 Next Steps

1. **Access Prowler**: `http://YOUR_EC2_IP:3000`
2. **Configure providers** (AWS, Azure, GCP credentials)
3. **Run security scans**
4. **Set up compliance frameworks**
5. **Configure notifications** (Slack, email)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/prowler-cloud/prowler/issues)
- **Documentation**: [Prowler Docs](https://docs.prowler.cloud)
- **Community**: [Discord/Slack](https://prowler.cloud/community)

---

**🎉 Congratulations!** You now have a fully functional Prowler deployment on a single EC2 instance without any complex infrastructure setup!