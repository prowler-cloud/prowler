# Prowler Cloud Security Platform - AWS Deployment Guide

This guide provides step-by-step instructions to deploy Prowler on AWS using Ubuntu 24.04 LTS with remote access capabilities.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/prowler-cloud/prowler.git
cd prowler

# Run automated setup (IP-based access)
chmod +x devops/setup-prowler.sh
./devops/setup-prowler.sh -t cloud -e production -m -b -a
```

## 📋 Prerequisites

### Local Requirements
- **Operating System**: Ubuntu 24.04 LTS (or compatible Linux distribution)
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: Minimum 50GB free disk space
- **Network**: Stable internet connection

### AWS Requirements
- **AWS Account** with appropriate permissions
- **AWS CLI** configured with access keys
- **EC2 Key Pair** for SSH access (optional)

### Optional Requirements
- **Domain**: Registered domain name (only if you want custom domain access)
- **SSL Certificate** (ACM or Let's Encrypt - only for custom domains)

## 🛠️ System Setup

### 1. Update Ubuntu System

```bash
# Update package lists and upgrade system
sudo apt update && sudo apt upgrade -y

# Install essential packages
sudo apt install -y curl git wget unzip software-properties-common
```

### 2. Install Docker

```bash
# Install Docker using official script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

### 3. Install AWS CLI

```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

### 4. Install Terraform

```bash
# Add HashiCorp GPG key and repository
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

# Install Terraform
sudo apt update && sudo apt install -y terraform

# Verify installation
terraform --version
```

## 🔧 AWS Configuration

### 1. Configure AWS Credentials

```bash
# Configure AWS CLI with your credentials
aws configure

# Input your AWS credentials:
# AWS Access Key ID: [Your Access Key]
# AWS Secret Access Key: [Your Secret Key]  
# Default region name: us-east-1 (or your preferred region)
# Default output format: json
```

### 2. Create S3 Bucket for Terraform State (Optional but Recommended)

```bash
# Create S3 bucket for Terraform state
aws s3 mb s3://prowler-terraform-state-$(date +%s) --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning --bucket prowler-terraform-state-$(date +%s) --versioning-configuration Status=Enabled
```

### 3. Request SSL Certificate (Optional - For Custom Domains)

```bash
# Only needed if you want to use a custom domain
# Request SSL certificate through ACM
aws acm request-certificate \
    --domain-name your-domain.com \
    --subject-alternative-names "*.your-domain.com" \
    --validation-method DNS \
    --region us-east-1

# Note the certificate ARN for later use
```

## 🚀 Deployment Process

### 1. Clone and Setup Repository

```bash
# Clone the Prowler repository
git clone https://github.com/prowler-cloud/prowler.git
cd prowler

# Make setup script executable
chmod +x devops/setup-prowler.sh
```

### 2. Configure Environment Variables

```bash
# Create deployment configuration
cat > deployment.env << EOF
# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Deployment Settings
ENVIRONMENT=production
DEPLOYMENT_TYPE=cloud
ENABLE_SSL=false
ENABLE_MONITORING=true
BACKUP_ENABLED=true
AUTO_SCALE=true

# Database Configuration
DB_INSTANCE_CLASS=db.t3.medium
DB_ALLOCATED_STORAGE=100

# Cache Configuration
ELASTICACHE_NODE_TYPE=cache.t3.micro

# Scaling Configuration
MIN_CAPACITY=2
MAX_CAPACITY=10

# Optional: Custom Domain Configuration (uncomment if using domain)
# DOMAIN_NAME=your-domain.com
# CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012
# ENABLE_SSL=true
EOF

# Load environment variables
source deployment.env
```

### 3. Deploy Infrastructure with Terraform

```bash
# Navigate to Terraform directory
cd devops/terraform

# Initialize Terraform
terraform init

# Create terraform.tfvars file (IP-based access)
cat > terraform.tfvars << EOF
environment = "production"
project_name = "prowler"
domain_name = "prowler.local"
certificate_arn = ""
enable_auto_scaling = true
min_capacity = 2
max_capacity = 10
db_instance_class = "db.t3.medium"
db_allocated_storage = 100
elasticache_node_type = "cache.t3.micro"
vpc_cidr = "10.0.0.0/16"
EOF

# If using custom domain, override with:
# cat > terraform.tfvars << EOF
# environment = "production"
# project_name = "prowler"
# domain_name = "$DOMAIN_NAME"
# certificate_arn = "$CERTIFICATE_ARN"
# enable_auto_scaling = true
# min_capacity = 2
# max_capacity = 10
# db_instance_class = "db.t3.medium"
# db_allocated_storage = 100
# elasticache_node_type = "cache.t3.micro"
# vpc_cidr = "10.0.0.0/16"
# EOF

# Plan deployment
terraform plan

# Apply infrastructure
terraform apply -auto-approve

# Note the outputs for later use
terraform output
```

### 4. Get Application Access Information

```bash
# Get the load balancer DNS name from Terraform output
ALB_DNS=$(terraform output -raw load_balancer_dns)

# Get the load balancer public IP (for direct IP access)
ALB_IP=$(nslookup $ALB_DNS | grep "Address:" | tail -1 | cut -d' ' -f2)

echo "=============================================="
echo "🌐 Application Access Information"
echo "=============================================="
echo "Load Balancer DNS: $ALB_DNS"
echo "Load Balancer IP: $ALB_IP"
echo "Web UI: http://$ALB_DNS (or http://$ALB_IP)"
echo "API: http://$ALB_DNS/api (or http://$ALB_IP/api)"
echo "=============================================="

# Optional: Configure DNS if using custom domain
# aws route53 change-resource-record-sets \
#     --hosted-zone-id Z1234567890123 \
#     --change-batch '{
#         "Changes": [
#             {
#                 "Action": "UPSERT",
#                 "ResourceRecordSet": {
#                     "Name": "'$DOMAIN_NAME'",
#                     "Type": "CNAME",
#                     "TTL": 300,
#                     "ResourceRecords": [
#                         {
#                             "Value": "'$ALB_DNS'"
#                         }
#                     ]
#                 }
#             }
#         ]
#     }'
```

### 5. Deploy Application

```bash
# Return to project root
cd ../..

# Run automated deployment (IP-based access)
./devops/setup-prowler.sh \
    --type cloud \
    --environment production \
    --monitoring \
    --backup \
    --auto-scale

# If using custom domain, use:
# ./devops/setup-prowler.sh \
#     --type cloud \
#     --environment production \
#     --domain $DOMAIN_NAME \
#     --ssl \
#     --monitoring \
#     --backup \
#     --auto-scale
```

## 🌐 Remote Access Setup

### 1. Configure Security Groups

```bash
# Get the security group ID from Terraform
ALB_SG_ID=$(terraform output -raw alb_security_group_id)

# Allow HTTP access from anywhere (no SSL required)
aws ec2 authorize-security-group-ingress \
    --group-id $ALB_SG_ID \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0

# Optional: Allow HTTPS access if using custom domain with SSL
# aws ec2 authorize-security-group-ingress \
#     --group-id $ALB_SG_ID \
#     --protocol tcp \
#     --port 443 \
#     --cidr 0.0.0.0/0
```

### 2. Configure Application Load Balancer

The Terraform configuration automatically creates an Application Load Balancer with:
- **HTTP access** on port 80 (no SSL required)
- **Health checks** for both API and UI services
- **Path-based routing** (`/api/*` → API, `/` → UI)
- **Public IP access** via AWS Load Balancer

### 3. Test Remote Access

```bash
# Get application URLs
ALB_DNS=$(terraform output -raw load_balancer_dns)
ALB_IP=$(nslookup $ALB_DNS | grep "Address:" | tail -1 | cut -d' ' -f2)

# Test API endpoint (using DNS)
curl -f http://$ALB_DNS/api/health

# Test API endpoint (using IP)
curl -f http://$ALB_IP/api/health

# Test UI accessibility (using DNS)
curl -f http://$ALB_DNS

# Test UI accessibility (using IP) 
curl -f http://$ALB_IP

echo "✅ Access your Prowler application at:"
echo "   🌐 http://$ALB_DNS"
echo "   🌐 http://$ALB_IP"
```

## 📊 Monitoring and Observability

### 1. Access Monitoring Dashboards

```bash
# Get Load Balancer DNS/IP for monitoring access
ALB_DNS=$(terraform output -raw load_balancer_dns)
ALB_IP=$(nslookup $ALB_DNS | grep "Address:" | tail -1 | cut -d' ' -f2)

echo "📊 Monitoring Dashboard Access:"
echo "- Grafana: http://$ALB_DNS:3001 (or http://$ALB_IP:3001)"
echo "  Username: admin"
echo "  Password: admin123"
echo "- Prometheus: http://$ALB_DNS:9090 (or http://$ALB_IP:9090)"
echo "- Alertmanager: http://$ALB_DNS:9093 (or http://$ALB_IP:9093)"
```

### 2. CloudWatch Integration

```bash
# Create CloudWatch dashboard
aws cloudwatch put-dashboard \
    --dashboard-name "Prowler-Production" \
    --dashboard-body '{
        "widgets": [
            {
                "type": "metric",
                "properties": {
                    "metrics": [
                        ["AWS/ECS", "CPUUtilization", "ServiceName", "prowler-prod-api"],
                        ["AWS/ECS", "MemoryUtilization", "ServiceName", "prowler-prod-api"]
                    ],
                    "period": 300,
                    "stat": "Average",
                    "region": "us-east-1",
                    "title": "ECS Service Metrics"
                }
            }
        ]
    }'
```

## 🔐 Security Best Practices

### 1. Configure WAF (Web Application Firewall)

```bash
# Create WAF Web ACL
aws wafv2 create-web-acl \
    --name prowler-waf \
    --scope REGIONAL \
    --default-action Allow={} \
    --rules '[
        {
            "Name": "RateLimitRule",
            "Priority": 1,
            "Statement": {
                "RateBasedStatement": {
                    "Limit": 2000,
                    "AggregateKeyType": "IP"
                }
            },
            "Action": {
                "Block": {}
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": true,
                "CloudWatchMetricsEnabled": true,
                "MetricName": "RateLimitRule"
            }
        }
    ]'
```

### 2. Enable VPC Flow Logs

```bash
# Enable VPC Flow Logs
VPC_ID=$(terraform output -raw vpc_id)
aws ec2 create-flow-logs \
    --resource-type VPC \
    --resource-ids $VPC_ID \
    --traffic-type ALL \
    --log-destination-type cloud-watch-logs \
    --log-group-name /aws/vpc/flowlogs
```

## 🔄 Backup and Recovery

### 1. Automated Backups

The deployment includes automated backup system:
- **Database snapshots** every 6 hours
- **Application data backup** daily
- **S3 cross-region replication** for disaster recovery
- **30-day retention policy** for backups

### 2. Manual Backup

```bash
# Create manual backup
docker-compose exec -T postgres pg_dump -U prowler -d prowler_db > backup_$(date +%Y%m%d).sql

# Upload to S3
aws s3 cp backup_$(date +%Y%m%d).sql s3://prowler-backups/manual/
```

## 🔧 Maintenance and Updates

### 1. Update Application

```bash
# Pull latest changes
git pull origin main

# Rebuild and redeploy
./devops/setup-prowler.sh \
    --type cloud \
    --environment production \
    --domain $DOMAIN_NAME \
    --ssl \
    --monitoring \
    --backup \
    --auto-scale
```

### 2. Scale Resources

```bash
# Scale ECS services
aws ecs update-service \
    --cluster prowler-prod-cluster \
    --service prowler-prod-api \
    --desired-count 4

# Scale RDS instance
aws rds modify-db-instance \
    --db-instance-identifier prowler-prod-postgres \
    --db-instance-class db.t3.large \
    --apply-immediately
```

## 🆘 Troubleshooting

### Common Issues

1. **SSL Certificate Validation**
   ```bash
   # Check certificate status
   aws acm describe-certificate --certificate-arn $CERTIFICATE_ARN
   ```

2. **ECS Service Health**
   ```bash
   # Check service status
   aws ecs describe-services \
       --cluster prowler-prod-cluster \
       --services prowler-prod-api prowler-prod-ui
   ```

3. **Database Connectivity**
   ```bash
   # Test database connection
   docker-compose exec -T postgres pg_isready -U prowler -d prowler_db
   ```

4. **Load Balancer Health**
   ```bash
   # Check target group health
   aws elbv2 describe-target-health \
       --target-group-arn $(terraform output -raw api_target_group_arn)
   ```

### Logs and Debugging

```bash
# View application logs
aws logs tail /ecs/prowler-prod-api --follow

# View load balancer access logs
aws s3 ls s3://prowler-alb-logs/

# Debug container issues
docker-compose logs -f api
```

## 📞 Support

- **Documentation**: [Prowler Official Docs](https://docs.prowler.cloud)
- **Community**: [GitHub Discussions](https://github.com/prowler-cloud/prowler/discussions)
- **Issues**: [GitHub Issues](https://github.com/prowler-cloud/prowler/issues)

## 🎯 Next Steps

After successful deployment:

1. **Access the application**: Use the Load Balancer DNS or IP address from Terraform output
   ```bash
   # Get your application URL
   ALB_DNS=$(terraform output -raw load_balancer_dns)
   echo "🌐 Access Prowler at: http://$ALB_DNS"
   ```

2. **Login with admin credentials** (check deployment logs for credentials)
3. **Configure cloud providers** (AWS, Azure, GCP)
4. **Set up scan schedules** and compliance frameworks
5. **Configure integrations** (Slack, Jira, etc.)
6. **Review security findings** and remediation guidance

---

## 🔑 Default Access Information

After deployment, you can access Prowler using:

```bash
# Get your application access details
ALB_DNS=$(terraform output -raw load_balancer_dns)
ALB_IP=$(nslookup $ALB_DNS | grep "Address:" | tail -1 | cut -d' ' -f2)

echo "🌐 Prowler Web Application:"
echo "   DNS: http://$ALB_DNS"
echo "   IP:  http://$ALB_IP"
echo ""
echo "🔧 API Endpoints:"
echo "   DNS: http://$ALB_DNS/api"
echo "   IP:  http://$ALB_IP/api"
echo ""
echo "📊 Monitoring (if enabled):"
echo "   Grafana: http://$ALB_DNS:3001"
echo "   Prometheus: http://$ALB_DNS:9090"
```

**🔒 Security Note**: 
- This deployment uses HTTP (port 80) for simplicity - suitable for testing and internal networks
- For production use with internet access, consider implementing SSL/TLS with a custom domain
- Always follow the principle of least privilege when configuring AWS IAM roles and policies
- Regularly review and rotate access keys and passwords

**💡 Pro Tip**: Use AWS Systems Manager Parameter Store or AWS Secrets Manager for sensitive configuration values in production environments.