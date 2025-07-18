# Prowler Cloud Security Platform - AWS Deployment Guide

This guide provides step-by-step instructions to deploy Prowler on AWS using Ubuntu 24.04 LTS with remote access capabilities.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/prowler-cloud/prowler.git
cd prowler

# Run automated setup
chmod +x devops/setup-prowler.sh
./devops/setup-prowler.sh -t cloud -e production -d your-domain.com -s -m -b -a
```

## 📋 Prerequisites

### Local Requirements
- **Operating System**: Ubuntu 24.04 LTS (or compatible Linux distribution)
- **Memory**: Minimum 8GB RAM (16GB recommended)
- **Storage**: Minimum 50GB free disk space
- **Network**: Stable internet connection
- **Domain**: Registered domain name for remote access

### AWS Requirements
- **AWS Account** with appropriate permissions
- **AWS CLI** configured with access keys
- **Domain Management** (Route 53 or external DNS provider)
- **SSL Certificate** (ACM or Let's Encrypt)

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

### 3. Request SSL Certificate

```bash
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

# Domain Configuration
DOMAIN_NAME=your-domain.com
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012

# Deployment Settings
ENVIRONMENT=production
DEPLOYMENT_TYPE=cloud
ENABLE_SSL=true
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

# Create terraform.tfvars file
cat > terraform.tfvars << EOF
environment = "production"
project_name = "prowler"
domain_name = "$DOMAIN_NAME"
certificate_arn = "$CERTIFICATE_ARN"
enable_auto_scaling = true
min_capacity = 2
max_capacity = 10
db_instance_class = "db.t3.medium"
db_allocated_storage = 100
elasticache_node_type = "cache.t3.micro"
vpc_cidr = "10.0.0.0/16"
EOF

# Plan deployment
terraform plan

# Apply infrastructure
terraform apply -auto-approve

# Note the outputs for later use
terraform output
```

### 4. Configure DNS

```bash
# Get the load balancer DNS name from Terraform output
ALB_DNS=$(terraform output -raw load_balancer_dns)

# Create DNS record (using Route 53 as example)
aws route53 change-resource-record-sets \
    --hosted-zone-id Z1234567890123 \
    --change-batch '{
        "Changes": [
            {
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": "'$DOMAIN_NAME'",
                    "Type": "CNAME",
                    "TTL": 300,
                    "ResourceRecords": [
                        {
                            "Value": "'$ALB_DNS'"
                        }
                    ]
                }
            }
        ]
    }'
```

### 5. Deploy Application

```bash
# Return to project root
cd ../..

# Run automated deployment
./devops/setup-prowler.sh \
    --type cloud \
    --environment production \
    --domain $DOMAIN_NAME \
    --ssl \
    --monitoring \
    --backup \
    --auto-scale
```

## 🌐 Remote Access Setup

### 1. Configure Security Groups

```bash
# Get the security group ID from Terraform
ALB_SG_ID=$(terraform output -raw alb_security_group_id)

# Allow HTTP/HTTPS access from anywhere
aws ec2 authorize-security-group-ingress \
    --group-id $ALB_SG_ID \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
    --group-id $ALB_SG_ID \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0
```

### 2. Configure Application Load Balancer

The Terraform configuration automatically creates an Application Load Balancer with:
- **HTTP to HTTPS redirect** (port 80 → 443)
- **SSL termination** with your ACM certificate
- **Health checks** for both API and UI services
- **Path-based routing** (`/api/*` → API, `/` → UI)

### 3. Test Remote Access

```bash
# Test SSL certificate and connectivity
curl -I https://$DOMAIN_NAME

# Test API endpoint
curl -f https://$DOMAIN_NAME/api/health

# Test UI accessibility
curl -f https://$DOMAIN_NAME
```

## 📊 Monitoring and Observability

### 1. Access Monitoring Dashboards

- **Grafana**: https://your-domain.com:3001
  - Username: `admin`
  - Password: `admin123`
- **Prometheus**: https://your-domain.com:9090
- **Alertmanager**: https://your-domain.com:9093

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

1. **Access the application**: https://your-domain.com
2. **Login with admin credentials** (check deployment logs)
3. **Configure cloud providers** (AWS, Azure, GCP)
4. **Set up scan schedules** and compliance frameworks
5. **Configure integrations** (Slack, Jira, etc.)
6. **Review security findings** and remediation guidance

---

**🔒 Security Note**: Always follow the principle of least privilege when configuring AWS IAM roles and policies. Regularly review and rotate access keys and passwords.

**💡 Pro Tip**: Use AWS Systems Manager Parameter Store or AWS Secrets Manager for sensitive configuration values in production environments.