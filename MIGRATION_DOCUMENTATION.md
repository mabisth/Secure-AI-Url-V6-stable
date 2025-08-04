# SecureURL AI - Platform Migration Documentation

## Application Overview
SecureURL AI is a full-stack e-skimming protection and malicious URL detection platform with:
- **Frontend**: React.js application with Tailwind CSS
- **Backend**: FastAPI (Python) with comprehensive security analysis
- **Database**: MongoDB Atlas (cloud-hosted) for scan results and analytics
- **Architecture**: Microservices with DNS analysis, ML models, and threat intelligence

### Current Enhanced Features (2025 Version)
- **Enhanced E-Skimming Detection**: Comprehensive security assessment with 18+ detailed fields
- **Advanced Technical Details**: 26+ fields across 4 categories (Server, Geographic, Performance, Technologies)
- **Comprehensive SSL Analysis**: Protocol support detection for all SSL/TLS versions
- **Domain Intelligence**: Geographic intelligence with country information, flags, and risk assessment
- **Authentication System**: Secure login with role-based access (superuser: `ohm` / `admin`)
- **Company Management**: Registration and tracking system for organizations
- **Bulk Scanning**: Multiple URL analysis with job tracking
- **MongoDB Atlas Integration**: Cloud-hosted database with automatic backups

### Latest Updates (Current Deployment)
- **Database**: Migrated to MongoDB Atlas (cloud-hosted)
- **Enhanced Analysis**: All security analysis modules significantly expanded
- **Authentication**: Updated superuser credentials for security
- **Performance**: Optimized for comprehensive threat intelligence gathering

---

# 1. Raspberry Pi Deployment

## System Requirements
- Raspberry Pi 4 Model B (4GB+ RAM recommended, 8GB preferred for enhanced features)
- 64GB+ microSD card (Class 10 or better) - increased for enhanced analysis capabilities
- Raspberry Pi OS (64-bit) or Ubuntu Server
- Stable internet connection (required for MongoDB Atlas and threat intelligence APIs)
- Python 3.9+ (required for enhanced ML models and security analysis)
- Node.js 16+ (for React frontend with enhanced UI components)

## Performance Requirements for Enhanced Features
- **CPU**: Raspberry Pi 4 recommended due to comprehensive analysis workload
- **Memory**: 4GB minimum, 8GB recommended for optimal performance with all enhanced features
- **Storage**: Additional space needed for ML models and enhanced analysis capabilities
- **Network**: Stable broadband connection for real-time threat intelligence and MongoDB Atlas

## Advantages of Using MongoDB Atlas with Raspberry Pi
- **Reliability**: Managed database with automatic backups and high availability
- **Scalability**: Database can grow independently of Pi hardware limitations
- **Maintenance**: No database administration on the Pi
- **Security**: Enterprise-grade security with Atlas
- **Global Access**: Database accessible from anywhere for development/debugging
- **Resource Savings**: Frees up Pi CPU and memory for application processing

## Installation Steps

### 1.1 Initial Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required system packages (removed mongodb as we'll use Atlas)
sudo apt install -y python3 python3-pip python3-venv nodejs npm git supervisor nginx
```

### 1.2 MongoDB Atlas Setup (Current Configuration)
The application is already configured to use MongoDB Atlas with the following details:

#### Current Database Configuration:
- **Cluster**: `cluster0.gqdf26i.mongodb.net`
- **Database Name**: `secureurl_db`
- **Username**: `parasafe`
- **Connection**: Already configured and tested

#### If you need to set up your own MongoDB Atlas cluster:
1. **Sign up for MongoDB Atlas**: Go to [https://cloud.mongodb.com](https://cloud.mongodb.com) and create a free account
2. **Create a new cluster**:
   - Choose "Build a Database"
   - Select "Shared" (Free tier - M0 Sandbox, supports up to 512MB)
   - Choose your preferred cloud provider and region (closest to your Pi location)
   - Name your cluster (e.g., "secureurl-pi-cluster")

3. **Create Database User**:
   - Go to "Database Access" in the left sidebar
   - Click "Add New Database User"
   - Choose "Password" authentication
   - Username: `secureurl_admin`
   - Password: Generate a strong password
   - Database User Privileges: "Read and write to any database"

4. **Configure Network Access**:
   - Go to "Network Access" in the left sidebar
   - Click "Add IP Address"
   - Add your Raspberry Pi's public IP address
   - For development: You can temporarily use `0.0.0.0/0` (not recommended for production)

5. **Get Connection String**:
   - Go to "Database" and click "Connect" on your cluster
   - Choose "Connect your application"
   - Select "Python" and version "3.6 or later"
   - Copy the connection string and replace `<password>` with your actual password

#### Note: 
The current deployment uses an existing Atlas cluster. If you're deploying on your own Pi, you can either:
- Use the existing cluster (ensure your Pi's IP is whitelisted)
- Create your own Atlas cluster following the steps above
- Set up a local MongoDB instance (not recommended due to resource constraints)

### 1.3 Application Deployment
```bash
# Create application directory
sudo mkdir -p /opt/secureurl
sudo chown pi:pi /opt/secureurl
cd /opt/secureurl

# Clone or copy application files
git clone <your-repo-url> .
# OR copy files from current deployment

# Backend setup with enhanced dependencies
cd backend
python3 -m venv venv
source venv/bin/activate

# Install enhanced requirements (includes ML models, threat intelligence, etc.)
pip install -r requirements.txt

# The current requirements.txt includes:
# - FastAPI with comprehensive security analysis
# - MongoDB Atlas connectivity (pymongo[srv], motor)
# - ML libraries (scikit-learn, numpy) for enhanced analysis  
# - Security analysis libraries (requests, dnspython, whois)
# - Enhanced SSL analysis capabilities
# - Threat intelligence integration libraries

# Frontend setup with enhanced UI components
cd ../frontend
# Use yarn instead of npm for better dependency management
npm install -g yarn
yarn install
yarn build

# The build includes:
# - Enhanced React components for comprehensive analysis display
# - Tailwind CSS for modern UI design
# - Comprehensive security analysis visualization
# - Authentication and company management interfaces
```

#### Important: Enhanced Features Dependencies
The current version includes several enhanced features that require additional system resources:
- **ML Models**: Pre-trained models for phishing and malware detection
- **SSL Analysis**: Comprehensive certificate and protocol analysis
- **Threat Intelligence**: Real-time threat feed integration
- **Geographic Intelligence**: IP-based location and risk assessment

### 1.4 Environment Configuration
```bash
# Backend environment
# Use the current MongoDB Atlas credentials that are configured in the system
cat > /opt/secureurl/backend/.env << EOF
MONGO_URL=mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority
DB_NAME=secureurl_db
PORT=8001
ENVIRONMENT=production
EOF

# Frontend environment
# Replace with your Raspberry Pi's actual IP address
cat > /opt/secureurl/frontend/.env << EOF
REACT_APP_BACKEND_URL=http://your-pi-ip:8001
EOF
```

#### Important Notes:
- **Database**: The application is configured to use MongoDB Atlas (cloud-hosted) with the connection string above
- **Authentication**: The application has a superuser account with username `ohm` and password `admin`
- **Database Name**: The application uses `secureurl_db` as the database name in MongoDB Atlas
- **Enhanced Features**: The current version includes comprehensive e-skimming detection, enhanced SSL analysis, technical details analysis, and domain intelligence

#### Verify Atlas Connection
Make sure your Raspberry Pi's IP address is added to the MongoDB Atlas Network Access whitelist:
1. Go to [MongoDB Atlas](https://cloud.mongodb.com)
2. Navigate to Network Access
3. Add your Raspberry Pi's public IP address
4. Or temporarily use `0.0.0.0/0` for testing (not recommended for production)

#### Update Backend Requirements
Since we're using MongoDB Atlas, we need to ensure the MongoDB driver supports SSL connections:

```bash
# Check if your requirements.txt includes the latest pymongo
cd /opt/secureurl/backend
echo "pymongo[srv]>=4.0.0" >> requirements.txt
echo "dnspython>=2.0.0" >> requirements.txt

# Reinstall requirements with Atlas support
source venv/bin/activate
pip install -r requirements.txt
```

### 1.5 Supervisor Configuration
```bash
# Create supervisor configs
sudo cat > /etc/supervisor/conf.d/secureurl-backend.conf << EOF
[program:secureurl-backend]
command=/opt/secureurl/backend/venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8001
directory=/opt/secureurl/backend
user=pi
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/secureurl-backend.log
EOF

sudo cat > /etc/supervisor/conf.d/secureurl-frontend.conf << EOF
[program:secureurl-frontend]
command=/usr/bin/npx serve -s build -p 3000
directory=/opt/secureurl/frontend
user=pi
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/supervisor/secureurl-frontend.log
EOF
```

### 1.6 Nginx Configuration
```bash
sudo cat > /etc/nginx/sites-available/secureurl << EOF
server {
    listen 80;
    server_name your-pi-ip;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /api {
        proxy_pass http://localhost:8001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/secureurl /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 1.7 Start Services
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start all

# Check service status
sudo supervisorctl status

# View logs if needed
sudo tail -f /var/log/supervisor/secureurl-backend.log
sudo tail -f /var/log/supervisor/secureurl-frontend.log
```

### 1.8 Testing the Deployment
```bash
# Test backend API health
curl http://localhost:8001/api/health

# Test backend stats endpoint
curl http://localhost:8001/api/stats

# Test authentication with current credentials
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "ohm", "password": "admin"}'

# Test enhanced URL scanning
curl -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com", "scan_type": "detailed"}' | jq '.'

# Test frontend (should return HTML)
curl http://localhost:3000

# Test full application in browser
# Open browser and go to http://your-pi-ip
# Login with: username=ohm, password=admin
# Try scanning a URL to test all enhanced features
```

#### Expected Enhanced Features in Testing:
When testing the application, you should see:
- **Comprehensive E-Skimming Analysis**: Security assessment, risk factors, detailed breakdown
- **Enhanced Technical Details**: Server info, geographic data, performance metrics, technologies
- **Advanced SSL Analysis**: Protocol support detection, certificate analysis, security grading
- **Domain Intelligence**: Country information, flags, risk levels, popularity scores
- **Authentication System**: Secure login with role-based access
- **Company Management**: Registration and tracking capabilities

### 1.9 MongoDB Atlas Connection Verification
```bash
# Test MongoDB connection from the Pi using current credentials
cd /opt/secureurl/backend
source venv/bin/activate
python3 -c "
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

async def test_connection():
    # Use the current MongoDB Atlas connection string
    mongo_url = 'mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority'
    client = AsyncIOMotorClient(mongo_url)
    try:
        # Test the connection
        await client.admin.command('ping')
        print('✅ MongoDB Atlas connection successful!')
        
        # Test database access
        db = client.secureurl_db
        collections = await db.list_collection_names()
        print(f'📁 Available collections in secureurl_db: {collections}')
        
        # Check if there are any scan results
        scan_count = await db.scan_results.count_documents({})
        print(f'📊 Total scans in database: {scan_count}')
        
        # Verify superuser exists
        user = await db.users.find_one({'username': 'ohm'})
        if user:
            print(f'👤 Superuser found: username={user[\"username\"]}, role={user[\"role\"]}')
        else:
            print('⚠️  Superuser not found - will be created on first backend startup')
        
    except Exception as e:
        print(f'❌ MongoDB Atlas connection failed: {e}')
    finally:
        client.close()

asyncio.run(test_connection())
"
```

### Application-Specific Testing
```bash
# Test the enhanced features that have been implemented
# Test backend health and authentication
curl -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "ohm", "password": "admin"}'

# Test URL scanning with enhanced features
curl -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com", "scan_type": "detailed"}'

# Check that enhanced features are working:
# - E-skimming detection evidence (comprehensive analysis)
# - Enhanced technical details (26+ fields)
# - Enhanced SSL analysis (protocol support detection) 
# - Enhanced domain intelligence (geographic information)
```

## Raspberry Pi Specific Considerations

### Performance Optimization for Enhanced Features
```bash
# Increase GPU memory split for better performance with enhanced analysis
sudo raspi-config
# Advanced Options -> Memory Split -> Set to 256 (increased for ML processing)

# Optimize swap space for enhanced analysis workload
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=100/CONF_SWAPSIZE=2048/g' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon

# Optimize CPU governor for performance
echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Add to /boot/config.txt for permanent settings:
echo "# Performance optimizations for SecureURL AI enhanced features" | sudo tee -a /boot/config.txt
echo "gpu_mem=256" | sudo tee -a /boot/config.txt
echo "arm_freq=1800" | sudo tee -a /boot/config.txt
echo "over_voltage=2" | sudo tee -a /boot/config.txt

# Create performance monitoring for enhanced features
sudo apt install htop iotop -y
```

### Memory Management for Enhanced Analysis
```bash
# Configure system for enhanced security analysis workload
cat > /opt/secureurl/optimize.sh << 'EOF'
#!/bin/bash
# SecureURL AI Performance Optimization Script

echo "=== SecureURL AI Performance Optimization ==="
echo "Optimizing system for enhanced security analysis..."

# Clear page cache
sudo sh -c 'echo 1 > /proc/sys/vm/drop_caches'

# Optimize for analysis workload
sudo sysctl -w vm.swappiness=10
sudo sysctl -w vm.vfs_cache_pressure=50
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400

echo "✅ Performance optimization complete"
EOF

chmod +x /opt/secureurl/optimize.sh

# Run optimization on boot
(crontab -l 2>/dev/null; echo "@reboot /opt/secureurl/optimize.sh") | crontab -
```

### Monitoring and Maintenance for Enhanced Features
```bash
# Create a comprehensive monitoring script for enhanced features
cat > /opt/secureurl/monitor.sh << 'EOF'
#!/bin/bash
echo "=== SecureURL AI Enhanced System Status ==="
echo "Date: $(date)"
echo ""

echo "=== System Resources ==="
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
echo "Memory Usage: $(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
echo "Disk Usage: $(df -h | awk '$NF=="/"{printf "%s", $5}')"
echo "Temperature: $(/opt/vc/bin/vcgencmd measure_temp | cut -d= -f2)"
echo "Swap Usage: $(free -m | awk 'NR==3{printf "%.1f%%", $3*100/$2 }')"
echo ""

echo "=== Service Status ==="
sudo supervisorctl status
echo ""

echo "=== Application Health Check ==="
echo "Backend API Health: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8001/api/health || echo 'Failed')"
echo "Backend Stats: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:8001/api/stats || echo 'Failed')"
echo "Frontend: $(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 || echo 'Failed')"
echo ""

echo "=== Database Connection ==="
cd /opt/secureurl/backend && source venv/bin/activate
DB_STATUS=$(python3 -c "
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test_db():
    try:
        client = AsyncIOMotorClient('mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority')
        await client.admin.command('ping')
        db = client.secureurl_db
        scan_count = await db.scan_results.count_documents({})
        user_count = await db.users.count_documents({})
        client.close()
        return f'✅ Connected - Scans: {scan_count}, Users: {user_count}'
    except Exception as e:
        return f'❌ Failed: {str(e)[:50]}'

print(asyncio.run(test_db()))
" 2>/dev/null)
echo "MongoDB Atlas: $DB_STATUS"
echo ""

echo "=== Enhanced Features Status ==="
echo "Authentication Test: $(curl -s -X POST http://localhost:8001/api/auth/login -H 'Content-Type: application/json' -d '{"username":"ohm","password":"admin"}' | grep -o 'session_token' >/dev/null && echo '✅ Working' || echo '❌ Failed')"
echo "Enhanced Scanning: $(curl -s -X POST http://localhost:8001/api/scan -H 'Content-Type: application/json' -d '{"url":"https://google.com","scan_type":"detailed"}' | grep -o 'e_skimming_analysis' >/dev/null && echo '✅ Enhanced features active' || echo '❌ Basic mode only')"
echo ""

echo "=== Recent Errors (Last 50 lines) ==="
sudo tail -n 50 /var/log/supervisor/secureurl-backend.log | grep -i error | tail -n 5
echo ""
EOF

chmod +x /opt/secureurl/monitor.sh

# Add to cron for regular comprehensive checks (every 4 hours)
(crontab -l 2>/dev/null; echo "0 */4 * * * /opt/secureurl/monitor.sh >> /var/log/secureurl-monitor.log") | crontab -

# Create log rotation for monitoring
sudo cat > /etc/logrotate.d/secureurl << EOF
/var/log/secureurl-monitor.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 pi pi
}
EOF
```

### Database Maintenance and Backup
```bash
# Create MongoDB Atlas backup verification script
cat > /opt/secureurl/backup-check.sh << 'EOF'
#!/bin/bash
echo "=== MongoDB Atlas Backup Status ==="
echo "Note: MongoDB Atlas provides automatic backups for all clusters"
echo "- Continuous backups with point-in-time recovery"
echo "- Backup retention: 7 days for free tier, customizable for paid tiers"
echo "- Backups are stored in cloud provider's storage (encrypted)"
echo ""

# Check database health and size
cd /opt/secureurl/backend && source venv/bin/activate
python3 -c "
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def check_db_stats():
    try:
        client = AsyncIOMotorClient('mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority')
        db = client.secureurl_db
        
        # Get collection stats
        collections = await db.list_collection_names()
        print(f'📁 Collections: {collections}')
        
        for collection_name in collections:
            count = await db[collection_name].count_documents({})
            print(f'📊 {collection_name}: {count} documents')
        
        # Get database stats
        stats = await db.command('dbStats')
        print(f'💾 Database size: {stats[\"dataSize\"]/1024/1024:.2f} MB')
        print(f'🗂️  Index size: {stats[\"indexSize\"]/1024/1024:.2f} MB')
        
        client.close()
        print('✅ Database health check complete')
    except Exception as e:
        print(f'❌ Database check failed: {e}')

asyncio.run(check_db_stats())
"
EOF

chmod +x /opt/secureurl/backup-check.sh

# Run backup check weekly
(crontab -l 2>/dev/null; echo "0 2 * * 0 /opt/secureurl/backup-check.sh >> /var/log/secureurl-backup.log") | crontab -
```

### Security Hardening for Enhanced Features
```bash
# Enable firewall with specific rules for SecureURL AI
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 8001/tcp

# Optional: Allow specific IP ranges only (replace with your actual IP range)
# sudo ufw delete allow 80/tcp
# sudo ufw allow from 192.168.1.0/24 to any port 80

# Disable unnecessary services for security and performance
sudo systemctl disable bluetooth
sudo systemctl disable hciuart
sudo systemctl disable avahi-daemon  # Disable network discovery
sudo systemctl disable triggerhappy  # Disable GPIO event daemon

# Enhanced boot configuration for security and performance
echo "# SecureURL AI Security and Performance Settings" | sudo tee -a /boot/config.txt
echo "dtoverlay=disable-wifi" | sudo tee -a /boot/config.txt  # If using Ethernet
echo "dtoverlay=disable-bt" | sudo tee -a /boot/config.txt
echo "disable_splash=1" | sudo tee -a /boot/config.txt
echo "boot_delay=0" | sudo tee -a /boot/config.txt

# Set up automatic security updates
sudo apt install unattended-upgrades apt-listchanges -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure SSH security
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# Create fail2ban configuration for enhanced security
sudo apt install fail2ban -y
sudo cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[secureurl-api]
enabled = true
port = 8001
filter = secureurl-api
logpath = /var/log/supervisor/secureurl-backend.log
maxretry = 5
EOF

# Create custom fail2ban filter for API abuse
sudo cat > /etc/fail2ban/filter.d/secureurl-api.conf << EOF
[Definition]
failregex = ^.*"POST /api/.*" 4[0-9][0-9].*$
            ^.*"POST /api/auth/login.*" 401.*$
ignoreregex =
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Application-Specific Security Configuration
```bash
# Create security configuration for SecureURL AI
cat > /opt/secureurl/security-config.sh << 'EOF'
#!/bin/bash
echo "=== SecureURL AI Security Configuration ==="

# Set proper file permissions
chown -R pi:pi /opt/secureurl
chmod 750 /opt/secureurl
chmod 640 /opt/secureurl/backend/.env
chmod 640 /opt/secureurl/frontend/.env
chmod 755 /opt/secureurl/*.sh

# Set up log rotation for application logs
sudo tee /etc/logrotate.d/secureurl-app << EOL
/var/log/supervisor/secureurl-*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0644 pi pi
    postrotate
        sudo supervisorctl restart all
    endscript
}
EOL

# Create application firewall rules
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 8001/tcp
sudo ufw enable

echo "✅ Security configuration complete"
EOF

chmod +x /opt/secureurl/security-config.sh
sudo /opt/secureurl/security-config.sh
```

---

# 2. Microsoft Azure Deployment

## Azure Resources Needed
- Azure Container Instances or App Service
- Azure Database for MongoDB (Cosmos DB)
- Azure Load Balancer
- Azure Storage Account

## Deployment Options

### Option A: Azure App Service

### 2.1 Create Azure Resources
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login

# Create resource group
az group create --name secureurl-rg --location eastus

# Create Cosmos DB (MongoDB API)
az cosmosdb create \
  --resource-group secureurl-rg \
  --name secureurl-cosmos \
  --kind MongoDB \
  --default-consistency-level Session

# Get connection string
az cosmosdb keys list --type connection-strings \
  --resource-group secureurl-rg \
  --name secureurl-cosmos
```

### 2.2 Backend App Service
```bash
# Create App Service Plan
az appservice plan create \
  --resource-group secureurl-rg \
  --name secureurl-plan \
  --sku B2 \
  --is-linux

# Create backend app
az webapp create \
  --resource-group secureurl-rg \
  --plan secureurl-plan \
  --name secureurl-backend \
  --runtime "PYTHON|3.9"

# Configure app settings
az webapp config appsettings set \
  --resource-group secureurl-rg \
  --name secureurl-backend \
  --settings MONGO_URL="<cosmos-connection-string>"
```

### 2.3 Frontend App Service
```bash
# Create frontend app
az webapp create \
  --resource-group secureurl-rg \
  --plan secureurl-plan \
  --name secureurl-frontend \
  --runtime "NODE|16-lts"

# Configure app settings
az webapp config appsettings set \
  --resource-group secureurl-rg \
  --name secureurl-frontend \
  --settings REACT_APP_BACKEND_URL="https://secureurl-backend.azurewebsites.net"
```

### 2.4 Deployment Files

**Backend startup.txt:**
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

**Frontend startup.txt:**
```bash
npm install
npm run build
npx serve -s build -p 8080
```

### Option B: Azure Container Instances

### 2.5 Docker Configuration
```dockerfile
# Backend Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 8001
CMD ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
```

```dockerfile
# Frontend Dockerfile
FROM node:16-alpine
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build
RUN npm install -g serve
EXPOSE 3000
CMD ["serve", "-s", "build", "-p", "3000"]
```

### 2.6 Deploy with ACI
```bash
# Create container registry
az acr create --resource-group secureurl-rg --name secureurlregistry --sku Basic
az acr login --name secureurlregistry

# Build and push images
docker build -t secureurlregistry.azurecr.io/secureurl-backend:latest ./backend
docker build -t secureurlregistry.azurecr.io/secureurl-frontend:latest ./frontend
docker push secureurlregistry.azurecr.io/secureurl-backend:latest
docker push secureurlregistry.azurecr.io/secureurl-frontend:latest

# Deploy containers
az container create \
  --resource-group secureurl-rg \
  --name secureurl-backend \
  --image secureurlregistry.azurecr.io/secureurl-backend:latest \
  --registry-login-server secureurlregistry.azurecr.io \
  --ports 8001 \
  --environment-variables MONGO_URL="<cosmos-connection-string>"

az container create \
  --resource-group secureurl-rg \
  --name secureurl-frontend \
  --image secureurlregistry.azurecr.io/secureurl-frontend:latest \
  --registry-login-server secureurlregistry.azurecr.io \
  --ports 3000 \
  --environment-variables REACT_APP_BACKEND_URL="http://<backend-ip>:8001"
```

---

# 3. Google Cloud Platform (GCP) Deployment

## GCP Services Used
- Google Kubernetes Engine (GKE) or Cloud Run
- Cloud MongoDB Atlas or Firestore
- Cloud Load Balancer
- Container Registry

### 3.1 Initial Setup
```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Option A: Cloud Run Deployment

### 3.2 Database Setup (MongoDB Atlas)
```bash
# Create MongoDB Atlas cluster (via web console)
# Get connection string for later use
```

### 3.3 Build and Deploy Backend
```bash
# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Build backend image
cd backend
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/secureurl-backend

# Deploy to Cloud Run
gcloud run deploy secureurl-backend \
  --image gcr.io/YOUR_PROJECT_ID/secureurl-backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars MONGO_URL="<mongodb-atlas-connection-string>"
```

### 3.4 Build and Deploy Frontend
```bash
# Build frontend image
cd frontend
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/secureurl-frontend

# Deploy to Cloud Run
gcloud run deploy secureurl-frontend \
  --image gcr.io/YOUR_PROJECT_ID/secureurl-frontend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars REACT_APP_BACKEND_URL="<backend-cloud-run-url>"
```

### Option B: GKE Deployment

### 3.5 Create GKE Cluster
```bash
gcloud container clusters create secureurl-cluster \
  --num-nodes 3 \
  --zone us-central1-a \
  --machine-type e2-medium
```

### 3.6 Kubernetes Manifests
```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureurl-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secureurl-backend
  template:
    metadata:
      labels:
        app: secureurl-backend
    spec:
      containers:
      - name: backend
        image: gcr.io/YOUR_PROJECT_ID/secureurl-backend:latest
        ports:
        - containerPort: 8001
        env:
        - name: MONGO_URL
          value: "<mongodb-connection-string>"
---
apiVersion: v1
kind: Service
metadata:
  name: secureurl-backend-service
spec:
  selector:
    app: secureurl-backend
  ports:
  - port: 80
    targetPort: 8001
  type: LoadBalancer
```

```yaml
# frontend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureurl-frontend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secureurl-frontend
  template:
    metadata:
      labels:
        app: secureurl-frontend
    spec:
      containers:
      - name: frontend
        image: gcr.io/YOUR_PROJECT_ID/secureurl-frontend:latest
        ports:
        - containerPort: 3000
        env:
        - name: REACT_APP_BACKEND_URL
          value: "<backend-service-external-ip>:80"
---
apiVersion: v1
kind: Service
metadata:
  name: secureurl-frontend-service
spec:
  selector:
    app: secureurl-frontend
  ports:
  - port: 80
    targetPort: 3000
  type: LoadBalancer
```

### 3.7 Deploy to GKE
```bash
kubectl apply -f backend-deployment.yaml
kubectl apply -f frontend-deployment.yaml

# Get external IPs
kubectl get services
```

---

# 4. Amazon Web Services (AWS) Deployment

## AWS Services Used
- ECS (Elastic Container Service) or EC2
- DocumentDB (MongoDB compatible) or EC2 MongoDB
- Application Load Balancer
- ECR (Elastic Container Registry)

### Option A: ECS Deployment

### 4.1 Initial Setup
```bash
# Install AWS CLI
pip install awscli
aws configure
```

### 4.2 Create DocumentDB Cluster
```bash
# Create DocumentDB subnet group
aws docdb create-db-subnet-group \
  --db-subnet-group-name secureurl-subnet-group \
  --db-subnet-group-description "SecureURL DocumentDB subnet group" \
  --subnet-ids subnet-12345 subnet-67890

# Create DocumentDB cluster
aws docdb create-db-cluster \
  --db-cluster-identifier secureurl-docdb \
  --engine docdb \
  --master-username admin \
  --master-user-password SecurePassword123 \
  --db-subnet-group-name secureurl-subnet-group
```

### 4.3 ECR Setup
```bash
# Create ECR repositories
aws ecr create-repository --repository-name secureurl-backend
aws ecr create-repository --repository-name secureurl-frontend

# Get login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
```

### 4.4 Build and Push Images
```bash
# Build and tag backend
cd backend
docker build -t secureurl-backend .
docker tag secureurl-backend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/secureurl-backend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/secureurl-backend:latest

# Build and tag frontend
cd frontend
docker build -t secureurl-frontend .
docker tag secureurl-frontend:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/secureurl-frontend:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/secureurl-frontend:latest
```

### 4.5 ECS Task Definitions
```json
{
  "family": "secureurl-backend",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<account-id>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "secureurl-backend",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/secureurl-backend:latest",
      "portMappings": [
        {
          "containerPort": 8001,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "MONGO_URL",
          "value": "mongodb://admin:SecurePassword123@secureurl-docdb.cluster-xyz.docdb.amazonaws.com:27017/url_security_db"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/secureurl-backend",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### 4.6 Create ECS Cluster and Services
```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name secureurl-cluster

# Register task definitions
aws ecs register-task-definition --cli-input-json file://backend-task-definition.json
aws ecs register-task-definition --cli-input-json file://frontend-task-definition.json

# Create services
aws ecs create-service \
  --cluster secureurl-cluster \
  --service-name secureurl-backend-service \
  --task-definition secureurl-backend:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345,subnet-67890],securityGroups=[sg-12345],assignPublicIp=ENABLED}"
```

### Option B: EC2 Deployment

### 4.7 Launch EC2 Instance
```bash
# Create security group
aws ec2 create-security-group \
  --group-name secureurl-sg \
  --description "SecureURL security group"

# Add rules
aws ec2 authorize-security-group-ingress \
  --group-name secureurl-sg \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name secureurl-sg \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-name secureurl-sg \
  --protocol tcp \
  --port 8001 \
  --cidr 0.0.0.0/0

# Launch instance
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --count 1 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-groups secureurl-sg
```

### 4.8 EC2 Instance Setup
```bash
# SSH into instance
ssh -i your-key.pem ec2-user@<instance-ip>

# Install Docker
sudo yum update -y
sudo yum install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 4.9 Docker Compose for EC2
```yaml
# docker-compose.yml
version: '3.8'
services:
  mongodb:
    image: mongo:5.0
    restart: always
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: SecurePassword123
    volumes:
      - mongodb_data:/data/db

  backend:
    build: ./backend
    restart: always
    ports:
      - "8001:8001"
    environment:
      - MONGO_URL=mongodb://admin:SecurePassword123@mongodb:27017/url_security_db?authSource=admin
    depends_on:
      - mongodb

  frontend:
    build: ./frontend
    restart: always
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_BACKEND_URL=http://<instance-public-ip>:8001
    depends_on:
      - backend

  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - frontend
      - backend

volumes:
  mongodb_data:
```

---

# Configuration Notes

## Environment Variables
Ensure these are set for each platform:
- `MONGO_URL`: Database connection string
- `REACT_APP_BACKEND_URL`: Backend API URL
- `PORT`: Application port (default: 8001 for backend, 3000 for frontend)

## Security Considerations
1. **Database Security**: Use strong passwords and enable authentication
2. **Network Security**: Configure firewalls and security groups
3. **SSL/TLS**: Enable HTTPS with proper certificates
4. **Environment Variables**: Store sensitive data securely
5. **Regular Updates**: Keep system and dependencies updated

## Monitoring and Logging
1. **Application Logs**: Configure centralized logging
2. **Performance Monitoring**: Set up metrics collection
3. **Health Checks**: Implement endpoint monitoring
4. **Alerts**: Configure alerts for critical issues

## Backup Strategy
1. **Database Backups**: Regular automated backups
2. **Application Code**: Version control and deployment artifacts
3. **Configuration**: Backup environment configurations
4. **Recovery Testing**: Regular disaster recovery testing

---

## Troubleshooting Common Issues (Enhanced Version)

### Backend Service Issues
```bash
# Check enhanced backend service status and logs
sudo supervisorctl status secureurl-backend
sudo tail -f /var/log/supervisor/secureurl-backend.log

# Common issues and solutions:

# 1. MongoDB Atlas Connection Issues
echo "Testing MongoDB Atlas connection..."
cd /opt/secureurl/backend && source venv/bin/activate
python3 -c "
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test_connection():
    try:
        client = AsyncIOMotorClient('mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority')
        result = await client.admin.command('ping')
        print('✅ MongoDB Atlas: Connected successfully')
        
        # Test database access
        db = client.secureurl_db
        collections = await db.list_collection_names()
        print(f'✅ Collections accessible: {len(collections)} found')
        
        client.close()
    except Exception as e:
        print(f'❌ MongoDB Atlas connection failed: {e}')
        print('🔧 Check: Internet connection, IP whitelist, credentials')

asyncio.run(test_connection())
"

# 2. Enhanced Features Memory Issues
echo "Checking system resources for enhanced features..."
FREE_MEM=$(free -m | awk 'NR==2{print $7}')
if [ $FREE_MEM -lt 1000 ]; then
    echo "⚠️  Low memory detected ($FREE_MEM MB free)"
    echo "🔧 Consider: Increasing swap, reducing analysis depth, restarting services"
fi

# 3. SSL Analysis Issues (new feature)
echo "Testing SSL analysis capabilities..."
curl -s -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","scan_type":"detailed"}' | \
  grep -o '"supported_protocols"' >/dev/null && \
  echo "✅ Enhanced SSL analysis: Working" || \
  echo "❌ Enhanced SSL analysis: Failed"

# 4. Authentication Issues
echo "Testing authentication with current credentials..."
AUTH_RESPONSE=$(curl -s -X POST http://localhost:8001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"ohm","password":"admin"}')
echo $AUTH_RESPONSE | grep -q "session_token" && \
  echo "✅ Authentication: Working (username: ohm, password: admin)" || \
  echo "❌ Authentication: Failed - check credentials or backend logs"
```

### Enhanced Features Troubleshooting
```bash
# Create comprehensive diagnostic script
cat > /opt/secureurl/diagnose.sh << 'EOF'
#!/bin/bash
echo "=== SecureURL AI Enhanced Features Diagnostic ==="
echo ""

# Check if all enhanced analysis components are working
echo "=== Enhanced Features Status ==="

# Test E-Skimming Analysis
ESKIMMING_TEST=$(curl -s -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","scan_type":"e_skimming"}' | \
  grep -o '"security_assessment"' | wc -l)
echo "E-Skimming Analysis: $([ $ESKIMMING_TEST -gt 0 ] && echo '✅ Enhanced' || echo '❌ Basic only')"

# Test Technical Details
TECH_TEST=$(curl -s -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","scan_type":"detailed"}' | \
  grep -o '"web_server_version\|geographic_location\|performance"' | wc -l)
echo "Technical Details: $([ $TECH_TEST -gt 2 ] && echo '✅ Enhanced (26+ fields)' || echo '❌ Basic only')"

# Test SSL Analysis
SSL_TEST=$(curl -s -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","scan_type":"detailed"}' | \
  grep -o '"supported_protocols\|active_protocols"' | wc -l)
echo "SSL Analysis: $([ $SSL_TEST -gt 1 ] && echo '✅ Enhanced (Protocol detection)' || echo '❌ Basic only')"

# Test Domain Intelligence
DOMAIN_TEST=$(curl -s -X POST http://localhost:8001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com","scan_type":"detailed"}' | \
  grep -o '"country_flag\|country_risk_level\|geographic"' | wc -l)
echo "Domain Intelligence: $([ $DOMAIN_TEST -gt 2 ] && echo '✅ Enhanced (Geographic data)' || echo '❌ Basic only')"

echo ""
echo "=== System Resources for Enhanced Features ==="
echo "Memory Usage: $(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
echo "CPU Load: $(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1)"
echo "Disk Usage: $(df -h | awk '$NF=="/"{printf "%s", $5}')"
echo "Temperature: $(/opt/vc/bin/vcgencmd measure_temp 2>/dev/null | cut -d= -f2 || echo 'N/A')"
echo ""

echo "=== Common Issues and Solutions ==="
if [ $ESKIMMING_TEST -eq 0 ]; then
    echo "🔧 E-Skimming: Check backend logs for import errors or restart backend"
fi
if [ $TECH_TEST -lt 2 ]; then
    echo "🔧 Technical Details: Verify network connectivity and DNS resolution"
fi
if [ $SSL_TEST -lt 1 ]; then
    echo "🔧 SSL Analysis: Check Python SSL libraries and certificate validation"
fi
if [ $DOMAIN_TEST -lt 2 ]; then
    echo "🔧 Domain Intelligence: Verify whois and DNS lookup capabilities"
fi

echo ""
echo "=== Performance Recommendations ==="
FREE_MEM=$(free -m | awk 'NR==2{print $7}')
if [ $FREE_MEM -lt 1000 ]; then
    echo "⚠️  Consider increasing RAM or reducing concurrent scans"
fi

TEMP=$(vcgencmd measure_temp 2>/dev/null | cut -d= -f2 | cut -d"'" -f1)
if [ ${TEMP%.*} -gt 70 ] 2>/dev/null; then
    echo "⚠️  High temperature detected - check cooling and reduce CPU frequency"
fi
EOF

chmod +x /opt/secureurl/diagnose.sh
```

### Database Issues (MongoDB Atlas)
```bash
# MongoDB Atlas specific troubleshooting
echo "=== MongoDB Atlas Troubleshooting ==="

# Check network connectivity to Atlas
echo "Testing Atlas connectivity..."
nslookup cluster0.gqdf26i.mongodb.net
ping -c 3 cluster0.gqdf26i.mongodb.net

# Check if IP is whitelisted
curl -s ipinfo.io/ip
echo "^ Your public IP address - ensure it's whitelisted in Atlas Network Access"

# Test different connection methods
cd /opt/secureurl/backend && source venv/bin/activate
python3 -c "
import pymongo
try:
    client = pymongo.MongoClient('mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority', serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    print('✅ PyMongo connection successful')
except Exception as e:
    print(f'❌ PyMongo connection failed: {e}')
    
try:
    import motor.motor_asyncio
    import asyncio
    async def test():
        client = motor.motor_asyncio.AsyncIOMotorClient('mongodb+srv://parasafe:Maha1!!Bir@cluster0.gqdf26i.mongodb.net/?retryWrites=true&w=majority')
        await client.admin.command('ping')
        return 'Motor connection successful'
    result = asyncio.run(test())
    print(f'✅ {result}')
except Exception as e:
    print(f'❌ Motor connection failed: {e}')
"

# Common Atlas issues and solutions
echo ""
echo "=== Common MongoDB Atlas Issues ==="
echo "1. IP not whitelisted: Add your Pi's public IP to Atlas Network Access"
echo "2. Credentials incorrect: Verify username/password in connection string"
echo "3. Network issues: Check firewall, DNS resolution, internet connectivity"
echo "4. Cluster paused: Free tier clusters auto-pause after inactivity"
echo "5. Connection limit: Free tier has 500 connection limit"
```

---

# Platform Comparison

| Feature | Raspberry Pi | Azure | GCP | AWS |
|---------|-------------|-------|-----|-----|
| **Cost** | Low (hardware cost) | Pay-per-use | Pay-per-use | Pay-per-use |
| **Scalability** | Limited | High | High | High |
| **Management** | Manual | Managed | Managed | Managed |
| **Security** | Self-managed | Enterprise | Enterprise | Enterprise |
| **Availability** | Single point | High | High | High |
| **Best For** | Development/Testing | Enterprise Apps | Container Workloads | Mature Ecosystems |

Choose the platform based on your requirements for scale, budget, management overhead, and specific feature needs.