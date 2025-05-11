#!/bin/bash

# Atualizar pip
#python3 -m pip install --upgrade pip
# Create the downloads directory if it doesn't exist
mkdir -p apps/downloads

# Define Trivy version
TRIVY_VERSION="v0.60.0"

# Download Linux 32-bit binaries
echo "Downloading Linux 32-bit binaries..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-32bit.deb" -o "apps/downloads/trivy-32.deb"
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-32bit.rpm" -o "apps/downloads/trivy-32.rpm"

# Download Linux 64-bit binaries
echo "Downloading Linux 64-bit binaries..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-64bit.deb" -o "apps/downloads/trivy-64.deb"
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-64bit.rpm" -o "apps/downloads/trivy-64.rpm"

# Download Linux ARM binaries
echo "Downloading Linux ARM binaries..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-ARM.deb" -o "apps/downloads/trivy-arm.deb"
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-ARM.rpm" -o "apps/downloads/trivy-arm.rpm"

# Download Linux ARM64 binaries
echo "Downloading Linux ARM64 binaries..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-ARM64.deb" -o "apps/downloads/trivy-arm64.deb"
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_Linux-ARM64.rpm" -o "apps/downloads/trivy-arm64.rpm"

# Download Windows binary
echo "Downloading Windows binary..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_windows-64bit.zip" -o "apps/downloads/trivy-windows.zip"
unzip -o "apps/downloads/trivy-windows.zip" -d "apps/downloads/"
mv "apps/downloads/trivy.exe" "apps/downloads/trivy-windows.exe"
rm "apps/downloads/trivy-windows.zip"

# Download macOS binaries
echo "Downloading macOS binaries..."
curl -L "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_0.60.0_macOS-64bit.tar.gz" -o "apps/downloads/trivy-macos.tar.gz"
tar -xzf "apps/downloads/trivy-macos.tar.gz" -C "apps/downloads/"
mv "apps/downloads/trivy" "apps/downloads/trivy-macos"
rm "apps/downloads/trivy-macos.tar.gz"

echo "All Trivy binaries have been downloaded to apps/downloads/"
ls -la apps/downloads/

# Configurar variável de ambiente para Flask
export FLASK_APP=app.py
export FLASK_ENV=development

# Executar migrações do banco de dados
flask db init || echo "Database already initialized"
flask db migrate || echo "Migration failed"
flask db upgrade || echo "Upgrade failed"

# Compilar utilitário CPE (comentado por enquanto)
#go build apps/utils/cpe_search.go
#chmod +x cpe_search
