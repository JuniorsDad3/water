#!/usr/bin/env bash

# Update system packages
apt-get update -y

# Install UnixODBC and Microsoft ODBC Driver 18
apt-get install -y curl gnupg2 unixodbc unixodbc-dev

# Add Microsoft repository
curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list

# Install Microsoft ODBC Driver 18
apt-get update -y
ACCEPT_EULA=Y apt-get install -y msodbcsql18

# Run the application
gunicorn app:app --bind 0.0.0.0:10000
