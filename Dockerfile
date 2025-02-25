# Use an official Python slim image
FROM python:3.11-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies and prerequisites
RUN apt-get update -y && apt-get install -y \
    apt-transport-https \
    curl \
    gnupg2 \
    unixodbc \
    unixodbc-dev

# Add Microsoft repository and install ODBC Driver 18 for SQL Server
RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    curl https://packages.microsoft.com/config/ubuntu/20.04/prod.list > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update -y && \
    ACCEPT_EULA=Y apt-get install -y msodbcsql18 odbcinst libodbc1

# Set LD_LIBRARY_PATH so the driver is found
ENV LD_LIBRARY_PATH=/opt/microsoft/msodbcsql18/lib64:$LD_LIBRARY_PATH

# Set the working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of your application code
COPY . /app/

# Expose the port your application runs on
EXPOSE 10000

# Command to run your application
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
