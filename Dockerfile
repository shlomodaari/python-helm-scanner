# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables to prevent Python from writing .pyc files to disk
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY . /app/

RUN apt-get update && apt-get install -y \
    curl \
    tar \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
# RUN curl -sSfL https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).tar.gz | tar -xz -C /usr/local/bin

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x /app/main.py

RUN ls /app

CMD ["python", "main.py"]
