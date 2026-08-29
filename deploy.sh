#!/bin/bash
set -e

echo "Building Gilos Auth with latest git tag..."
VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0-dev")
go build -ldflags "-X gilosauth/config.Version=$VERSION" -o main main.go

echo "Restarting the auth service..."
sudo systemctl restart auth

echo "Deployment complete!"
