#!/usr/bin/env bash
# Render build script

set -o errexit

echo "🚀 Starting build process..."

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

echo "✅ Build completed successfully!"
