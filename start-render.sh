#!/bin/bash
set -e

echo "=== Starting NT219 Payment Gateway ==="
echo "Python version: $(python --version)"
echo "Working directory: $(pwd)"
echo "PORT: ${PORT:-10000}"

# Check directory structure
echo ""
echo "=== Directory Structure ==="
ls -la /app
echo ""
echo "=== Backend contents ==="
ls -la /app/backend

# Check Python can find modules
echo ""
echo "=== Python Path ==="
python -c "import sys; print('\n'.join(sys.path))"

# Try importing backend
echo ""
echo "=== Testing Import ==="
python -c "import backend; print('✓ backend imported successfully')" || {
    echo "✗ Failed to import backend package"
    exit 1
}

# Try importing main with error details
echo ""
echo "=== Testing backend.main import ==="
python -c "
try:
    import backend.main
    print('✓ backend.main imported successfully')
except Exception as e:
    import traceback
    print('✗ Failed to import backend.main:')
    print(traceback.format_exc())
    exit(1)
" || {
    echo ""
    echo "=== Import failed, checking dependencies ==="
    pip list | grep -E "(fastapi|uvicorn|sqlalchemy|stripe)"
    exit 1
}

# Start the application
echo ""
echo "=== Starting Uvicorn ==="
echo "Binding to 0.0.0.0:${PORT:-10000}"
exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-10000}
