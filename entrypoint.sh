#!/bin/sh
set -e

# Create/update database tables, then start the production web server
python manage.py migrate --noinput
# gthread workers handle idle browser connections without "WORKER TIMEOUT" errors
exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 \
    --workers 3 --worker-class gthread --threads 4 --timeout 60
