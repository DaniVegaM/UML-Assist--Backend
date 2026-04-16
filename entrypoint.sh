#!/bin/bash
set -e

echo "Esperando a que la base de datos esté lista..."
count=0
max_attempts=30
until nc -z $DB_HOST $DB_PORT; do
  count=$((count + 1))
  if [ $count -gt $max_attempts ]; then
    echo "ERROR: Database connection failed after $max_attempts attempts"
    exit 1
  fi
  echo "Intento $count/$max_attempts - Esperando BD en $DB_HOST:$DB_PORT..."
  sleep 2
done
echo "✓ Base de datos lista!"

echo "Ejecutando migraciones..."
if ! python manage.py migrate --noinput; then
  echo "ERROR: Las migraciones fallaron"
  exit 1
fi
echo "✓ Migraciones completadas"

echo "Recolectando archivos estáticos..."
if ! python manage.py collectstatic --noinput; then
  echo "ERROR: Recolección de estáticos falló"
  exit 1
fi
echo "✓ Estáticos recolectados"

echo "Iniciando Gunicorn..."
exec gunicorn \
  --bind 0.0.0.0:8000 \
  --workers 4 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile - \
  --log-level info \
  uml_assist_backend.wsgi:application

