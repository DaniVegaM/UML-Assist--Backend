#!/bin/bash
set -e

echo "Esperando a que la base de datos esté lista..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "Base de datos lista!"

echo "Verificando si hay cambios de modelos sin migrar..."
python manage.py makemigrations --check --dry-run || {
  echo "ERROR: Hay cambios de modelos sin migrar. Debes ejecutar 'python manage.py makemigrations' localmente."
  exit 1
}

echo "Ejecutando migraciones..."
python manage.py migrate --noinput

echo "Recolectando archivos estáticos..."
python manage.py collectstatic --noinput

echo "Iniciando Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 uml_assist_backend.wsgi:application
