FROM python:3.11-slim

# Evita que Python genere archivos .pyc y permite ver logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Crear usuario no-root para ejecutar la aplicación
RUN useradd -m -u 1000 appuser

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copiar y instalar requirements
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copiar aplicación
COPY . /app/

# Copiar y hacer ejecutable el script de entrada
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Cambiar propiedad de archivos
RUN chown -R appuser:appuser /app

# Cambiar a usuario no-root
USER appuser

EXPOSE 8000

# Usar el script de entrada que maneja migraciones automáticamente
ENTRYPOINT ["/app/entrypoint.sh"]