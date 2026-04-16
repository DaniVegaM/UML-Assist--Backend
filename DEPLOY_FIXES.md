# Correcciones para 502 Bad Gateway

## Cambios realizados:

### 1. **settings.py** - Configuración de seguridad y hosts
- ✅ `ALLOWED_HOSTS` ahora es configurable por variable de entorno
- ✅ Agregado `SECURE_SSL_REDIRECT` para forzar HTTPS en producción
- ✅ Seguridad de cookies habilitada en producción (SSL)
- ✅ `CORS_ALLOWED_ORIGINS` ahora es configurable y limpiado

### 2. **entrypoint.sh** - Mejor manejo de errores
- ✅ Retry logic mejorado con máximo de intentos
- ✅ Validación explícita de cada paso (migraciones, estáticos, gunicorn)
- ✅ Mejor logging para debugging
- ✅ Configuración de Gunicorn optimizada (4 workers, timeouts, logging)

### 3. **Dockerfile** - Seguridad y optimizaciones
- ✅ Usuario no-root (appuser) para ejecutar la aplicación
- ✅ `--no-install-recommends` para reducir tamaño
- ✅ Mejor gestión de permisos de archivos

### 4. **deploy.yml** - Health checks y validaciones
- ✅ Espera de 15 segundos en lugar de 10
- ✅ Verificación de que el contenedor está activo
- ✅ Health check HTTP endpoint
- ✅ Logs de error si algo falla
- ✅ `--restart unless-stopped` para que se reinicie automáticamente

### 5. **urls.py** - Endpoint de salud
- ✅ Nuevo endpoint `/health/` para verificar que el servidor está funcionando

## Variable de entorno en EC2 (backend.env)

Asegúrate de que en `/home/ec2-user/app-config/backend.env` tengas configurado:

```bash
# Requeridos
DB_HOST=<tu-rds-host>
DB_PORT=5432
DB_NAME=<nombre-bd>
DB_USER=<usuario-bd>
DB_PASSWORD=<contraseña-bd>

# Seguridad
SECRET_KEY=<tu-secret-key>
DEBUG=False

# Email
EMAIL_HOST=<smtp-host>
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=<tu-email>
EMAIL_HOST_PASSWORD=<tu-password>
DEFAULT_FROM_EMAIL=<tu-email>

# Frontend
FRONTEND_URL=https://uml-assist.danivegam.com

# CORS - Agregá tu dominio y el IP de EC2 si es necesario
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,https://uml-assist.danivegam.com

# Hosts permitidos - Agregá el IP de EC2 o dominio
ALLOWED_HOSTS=uml-assist.danivegam.com,localhost,127.0.0.1,<IP-EC2-si-es-necesario>
```

## Pasos para desplegar:

1. **Commit y push de cambios:**
   ```bash
   git add .
   git commit -m "Fix: 502 Bad Gateway - mejorar seguridad y health checks"
   git push origin main
   ```

2. **El workflow de GitHub Actions se ejecutará automáticamente**
   - Construye la imagen Docker
   - La sube a ECR
   - Se conecta al EC2 y hace el deploy
   - Verifica que todo funcione

3. **Si hay problemas, revisa los logs en EC2:**
   ```bash
   # SSH a tu EC2
   docker logs uml-backend
   
   # Ver el estado del contenedor
   docker ps -a
   
   # Reiniciar el contenedor manualmente si es necesario
   docker restart uml-backend
   ```

## Checklist para resolver 502:

- [ ] Backend.env en EC2 contiene todas las variables requeridas
- [ ] La base de datos está accesible desde EC2
- [ ] El puerto 8000 está abierto en el security group de EC2
- [ ] El reverse proxy (nginx/load balancer) tiene configurado el backend en `http://localhost:8000`
- [ ] Los logs del contenedor no muestran errores de base de datos
- [ ] El health check `/health/` responde exitosamente

## Debugging si sigue habiendo 502:

```bash
# Ver logs en tiempo real
docker logs -f uml-backend

# Ejecutar comando dentro del contenedor
docker exec -it uml-backend python manage.py shell

# Verificar que Gunicorn está escuchando
docker exec uml-backend netstat -tlnp | grep 8000

# Comprobar health check
curl http://localhost:8000/health/
```

## Notas importantes:

1. **SECURE_SSL_REDIRECT**: Solo activo en producción (DEBUG=False). Si el frontend está en HTTP, esto puede causar redirects infinitos. Asegúrate de que el frontend use HTTPS.

2. **CSRF_TRUSTED_ORIGINS**: Ya está configurado para `https://uml-assist.danivegam.com`

3. **CORS**: Ahora es configurable por variable de entorno para mayor flexibilidad

4. **Gunicorn workers**: Configurado con 4 workers. Puedes aumentar/disminuir según recursos de EC2:
   - t2.micro: 2 workers
   - t2.small: 4 workers
   - t2.medium: 4-6 workers
