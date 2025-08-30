# UML Assist Backend

<div align="center">
  <img src="https://www.django-rest-framework.org/img/logo.png" alt="Django REST Framework" width="300"/>
  <br><br>
  <p><strong>API Backend para UML Assist - Generador de Diagramas UML</strong></p>
  
  ![Django](https://img.shields.io/badge/Django-5.2.5-092E20?style=for-the-badge&logo=django&logoColor=white)
  ![DRF](https://img.shields.io/badge/DRF-3.16.1-ff1709?style=for-the-badge&logo=django&logoColor=white)
  ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)
  ![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)
</div>

---

## 📋 Descripción

API REST desarrollada con Django REST Framework para el manejo de usuarios y diagramas UML. Proporciona endpoints para la creación, edición y gestión de diagramas UML de manera eficiente.

## 🛠️ Tecnologías

- **Django 5.2.5** - Framework web de Python
- **Django REST Framework 3.16.1** - Toolkit para APIs REST
- **PostgreSQL** - Base de datos relacional
- **Python 3.13** - Lenguaje de programación

## 📦 Instalación

### 1. Clonar el repositorio
```bash
git clone https://github.com/DaniVegaM/UML-Assist--Backend.git
cd UML-Assist--Backend
```

### 2. Crear entorno virtual
```bash
python -m venv venv
source venv/bin/activate  # En macOS/Linux
# venv\Scripts\activate   # En Windows
```

### 3. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar variables de entorno
Crea un archivo `.env` basado en `.env.example`:
```bash
cp .env.example .env
```

Edita el archivo `.env` con tus credenciales:
```env
# Base de datos PostgreSQL
DB_NAME=tu_base_de_datos
DB_USER=tu_usuario
DB_PASSWORD=tu_password
DB_HOST=localhost
DB_PORT=5432

# Configuración de Django
SECRET_KEY=tu_secret_key_aqui
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
```

### 5. Configurar PostgreSQL
```bash
# Instalar PostgreSQL (macOS)
brew install postgresql
brew services start postgresql

# Crear base de datos
createdb tu_base_de_datos

# O crear usuario y base de datos desde psql
psql postgres
CREATE USER tu_usuario WITH PASSWORD 'tu_password';
CREATE DATABASE tu_base_de_datos OWNER tu_usuario;
GRANT ALL PRIVILEGES ON DATABASE tu_base_de_datos TO tu_usuario;
\q
```

## 🚀 Comandos Básicos

### Ejecutar migraciones
```bash
# Crear archivos de migración
python manage.py makemigrations

# Aplicar migraciones a la base de datos
python manage.py migrate
```

### Crear superusuario
```bash
python manage.py createsuperuser
```

### Iniciar servidor de desarrollo
```bash
# Servidor en http://127.0.0.1:8000/
python manage.py runserver

# Servidor en puerto específico
python manage.py runserver 8080

# Servidor accesible desde cualquier IP
python manage.py runserver 0.0.0.0:8000
```

### Comandos adicionales útiles
```bash
# Verificar el proyecto
python manage.py check

# Abrir shell de Django
python manage.py shell

# Colectar archivos estáticos (producción)
python manage.py collectstatic

# Crear nueva app
python manage.py startapp nombre_app
```

## 📡 Endpoints de la API

### Usuarios
```
GET    /api/users/          # Listar usuarios
POST   /api/users/          # Crear usuario
GET    /api/users/{id}/     # Obtener usuario específico
PUT    /api/users/{id}/     # Actualizar usuario completo
PATCH  /api/users/{id}/     # Actualizar usuario parcial
DELETE /api/users/{id}/     # Eliminar usuario
```

### Diagramas
```
GET    /api/diagrams/       # Listar diagramas
POST   /api/diagrams/       # Crear diagrama
GET    /api/diagrams/{id}/  # Obtener diagrama específico
PUT    /api/diagrams/{id}/  # Actualizar diagrama completo
PATCH  /api/diagrams/{id}/  # Actualizar diagrama parcial
DELETE /api/diagrams/{id}/  # Eliminar diagrama
```

### Admin
```
GET    /admin/              # Panel de administración de Django
```

## 📁 Estructura del Proyecto

```
uml_assist_backend/
├── diagram/                 # App de diagramas UML
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   └── urls.py
├── user/                    # App de usuarios
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   └── urls.py
├── uml_assist_backend/      # Configuración principal
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── .env                     # Variables de entorno (no subir a git)
├── .env.example            # Ejemplo de variables de entorno
├── .gitignore              # Archivos ignorados por git
├── manage.py               # Comando principal de Django
├── requirements.txt        # Dependencias del proyecto
└── README.md              # Este archivo
```

## 🔧 Desarrollo

### Agregar nueva funcionalidad
1. Crear o modificar modelos en `models.py`
2. Crear migraciones: `python manage.py makemigrations`
3. Aplicar migraciones: `python manage.py migrate`
4. Crear serializers en `serializers.py`
5. Crear ViewSets en `views.py`
6. Configurar URLs en `urls.py`

### Testing
```bash
# Ejecutar todos los tests
python manage.py test

# Ejecutar tests de una app específica
python manage.py test user
python manage.py test diagram
```

## 👥 Autores

- **DaniVegaM** - [@DaniVegaM](https://github.com/DaniVegaM)
- **0ambar** - [@0ambar](https://github.com/0ambar)
- **Eduardo0811** - [@Eduardo0811](https://github.com/Eduardo0811)
- **Verito1508** - [@Verito1508](https://github.com/Verito1508)
