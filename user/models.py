from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Usar email como campo de login 
    Importante: no tener el email en REQUIRED_FIELDS y debe ser unico
    """
    email = models.EmailField(unique = True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [] 
