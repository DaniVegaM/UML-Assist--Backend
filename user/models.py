from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    access_token = models.CharField(max_length=255, blank=True, null=True)
    """
    Usar email como campo de login 
    Importante: no tener el email en REQUIRED_FIELDS y debe ser unico
    """
    email = models.EmailField(unique = True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [] 