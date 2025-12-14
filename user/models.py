from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Usar email como campo de login 
    Importante: no tener el email en REQUIRED_FIELDS y debe ser único
    """
    email = models.EmailField(unique=True)
    
    # Campo para diferenciar el método de autenticación
    PROVIDER_CHOICES = [
        ('email', 'Email/Password'),
        ('google', 'Google'),
        ('github', 'GitHub'),
    ]
    provider = models.CharField(
        max_length=10,
        choices=PROVIDER_CHOICES,
        default='email'
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
