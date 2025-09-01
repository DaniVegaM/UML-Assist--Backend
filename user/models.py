from django.db import models
from django.contrib.auth.hashers import make_password, check_password

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    access_token = models.CharField(max_length=255, blank=True, null=True)

    def save(self, *args, **kwargs): # Hash la contraseña antes de guardar (solo si es nueva)
        if not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def check_password(self, raw_password): # Verifica la contraseña
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username