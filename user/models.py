from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    access_token = models.CharField(max_length=255, blank=True, null=True)