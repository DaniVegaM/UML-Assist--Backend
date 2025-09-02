from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer para el modelo User
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'is_active']
        read_only_fields = ['id', 'date_joined']

class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer para validar el código de autorización de Google
    """
    code = serializers.CharField(required=True, help_text="Authorization code from Google OAuth")

class TokenResponseSerializer(serializers.Serializer):
    """
    Serializer para la respuesta de tokens JWT
    """
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user = UserSerializer()
    success = serializers.BooleanField()
    created = serializers.BooleanField(help_text="True if user was created, False if existing user")

class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer para validar refresh token
    """
    refresh_token = serializers.CharField(required=True)