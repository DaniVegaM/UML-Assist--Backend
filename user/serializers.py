from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from user.utils.user_utils import generate_unique_username

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer para el modelo User
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined', 'is_active']
        read_only_fields = ['id', 'date_joined']

class GoogleAuthSerializer(serializers.Serializer):
    """
    Serializer para validar el código de autorización de Google
    """
    code = serializers.CharField(required=True, help_text="Authorization code from Google OAuth")

class GitHubAuthSerializer(serializers.Serializer):
    """
    Serializer para validar el código de autorización de GitHub
    """
    code = serializers.CharField(required=True, help_text="Authorization code from GitHub OAuth")

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


class UserSignupSerializer(serializers.ModelSerializer):
    """
    Serializer para registro de usuarios
    """
    password = serializers.CharField(write_only = True, min_length = 8)

    class Meta:
        model = User
        fields = ('email', 'password')
        extra_kwargs = {
            'email': {'required': True},
        }

    def validate_email(self, value):
        """Validar que el email no exista"""
        if User.objects.filter(email = value).exists():
            raise serializers.ValidationError('A user with this email already exists.')
        return value

    def validate_password(self,value):
        """Validar complejidad del password"""
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError({'password': e.messages})
        return value
    
    def create(self, validated_data):
        email = validated_data.get('email')
        base_username = email.split('@')[0]
        validated_data['username'] = generate_unique_username(base_username)

        user = User.objects.create_user(**validated_data)
        return user
    

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer para inicio se sesion con email
    """
    password = serializers.CharField(write_only = True, required = True)
    email = serializers.EmailField(required = True)

    def validate(self, attrs):
        """Validar credenciales de usuario"""
        email = attrs.get('email')
        password = attrs.get('password')

        if not email or not password:
            raise serializers.ValidationError('Email and password are required.')
        
        # Intentar autenticar al usuario
        user = authenticate(username = email, password = password)

        if not user:
            raise serializers.ValidationError('Invalid email or password.')
        
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled.')
        
        attrs['user'] = user
        return attrs
    
