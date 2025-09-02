from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from decouple import config
import requests
import logging

from .models import User
from .serializers import (
    UserSerializer, 
    GoogleAuthSerializer, 
    RefreshTokenSerializer
)

logger = logging.getLogger(__name__)

GOOGLE_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET', default='')
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')

class AuthViewSet(viewsets.GenericViewSet):
    """
    ViewSet para manejar autenticación con Google OAuth + JWT
    """
    permission_classes = [AllowAny]
    
    @action(detail=False, methods=['get'], url_path='google/url')
    def google_auth_url(self, request):
        """
        GET /api/user/auth/google/url/
        Devuelve la URL para iniciar OAuth con Google
        """
        try:
            if not GOOGLE_CLIENT_ID:
                return Response({
                    'error': 'Google OAuth client ID not configured',
                    'success': False
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            auth_url = (
                "https://accounts.google.com/o/oauth2/auth?"
                f"client_id={GOOGLE_CLIENT_ID}&"
                f"redirect_uri={FRONTEND_URL}/auth/callback&"
                "scope=openid email profile&"
                "response_type=code&"
                "access_type=offline"
            )
            
            return Response({
                'auth_url': auth_url,
                'success': True
            })
            
        except Exception as e:
            logger.error(f"Error generating Google auth URL: {str(e)}")
            return Response({
                'error': 'Failed to generate authentication URL',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='google/callback')
    def google_oauth_callback(self, request):
        """
        POST /api/user/auth/google/callback/
        Body: {"code": "auth_code_from_google"}
        Devuelve JWT tokens
        """
        serializer = GoogleAuthSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': 'Invalid request data',
                'details': serializer.errors,
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        code = serializer.validated_data['code']
        
        try:
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                return Response({
                    'error': 'Google OAuth credentials not configured',
                    'success': False
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Intercambiar código por token de acceso
            token_url = 'https://oauth2.googleapis.com/token'
            token_data = {
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': f'{FRONTEND_URL}/auth/callback',
            }
            
            token_response = requests.post(token_url, data=token_data, timeout=10)
            
            if token_response.status_code != 200:
                logger.error(f"Google token exchange failed: {token_response.text}")
                return Response({
                    'error': 'Failed to exchange authorization code',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            token_json = token_response.json()
            
            if 'access_token' not in token_json:
                return Response({
                    'error': 'No access token received from Google',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Obtener info del usuario de Google
            user_info_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={token_json['access_token']}"
            user_response = requests.get(user_info_url, timeout=10)
            
            if user_response.status_code != 200:
                logger.error(f"Google user info failed: {user_response.text}")
                return Response({
                    'error': 'Failed to get user information from Google',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_data = user_response.json()
            
            if 'email' not in user_data:
                return Response({
                    'error': 'Email not provided by Google',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Crear u obtener usuario
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults={
                    'username': user_data['email'],
                    'first_name': user_data.get('given_name', ''),
                    'last_name': user_data.get('family_name', ''),
                    'access_token': token_json['access_token'],
                }
            )
            
            # Si el usuario ya existe, actualizar el access_token
            if not created:
                user.access_token = token_json['access_token']
                user.save(update_fields=['access_token'])
            
            # Generar JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Serializar datos del usuario
            user_serializer = UserSerializer(user)
            
            response_data = {
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'user': user_serializer.data,
                'success': True,
                'created': created
            }
            
            return Response(response_data)
            
        except requests.RequestException as e:
            logger.error(f"Request to Google failed: {str(e)}")
            return Response({
                'error': 'Failed to communicate with Google services',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Unexpected error in Google OAuth callback: {str(e)}")
            return Response({
                'error': 'Internal server error',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='refresh')
    def refresh_token(self, request):
        """
        POST /api/user/auth/refresh/
        Body: {"refresh_token": "refresh_token_here"}
        Devuelve nuevo access token
        """
        serializer = RefreshTokenSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': 'Invalid request data',
                'details': serializer.errors,
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            refresh_token = RefreshToken(serializer.validated_data['refresh_token'])
            
            return Response({
                'access_token': str(refresh_token.access_token),
                'success': True
            })
            
        except TokenError as e:
            return Response({
                'error': 'Invalid or expired refresh token',
                'success': False
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    @action(detail=False, methods=['post'], url_path='logout', permission_classes=[IsAuthenticated])
    def logout(self, request):
        """
        POST /api/user/auth/logout/
        Body: {"refresh_token": "refresh_token_here"}
        Logout del usuario (invalida refresh token)
        """
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'message': 'Successfully logged out',
                'success': True
            })
        except TokenError:
            return Response({
                'message': 'Logged out (token was already invalid)',
                'success': True
            })
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            return Response({
                'message': 'Logged out with warnings',
                'success': True
            })

class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet para operaciones CRUD de usuarios
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    @action(detail=False, methods=['get'], url_path='me')
    def me(self, request):
        """
        GET /api/user/users/me/
        Devuelve información del usuario actual
        """
        serializer = self.get_serializer(request.user)
        return Response({
            'user': serializer.data,
            'success': True
        })
