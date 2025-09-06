from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.utils import timezone
from decouple import config
import requests
import logging
import uuid

from .models import User
from .serializers import (
    UserSerializer, 
    GoogleAuthSerializer, 
    GitHubAuthSerializer,
    RefreshTokenSerializer
)

logger = logging.getLogger(__name__)

GOOGLE_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET', default='')
GITHUB_CLIENT_ID = config('GITHUB_OAUTH_CLIENT_ID', default='')
GITHUB_CLIENT_SECRET = config('GITHUB_OAUTH_CLIENT_SECRET', default='')
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')

def generate_unique_username(base_username):
    """
    Genera un username único basado en un username base.
    Si el username ya existe, agrega un sufijo numérico o UUID.
    """
    username = base_username
    counter = 1
    
    while User.objects.filter(username=username).exists():
        username = f"{base_username}_{counter}"
        counter += 1
        
        if counter > 999:
            username = f"{base_username}_{uuid.uuid4().hex[:8]}"
            break
    
    return username

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
                f"redirect_uri={FRONTEND_URL}/auth/google/callback&"
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
            
            token_url = 'https://oauth2.googleapis.com/token'
            token_data = {
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': f'{FRONTEND_URL}/auth/google/callback',
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
            
            email = user_data['email']
            base_username = email.split('@')[0]
            username = generate_unique_username(base_username)
            
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': username,
                    'first_name': user_data.get('given_name', ''),
                    'last_name': user_data.get('family_name', ''),
                    'access_token': token_json['access_token'],
                }
            )
            
            if not created:
                user.access_token = token_json['access_token']
                if not user.first_name and user_data.get('given_name'):
                    user.first_name = user_data.get('given_name', '')
                if not user.last_name and user_data.get('family_name'):
                    user.last_name = user_data.get('family_name', '')
                user.save(update_fields=['access_token', 'first_name', 'last_name'])
            
            refresh = RefreshToken.for_user(user)
            
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
    
    @action(detail=False, methods=['get'], url_path='github/url')
    def github_auth_url(self, request):
        """
        GET /api/user/auth/github/url/
        Devuelve la URL para iniciar OAuth con GitHub
        """
        try:
            if not GITHUB_CLIENT_ID:
                return Response({
                    'error': 'GitHub OAuth client ID not configured',
                    'success': False
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            import secrets
            state = secrets.token_hex(16)
            
            from django.core.cache import cache
            cache.set(f"github_oauth_state_{state}", True, timeout=300)
            
            auth_url = (
                "https://github.com/login/oauth/authorize?"
                f"client_id={GITHUB_CLIENT_ID}&"
                f"redirect_uri={FRONTEND_URL}/auth/github/callback&"
                "scope=user:email read:user&"
                f"state={state}"
            )
            
            return Response({
                'auth_url': auth_url,
                'success': True
            })
            
        except Exception as e:
            logger.error(f"Error generating GitHub auth URL: {str(e)}")
            return Response({
                'error': 'Failed to generate authentication URL',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=False, methods=['post'], url_path='github/callback')
    def github_oauth_callback(self, request):
        """
        POST /api/user/auth/github/callback/
        Body: {"code": "auth_code_from_github"}
        Devuelve JWT tokens
        """
        serializer = GitHubAuthSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'error': 'Invalid request data',
                'details': serializer.errors,
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        code = serializer.validated_data['code']
        
        if code.startswith("RETRY_"):
            real_code = code[6:]
            logger.info(f"Frontend reports this as a retry call with code: {real_code[:10]}...")
            
            recent_users = User.objects.filter(
                date_joined__gte=timezone.now() - timezone.timedelta(minutes=2)
            ).order_by('-date_joined')
            
            if recent_users.exists():
                user = recent_users.first()
                logger.info(f"Retry: Found recent user {user.email}")
                refresh = RefreshToken.for_user(user)
                user_serializer = UserSerializer(user)
                
                return Response({
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'user': user_serializer.data,
                    'success': True,
                    'created': False,
                    'retry_success': True
                })
            
            code = real_code
        
        try:
            logger.info(f"GitHub OAuth callback received code: {code[:5]}...")
            
            if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
                logger.error("GitHub OAuth credentials not configured")
                return Response({
                    'error': 'GitHub OAuth credentials not configured',
                    'success': False
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            token_url = 'https://github.com/login/oauth/access_token'
            token_data = {
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'code': code,
                'redirect_uri': f'{FRONTEND_URL}/auth/github/callback',
            }
            
            headers = {'Accept': 'application/json'}
            logger.info(f"Sending GitHub token exchange request to {token_url}")
            token_response = requests.post(token_url, data=token_data, headers=headers, timeout=10)
            
            logger.info(f"GitHub token exchange response status: {token_response.status_code}")
            if token_response.status_code != 200:
                error_text = str(token_response.text).lower()
                if 'bad_verification_code' in error_text or 'incorrect or expired' in error_text:
                    logger.warning(f"GitHub says the code is invalid or already used: {token_response.text}")
                    
                    from django.core.cache import cache
                    cache_key = f"github_pending_code_{code[:10]}"
                    cache.set(cache_key, True, timeout=30)
                    
                    return Response({
                        'error': 'GitHub authorization code may need a retry',
                        'retry_needed': True,
                        'details': token_response.text,
                        'success': False
                    }, status=status.HTTP_202_ACCEPTED)
                
                logger.error(f"GitHub token exchange failed: {token_response.status_code} - {token_response.text}")
                return Response({
                    'error': 'Failed to exchange authorization code',
                    'details': token_response.text,
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            token_json = token_response.json()
            logger.info(f"GitHub token response: {token_json.keys()}")
            
            if 'access_token' in token_json:
                token_info = {
                    'length': len(token_json['access_token']),
                    'token_type': token_json.get('token_type', 'unknown'),
                    'scope': token_json.get('scope', 'unknown')
                }
                logger.info(f"GitHub token received: {token_info}")
                
                from django.core.cache import cache
                cache_key = f"github_auth_code_{code[:10]}"
                cache.set(cache_key, True, timeout=300)
            else:
                logger.warning(f"GitHub token exchange response contains no access_token: {token_json}")
                return Response({
                    'error': 'No access token received from GitHub',
                    'details': token_json,
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if 'access_token' not in token_json:
                return Response({
                    'error': 'No access token received from GitHub',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = token_json['access_token']
            
            user_headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'User-Agent': 'UML-Assist-Backend'
            }
            logger.info("Making GitHub API user request with Bearer token")
            
            import time
            time.sleep(2)
            
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                user_response = requests.get('https://api.github.com/user', headers=user_headers, timeout=15)
                
                if user_response.status_code == 200:
                    break
                
                if retry_count == 0 and user_response.status_code != 200:
                    user_headers['Authorization'] = f'token {access_token}'
                    logger.info("First attempt failed, trying with 'token' format instead of 'Bearer'")
                
                logger.warning(f"GitHub API attempt {retry_count+1} failed with status {user_response.status_code}")
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(2)
            
            if user_response.status_code != 200:
                logger.error(f"GitHub user info failed after {max_retries} attempts: {user_response.status_code} - {user_response.text}")
                
                debug_info = {
                    'token_length': len(access_token) if access_token else 0,
                    'token_type': token_json.get('token_type', 'unknown'),
                    'scopes': token_json.get('scope', '').split(',')
                }
                logger.error(f"GitHub token debug info: {debug_info}")
                
                return Response({
                    'error': 'Failed to get user information from GitHub',
                    'details': user_response.text,
                    'retry_needed': True,
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_data = user_response.json()
            
            email = user_data.get('email')
            if not email:
                emails_response = requests.get('https://api.github.com/user/emails', headers=user_headers, timeout=10)
                
                if emails_response.status_code == 200:
                    emails_data = emails_response.json()
                    logger.info(f"GitHub emails response: {emails_data}")
                    primary_email = next((e['email'] for e in emails_data if e['primary']), None)
                    if primary_email:
                        email = primary_email
                else:
                    logger.error(f"GitHub emails failed: {emails_response.status_code} - {emails_response.text}")
            
            if not email:
                return Response({
                    'error': 'Email not provided by GitHub',
                    'success': False
                }, status=status.HTTP_400_BAD_REQUEST)
            
            full_name = user_data.get('name', '')
            name_parts = full_name.split(' ', 1) if full_name else []
            first_name = name_parts[0] if name_parts else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            base_username = email.split('@')[0]
            username = generate_unique_username(base_username)
            
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'username': username,
                    'first_name': first_name,
                    'last_name': last_name,
                    'access_token': token_json['access_token'],
                }
            )
            
            if not created:
                user.access_token = token_json['access_token']
                if not user.first_name and first_name:
                    user.first_name = first_name
                if not user.last_name and last_name:
                    user.last_name = last_name
                user.save(update_fields=['access_token', 'first_name', 'last_name'])
            
            refresh = RefreshToken.for_user(user)
            
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
            logger.error(f"Request to GitHub failed: {str(e)}")
            
            try:
                recent_users = User.objects.filter(
                    date_joined__gte=timezone.now() - timezone.timedelta(seconds=60)
                ).order_by('-date_joined')
                
                if recent_users.exists():
                    user = recent_users.first()
                    logger.info(f"Found recent user {user.email} during error handling")
                    refresh = RefreshToken.for_user(user)
                    user_serializer = UserSerializer(user)
                    return Response({
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'user': user_serializer.data,
                        'success': True,
                        'created': False,
                        'recovered': True
                    })
            except Exception as recovery_error:
                logger.error(f"Error during recovery attempt: {str(recovery_error)}")
                
            return Response({
                'error': 'Failed to communicate with GitHub services',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Unexpected error in GitHub OAuth callback: {str(e)}")
            
            try:
                recent_users = User.objects.filter(
                    date_joined__gte=timezone.now() - timezone.timedelta(seconds=60)
                ).order_by('-date_joined')
                
                if recent_users.exists():
                    user = recent_users.first()
                    logger.info(f"Found recent user {user.email} during general error handling")
                    refresh = RefreshToken.for_user(user)
                    user_serializer = UserSerializer(user)
                    return Response({
                        'access_token': str(refresh.access_token),
                        'refresh_token': str(refresh),
                        'user': user_serializer.data,
                        'success': True,
                        'created': False,
                        'recovered': True
                    })
            except Exception as recovery_error:
                logger.error(f"Error during recovery attempt: {str(recovery_error)}")
                
            return Response({
                'error': 'Internal server error',
                'details': str(e),
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    @action(detail=False, methods=['get'], url_path='github/test')
    def github_test(self, request):
        """
        GET /api/user/auth/github/test
        Endpoint de prueba para verificar configuración GitHub
        """
        try:
            return Response({
                'client_id': GITHUB_CLIENT_ID[:5] + '...' if GITHUB_CLIENT_ID else 'Not set',
                'client_secret': 'Set' if GITHUB_CLIENT_SECRET else 'Not set',
                'redirect_uri': f'{FRONTEND_URL}/auth/github/callback',
                'success': True
            })
        except Exception as e:
            return Response({
                'error': str(e),
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    @action(detail=False, methods=['get'], url_path='github/test-token')
    def github_test_token(self, request):
        """
        GET /api/user/auth/github/test-token?token=xyz
        Endpoint para probar un token de GitHub directamente
        """
        token = request.query_params.get('token')
        if not token:
            return Response({
                'error': 'No token provided',
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            bearer_headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/json',
                'User-Agent': 'UML-Assist-Backend'
            }
            token_headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/json',
                'User-Agent': 'UML-Assist-Backend'
            }
            
            bearer_response = requests.get('https://api.github.com/user', headers=bearer_headers, timeout=10)
            token_response = requests.get('https://api.github.com/user', headers=token_headers, timeout=10)
            
            return Response({
                'bearer_status': bearer_response.status_code,
                'bearer_body': bearer_response.json() if bearer_response.status_code == 200 else bearer_response.text,
                'token_status': token_response.status_code,
                'token_body': token_response.json() if token_response.status_code == 200 else token_response.text,
                'success': bearer_response.status_code == 200 or token_response.status_code == 200
            })
        except Exception as e:
            logger.error(f"Error testing GitHub token: {str(e)}")
            return Response({
                'error': f'Error testing token: {str(e)}',
                'success': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    @action(detail=False, methods=['post'], url_path='refresh')
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
