from rest_framework import viewsets
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from diagram.models import Diagram
from diagram.serializers import DiagramSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied
from rest_framework import filters

class DiagramViewSet(viewsets.ModelViewSet):
    """
    ViewSet para operaciones CRUD de Diagramas
    """
    queryset = Diagram.objects.all()
    serializer_class = DiagramSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, JSONParser)

    filter_backends = [filters.OrderingFilter]
    ordering_fields = ['title', 'created_at', 'updated_at']
    ordering = ['title']  # orden por defecto

    def get_queryset(self):
        # Filtrar diagramas por el usuario autenticado
        return self.queryset.filter(user=self.request.user)
    
    def get_object(self):
        """
        Validar que el usuario solo acceda a sus propios diagramas
        """
        obj = super().get_object()
        if obj.user != self.request.user:
            raise PermissionDenied("No tienes permiso para acceder a este diagrama")
        return obj