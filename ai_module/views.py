from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated


class ReviewDiagramView(APIView):
    """
    Vista para revisar diagramas usando IA
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Método POST para revisar un diagrama
        """
        data = request.data

        print("Datos recibidos para revisión de diagrama:", data)
        
        # Ejemplo de respuesta
        return Response({
            'suggestions': [
                {
                    'component': 'acc_212',
                    'suggestion': 'Considera agregar un método toString() para facilitar la depuración'
                },
                {
                    'component': 'edge_45',
                    'suggestion': 'La cardinalidad debería ser 1 a muchos en lugar de muchos a muchos'
                },
                {
                    'component': 'acty_78',
                    'suggestion': 'Agregar validación de formato de email en el modelo'
                }
            ]
        }, status=status.HTTP_200_OK)