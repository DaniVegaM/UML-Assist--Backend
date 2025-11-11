from rest_framework import serializers
from diagram.models import Diagram


class DiagramSerializer(serializers.ModelSerializer):
    """
    Serializer para Diagramas
    """

    class Meta:
        model = Diagram
        fields = ['id', 'title', 'user', 'created_at', 'updated_at', 'content']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def create(self, validated_data):
        user = self.context['request'].user
        diagram = Diagram.objects.create(user=user, **validated_data)
        return diagram
        