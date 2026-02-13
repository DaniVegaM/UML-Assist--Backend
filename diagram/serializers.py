from rest_framework import serializers
from diagram.models import Diagram
import json


class DiagramSerializer(serializers.ModelSerializer):
    """
    Serializer para Diagramas
    """

    class Meta:
        model = Diagram
        fields = ['id', 'title', 'user', 'created_at', 'updated_at', 'content', 'preview_image']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

    def create(self, validated_data):
        user = self.context['request'].user
        diagram = Diagram.objects.create(user=user, **validated_data)
        return diagram
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance