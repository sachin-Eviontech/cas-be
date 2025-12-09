from rest_framework import serializers
from .models import Organization

class OrganizationSerializer(serializers.ModelSerializer):
    logo = serializers.ImageField(required=False)
    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'logo', 'message', 'package_name', 'show_warning', 'block_access'
        ]

    def update(self, instance, validated_data):
        if 'logo' in validated_data and instance.logo:
            instance.logo.delete(save=False)
        return super().update(instance, validated_data)
    
