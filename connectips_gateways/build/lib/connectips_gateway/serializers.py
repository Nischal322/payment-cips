# serializers.py
from rest_framework import serializers
from .models import CipsPayment

class ConnectIpsPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CipsPayment
        fields = '__all__'  # Includes all fields from the model
