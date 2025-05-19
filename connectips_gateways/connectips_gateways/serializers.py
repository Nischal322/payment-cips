# serializers.py
from rest_framework import serializers
from .models import CipsPayment

class ConnectIpsPaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CipsPayment
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")

        is_dashboard = request.query_params.get("dashboard", "true").lower() == "true" if request else True

        if not is_dashboard:
            return {
                "gateway_url": data["gateway_url"],
                "merchant_id": data["merchant_id"],
                "app_id": data["app_id"],
                "app_name": data["app_name"]
                
            }
        return data
