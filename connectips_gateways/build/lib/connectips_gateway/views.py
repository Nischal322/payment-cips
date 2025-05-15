import hmac
import hashlib
import base64
import requests
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.decorators import action, api_view
from rest_framework.views import APIView
from django.conf import settings
from .models import CipsPayment
from .serializers import ConnectIpsPaymentSerializer
import os
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from OpenSSL import crypto
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import json
from datetime import datetime


class ConnectIpsPaymentViewSet(viewsets.ModelViewSet):
    """ViewSet for managing NPS Payment configurations"""

    queryset = CipsPayment.objects.all()
    serializer_class = ConnectIpsPaymentSerializer
    http_method_names = ['get', 'post', 'put', 'patch']

    def list(self, request):
        payments = CipsPayment.objects.all()
        serializer = ConnectIpsPaymentSerializer(payments, many=True)
        return Response({"data": serializer.data})

    def create(self, request):
        serializer = ConnectIpsPaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            payment = CipsPayment.objects.get(pk=pk)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ConnectIpsPaymentSerializer(payment, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Updated successfully", "data": serializer.data})
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        try:
            payment = CipsPayment.objects.get(pk=pk)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ConnectIpsPaymentSerializer(payment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Partially updated successfully", "data": serializer.data})
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class ConnectIpsSuccessUrl(APIView):

    def get(self, request):
        txn_id = request.query_params.get('TXNID')
        if txn_id:
            return Response(
                {"message": "Success", "transaction_id": txn_id},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "Transaction ID not provided"},
                status=status.HTTP_400_BAD_REQUEST
            )
        

class ConnectIpsFailureUrl(APIView):

    def get(self, request):
        txn_id = request.query_params.get('TXNID')
        if txn_id:
            return Response(
                {"message": "Failure", "transaction_id": txn_id},
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"error": "Transaction ID not provided"},
                status=status.HTTP_400_BAD_REQUEST
            )        
        

def generate_connectips_token(merchant_id, app_id, app_name, txn_id, txn_date, 
                            txn_currency, txn_amount, reference_id, remarks, 
                            particulars, pfx_path, pfx_password):
    """
    Generate ConnectIPS payment token
    """
    try:
        # Generate message string
        message = (
            f"MERCHANTID={merchant_id},"
            f"APPID={app_id},"
            f"APPNAME={app_name},"
            f"TXNID={txn_id},"
            f"TXNDATE={txn_date},"
            f"TXNCRNCY={txn_currency},"
            f"TXNAMT={txn_amount},"
            f"REFERENCEID={reference_id},"
            f"REMARKS={remarks},"
            f"PARTICULARS={particulars},"
            f"TOKEN=TOKEN"
        )
        
        # Read and load PFX file
        with open(pfx_path, 'rb') as pfx_file:
            pfx_data = pfx_file.read()
        
        # Load the PFX file with password
        p12 = crypto.load_pkcs12(pfx_data, pfx_password.encode())
        private_key = p12.get_privatekey()
        
        # Generate SHA256 hash and sign
        message_hash = hashlib.sha256(message.encode()).digest()
        signature = crypto.sign(private_key, message_hash, 'sha256')
        
        # Convert to base64
        return base64.b64encode(signature).decode()
        
    except Exception as e:
        raise Exception(f"Token generation failed: {str(e)}")

class ConnectIpsTokenView(APIView):
    def post(self, request):
        try:
            body = request.data
            
            # Required parameters
            required_params = [
                'MERCHANTID', 'APPID', 'APPNAME', 'TXNID', 'TXNDATE',
                'TXNCRNCY', 'TXNAMT', 'REFERENCEID', 'REMARKS', 'PARTICULARS'
            ]
            
            # Check for missing parameters
            missing_params = [param for param in required_params if param not in body]
            if missing_params:
                return Response({
                    'error': f'Missing required parameters: {", ".join(missing_params)}'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get configuration from database
            try:
                cips_config = CipsPayment.objects.get(merchant_id=body['MERCHANTID'])
            except CipsPayment.DoesNotExist:
                return Response({
                    'error': f'ConnectIPS configuration not found for merchant ID: {body["MERCHANTID"]}'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Get PFX file path and password
            pfx_path = os.path.join(os.path.dirname(__file__), 'CREDITOR.pfx')
            pfx_password = cips_config.password
            
            if not os.path.exists(pfx_path):
                return Response({
                    'error': f'Certificate file not found at: {pfx_path}'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Generate token
            token = generate_connectips_token(
                merchant_id=body['MERCHANTID'],
                app_id=body['APPID'],
                app_name=body['APPNAME'],
                txn_id=body['TXNID'],
                txn_date=body['TXNDATE'],
                txn_currency=body['TXNCRNCY'],
                txn_amount=body['TXNAMT'],
                reference_id=body['REFERENCEID'],
                remarks=body['REMARKS'],
                particulars=body['PARTICULARS'],
                pfx_path=pfx_path,
                pfx_password=pfx_password
            )
            
            # Return response with token
            return Response({
                **body,
                'TOKEN': token
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'error': f'Unexpected error: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


