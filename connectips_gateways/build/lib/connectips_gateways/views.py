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
from cryptography.hazmat.primitives.serialization import pkcs12
import json
from datetime import datetime


class ConnectIpsPaymentViewSet(viewsets.ModelViewSet):
    """ViewSet for managing ConnectIPS Payment configurations"""

    queryset = CipsPayment.objects.all()
    serializer_class = ConnectIpsPaymentSerializer
    http_method_names = ['get', 'post', 'put', 'patch']

    def get_queryset(self):
        tenant_header = self.request.headers.get('Tenant-Header', self.request.headers.get('tenant_header'))
        return CipsPayment.objects.filter(tenant_header=tenant_header)

    def list(self, request):
        payments = self.get_queryset()
        serializer = ConnectIpsPaymentSerializer(payments, many=True)
        return Response({"data": serializer.data})

    def create(self, request):
        tenant_header = self.request.headers.get('Tenant-Header', self.request.headers.get('tenant_header'))
        if CipsPayment.objects.filter(tenant_header=tenant_header).exists():
            return Response({"status": 400, "message": "CipsPayment already configured for this tenant."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = ConnectIpsPaymentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(tenant_header=tenant_header)
            return Response({"status": 201, "message": "Created successfully", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        tenant_header = self.request.headers.get('Tenant-Header', self.request.headers.get('tenant_header'))
        try:
            payment = CipsPayment.objects.get(pk=pk, tenant_header=tenant_header)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found for this tenant"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ConnectIpsPaymentSerializer(payment, data=request.data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        tenant_header = self.request.headers.get('Tenant-Header', self.request.headers.get('tenant_header'))
        try:
            payment = CipsPayment.objects.get(pk=pk, tenant_header=tenant_header)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found for this tenant"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ConnectIpsPaymentSerializer(payment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Partially updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



def generate_connectips_token(merchant_id, app_id, app_name, txn_id, txn_date, 
                            txn_currency, txn_amount, reference_id, remarks, 
                            particulars, pfx_path, pfx_password):
    """
    Generate ConnectIPS payment token using the cryptography library
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
        
        # Read PFX file
        with open(pfx_path, 'rb') as pfx_file:
            pfx_data = pfx_file.read()
        
        # Load the PKCS12 bundle
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            pfx_data, 
            pfx_password.encode(),
            default_backend()
        )
        
        # Create signature
        message_bytes = message.encode()
        signature = private_key.sign(
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Convert to base64
        return base64.b64encode(signature).decode()
        
    except Exception as e:
        raise Exception(f"Token generation failed: {str(e)}")

class ConnectIpsTokenView(APIView):
    """API view for generating ConnectIPS token"""
    
    def post(self, request):
        try:
            # 1. Get request data
            body = request.data
            
            # 2. Get Tenant-Header
            tenant_header = request.headers.get('Tenant-Header')
            if not tenant_header:
                return Response({
                    "status":"404",
                    "error": "Tenant-Header not provided"
                }, status=404)

            # 3. Get ConnectIPS config based on Tenant-Header
            try:
                connectips_config = CipsPayment.objects.get(tenant_header=tenant_header)
            except CipsPayment.DoesNotExist:
                return Response({
                    "status":"404",
                    "error": "ConnectIPS configuration not found for tenant"
                }, status=404)

            # 4. Get PFX file path and password
            pfx_path = os.path.join(settings.MEDIA_ROOT, f'CREDITOR_{tenant_header}.pfx')
            if not os.path.exists(pfx_path):
                return Response({
                    "status":"404",
                    "error": f"Certificate file not found for tenant"
                }, status=404)

            # 5. Build params with default values from config
            required_fields = [
            "MERCHANTID", "APPID", "APPNAME", "TXNID", "TXNDATE",
            "TXNCRNCY", "TXNAMT", "REFERENCEID", "REMARKS", "PARTICULARS"
            ]
            # Ensure all required fields are present in the request body
            params = {
                "MERCHANTID": connectips_config.merchant_id,
                "APPID": connectips_config.app_id,  # Use from config
                "APPNAME": connectips_config.app_name,  # Use from config
                "TXNID": body.get('TXNID', ''),
                "TXNDATE": body.get('TXNDATE', ''),
                "TXNCRNCY": body.get('TXNCRNCY', 'NPR'),  # Default to NPR
                "TXNAMT": body.get('TXNAMT', ''),
                "REFERENCEID": body.get('REFERENCEID', ''),
                "REMARKS": body.get('REMARKS', ''),
                "PARTICULARS": body.get('PARTICULARS', '')
            }   

            # 6. Generate token
            try:
                token = generate_connectips_token(
                    merchant_id=params['MERCHANTID'],
                    app_id=params['APPID'],
                    app_name=params['APPNAME'],
                    txn_id=params['TXNID'],
                    txn_date=params['TXNDATE'],
                    txn_currency=params['TXNCRNCY'],
                    txn_amount=params['TXNAMT'],
                    reference_id=params['REFERENCEID'],
                    remarks=params['REMARKS'],
                    particulars=params['PARTICULARS'],
                    pfx_path=pfx_path,
                    pfx_password=connectips_config.creditor_password
                )
            except Exception as e:
                return Response({
                    "status":"500",
                    "error": f"Token generation failed: {str(e)}"
                }, status=500)

            # 7. Return token response
            return Response({
                
                "TOKEN": token
            }, status=200)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=500)


class UploadCreditorPfxView(APIView):
    def post(self, request):
        try:
            # 1. Get Tenant-Header
            tenant_header = request.headers.get('Tenant-Header')
            if not tenant_header:
                return Response({
                    "status":"404",
                    "error": "Tenant-Header not provided"
                }, status=404)

            # 2. Get ConnectIPS config based on Tenant-Header
            try:
                connectips_config = CipsPayment.objects.get(tenant_header=tenant_header)
            except CipsPayment.DoesNotExist:
                return Response({
                    "status":"404",
                    "error": "ConnectIPS configuration not found for tenant"
                }, status=404)

            # 3. Get the uploaded file
            file = request.FILES.get('file')
            if not file:
                return Response({
                    "error": "CREDITOR_.pfx file not provided"
                }, status=status.HTTP_400_BAD_REQUEST)

            # 4. Save the file to the correct location
            file_path = os.path.join(settings.MEDIA_ROOT, f'CREDITOR_{tenant_header}.pfx')
            with open(file_path, 'wb') as f:
                f.write(file.read())

            # 5. Update the ConnectIPS config with the new file path
            connectips_config.creditor_pfx_file = file_path
            connectips_config.save()

            return Response({
                "message": "CREDITOR_.pfx file uploaded successfully"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





class ConnectIpsSuccessUrl(APIView):
    """Handles ConnectIPS success callback and validates payment."""

    def get_transaction_details(self, request):
        """Get transaction details and validate required parameters"""
        txn_id = request.query_params.get('TXNID')
        txn_amt = request.query_params.get('TXNAMT')

        if not txn_id or not txn_amt:
            return None, None, Response(
                {"error": "Transaction ID or amount not provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        return txn_id, txn_amt, None

    def get_tenant_config(self, request):
        """Get tenant configuration and validate"""
        tenant_header = request.headers.get('Tenant-Header') or request.headers.get('tenant_header')
        if not tenant_header:
            return None, None, None, Response({
                "status": "404",
                "error": "Tenant-Header not provided"
            }, status=status.HTTP_404_NOT_FOUND)
        print("test")  
        connectips_config = CipsPayment.objects.first()
        print("connectips_config",connectips_config.merchant_id)

        if not connectips_config:
            return None, None, None, Response({
                "status": "404",
                "error": "ConnectIPS configuration not found for tenant"
            }, status=status.HTTP_404_NOT_FOUND)
  
        if not connectips_config:
            return None, None, None, Response({
                "status": "404",
                "error": "ConnectIPS configuration not found for tenant"
            }, status=status.HTTP_404_NOT_FOUND)

        pfx_path = os.path.join(settings.MEDIA_ROOT, f'CREDITOR_{tenant_header}.pfx')
        if not os.path.exists(pfx_path):
            return None, None, None, Response({
                "status": "404",
                "error": "Certificate file not found for tenant"
            }, status=status.HTTP_404_NOT_FOUND)

        return tenant_header, connectips_config, pfx_path, None

    def validate_payment(self, txn_id, txn_amt, merchant_id, app_id, password, validate_url, pfx_path, pfx_password):
        """Validate payment with ConnectIPS"""
        try:
            token_message = f"MERCHANTID={merchant_id},APPID={app_id},REFERENCEID={txn_id},TXNAMT={txn_amt}"
            print("token_message", token_message)

            token = self.generate_digital_signature(token_message, pfx_path, pfx_password)
            print("Generated token:", token)

            print(merchant_id, app_id, txn_id, txn_amt, token ,password)
            payload = {
                "merchantId": merchant_id,
                "appId": app_id,
                "referenceId": txn_id,
                "txnAmt": txn_amt,
                "token": token
            }

            print("payload", payload)

            response = requests.post(
                validate_url,
                json=payload,
                auth=(app_id, password)
            )

            print("ConnectIPS response status:", response.status_code)
            print("ConnectIPS response body:", response.text)

            # ✅ Return the response to the calling function
            return response.json() if response.ok else {"error": "ConnectIPS returned error", "status_code": response.status_code, "body": response.text}

        except Exception as e:
            return {"error": f"Validation failed: {str(e)}"}

    def generate_digital_signature(self, message, pfx_path, pfx_password):
        """Generate digital signature using the creditor's certificate"""
        try:
            with open(pfx_path, 'rb') as pfx_file:
                pfx_data = pfx_file.read()
            print("pfx_data",pfx_data)
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                pfx_data,
                pfx_password.encode(),
                backend=default_backend()
            )

            signature = private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return base64.b64encode(signature).decode()
        except Exception as e:
            raise Exception(f"Digital signature generation failed: {str(e)}")

    def get(self, request):
        """Handle GET request for success URL"""
        # Step 1: Get transaction info
        txn_id, txn_amt, error = self.get_transaction_details(request)
        if error:
            return error

        # Step 2: Get tenant-specific config
        tenant_header, config, pfx_path, error = self.get_tenant_config(request)
        if error:
            return error

        # Step 3: Validate payment
        result = self.validate_payment(
            txn_id=txn_id,
            txn_amt=txn_amt,
            merchant_id=config.merchant_id,
            app_id=config.app_id,
            password=config.password,
            validate_url=config.validation_url,
            pfx_path=pfx_path,
            pfx_password=config.creditor_password
        )

        return Response(result)

        

class ConnectIpsFailureUrl(APIView):
    
    def get(self, request):
        txn_id = request.query_params.get('TXNID')
        txn_amt = request.query_params.get('TXNAMT')

        if not txn_id or not txn_amt:
            return Response(
                {"error": "Transaction ID or amount not provided"},
                status=status.HTTP_400_BAD_REQUEST
            )

        tenant_header = request.headers.get('Tenant-Header')
        if not tenant_header:
            return Response({
                "status": "404",
                "error": "Tenant-Header not provided"
            }, status=status.HTTP_404_NOT_FOUND)

        try:
            connectips_config = CipsPayment.objects.first()
            print(connectips_config)
        except CipsPayment.DoesNotExist:
            return Response({
                "status": "404",
                "error": "ConnectIPS configuration not found for tenant"
            }, status=status.HTTP_404_NOT_FOUND)

        pfx_path = os.path.join(settings.MEDIA_ROOT, f'CREDITOR_{tenant_header}.pfx')
        if not os.path.exists(pfx_path):
            return Response({
                "status": "404",
                "error": "Certificate file not found for tenant"
            }, status=status.HTTP_404_NOT_FOUND)

        try:
            # Validate the payment even on failure
            validation_result = self.validate_payment(
                txn_id=txn_id,
                txn_amt=txn_amt,
                merchant_id=connectips_config.merchant_id,
                app_id=connectips_config.app_id,
                password=connectips_config.password,
                validate_url=connectips_config.validation_url,
                pfx_path=pfx_path,
                pfx_password=connectips_config.creditor_password
            )
            print("validation_result",validation_result)

            return Response(
                {
                    "message": "Failure",
                    "transaction_id": txn_id,
                    "validation_result": validation_result
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response({
                "error": f"Validation failed: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def validate_payment(self, txn_id, txn_amt, merchant_id, app_id, password, validate_url, pfx_path, pfx_password):
        """Validate payment with ConnectIPS"""
        try:
            token_message = f"MERCHANTID={merchant_id},APPID={app_id},REFERENCEID={txn_id},TXNAMT={txn_amt}"
            print("token_message", token_message)

            token = self.generate_digital_signature(token_message, pfx_path, pfx_password)
            print("Generated token:", token)

            print(merchant_id, app_id, txn_id, txn_amt, token ,password)
            payload = {
                "merchantId": merchant_id,
                "appId": app_id,
                "referenceId": txn_id,
                "txnAmt": txn_amt,
                "token": token
            }

            print("payload", payload)

            response = requests.post(
                validate_url,
                json=payload,
                auth=(app_id, password)
            )

            print("ConnectIPS response status:", response.status_code)
            print("ConnectIPS response body:", response.text)

            # ✅ Return the response to the calling function
            return response.json() if response.ok else {"error": "ConnectIPS returned error", "status_code": response.status_code, "body": response.text}

        except Exception as e:
            return {"error": f"Validation failed: {str(e)}"}

    def generate_digital_signature(message, pfx_path, pfx_password):
        """Generate digital signature using the creditor's certificate"""
        try:
            print("pfx_path",pfx_path)
            print("pfx_password",pfx_password)
            print("message",message)
            # Read the PFX file
            with open(pfx_path, 'rb') as pfx_file:
                pfx_data = pfx_file.read()

            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                pfx_data,
                pfx_password.encode()  # no default_backend()
            )
            print("✅ PFX file opened successfully.")
            print("private_key",private_key)
            print("certificate",certificate)
            print("additional_certificates",additional_certificates)

            if private_key is None:
                raise ValueError("Private key not found in PFX file.")

            signature = private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            print("Generated signature (raw bytes):", signature)
            return base64.b64encode(signature).decode()

        except Exception as e:
            raise Exception(f"Digital signature generation failed: {str(e)}")

