import base64
import os
import requests
from rest_framework import status, viewsets
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from .models import CipsPayment
from .serializers import ConnectIpsPaymentSerializer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import pkcs12


class ConnectIpsPaymentViewSet(viewsets.ModelViewSet):
    queryset = CipsPayment.objects.all()
    serializer_class = ConnectIpsPaymentSerializer
    http_method_names = ['get', 'post', 'put', 'patch']

    def get_serializer_context(self):
        # Ensure the request is available in the serializer context
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    def list(self, request):
        payments = self.get_queryset()
        serializer = self.get_serializer(payments, many=True)
        return Response({"data": serializer.data})

    def create(self, request):
        if CipsPayment.objects.exists():
            return Response(
                {"message": "CipsPayment already configured."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate PFX file
        file = request.FILES.get("file")
        if not file:
            return Response({"error": "No file uploaded"}, status=400)

        if not file.name.lower().endswith('.pfx'):
            return Response({"error": "Only .pfx files are allowed"}, status=400)

        # Validate and save serialized CipsPayment data
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            instance = serializer.save()

            # Save the PFX file
            tenant_header = request.headers.get('Tenant-Header')
            if not tenant_header:
                return Response({"error": "Tenant-Header not provided"}, status=400)

            file_name = f"CREDITOR_{tenant_header}.pfx"
            file_path = os.path.join(settings.MEDIA_ROOT, file_name)

            with open(file_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            # Save file path to the instance
            instance.creditor_pfx_file = file_path
            instance.save()

            return Response(
                {"message": "Created successfully", "data": serializer.data},
                status=status.HTTP_201_CREATED
            )

        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        try:
            payment = self.get_queryset().get(pk=pk)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(payment, data=request.data)
        if serializer.is_valid():
            file = request.FILES.get("file")

            # If file is provided, validate and store it
            if file:
                if not file.name.lower().endswith('.pfx'):
                    return Response({"error": "Only .pfx files are allowed"}, status=400)

                tenant_header = request.headers.get('Tenant-Header')
                if not tenant_header:
                    return Response({"error": "Tenant-Header not provided"}, status=400)

                file_name = f"CREDITOR_{tenant_header}.pfx"
                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                with open(file_path, 'wb') as f:
                    for chunk in file.chunks():
                        f.write(chunk)

                # Update file path in the instance
                payment.creditor_pfx_file = file_path

            serializer.save()
            return Response({"message": "Updated successfully", "data": serializer.data})

        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


    def partial_update(self, request, pk=None):
        try:
            payment = self.get_queryset().get(pk=pk)
        except CipsPayment.DoesNotExist:
            return Response({"error": "Payment not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(payment, data=request.data, partial=True)
        if serializer.is_valid():
            file = request.FILES.get("file")

            # If file is provided, validate and store it
            if file:
                if not file.name.lower().endswith('.pfx'):
                    return Response({"error": "Only .pfx files are allowed"}, status=400)

                tenant_header = request.headers.get('Tenant-Header')
                if not tenant_header:
                    return Response({"error": "Tenant-Header not provided"}, status=400)

                file_name = f"CREDITOR_{tenant_header}.pfx"
                file_path = os.path.join(settings.MEDIA_ROOT, file_name)

                with open(file_path, 'wb') as f:
                    for chunk in file.chunks():
                        f.write(chunk)

                # Update file path in the instance
                payment.creditor_pfx_file = file_path

            serializer.save()
            return Response({"message": "Partially updated successfully", "data": serializer.data})

        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



def generate_connectips_token(merchant_id, app_id, app_name, txn_id, txn_date,
                               txn_currency, txn_amount, reference_id, remarks,
                               particulars, pfx_path, pfx_password):
    message = (
        f"MERCHANTID={merchant_id},APPID={app_id},APPNAME={app_name},"
        f"TXNID={txn_id},TXNDATE={txn_date},TXNCRNCY={txn_currency},"
        f"TXNAMT={txn_amount},REFERENCEID={reference_id},REMARKS={remarks},"
        f"PARTICULARS={particulars},TOKEN=TOKEN"
    )

    with open(pfx_path, 'rb') as pfx_file:
        pfx_data = pfx_file.read()

    try:
        private_key, _, _ = pkcs12.load_key_and_certificates(
            pfx_data, pfx_password.encode(), default_backend()
        )
    except ValueError:
        # This will be caught by your view
        raise ValueError("Invalid PFX certificate or password.")

    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()


class ConnectIpsTokenView(APIView):
    def post(self, request):
        try:
            tenant_header = request.headers.get("Tenant-Header")
            if not tenant_header:
                return Response({"error": "Tenant-Header not provided"}, status=400)

            # Using first config (assumed shared across tenants for now)
            config = CipsPayment.objects.first()
            if not config:
                return Response({"error": "ConnectIPS configuration not found"}, status=404)

            # Construct tenant-specific PFX path
            pfx_path = os.path.join(settings.MEDIA_ROOT, f"CREDITOR_{tenant_header}.pfx")
            if not os.path.exists(pfx_path):
                return Response({"error": f"PFX certificate not found for tenant: {tenant_header}"}, status=404)

            body = request.data

            token = generate_connectips_token(
                merchant_id=config.merchant_id,
                app_id=config.app_id,
                app_name=config.app_name,
                txn_id=body.get("TXNID", ""),
                txn_date=body.get("TXNDATE", ""),
                txn_currency=body.get("TXNCRNCY", "NPR"),
                txn_amount=body.get("TXNAMT", ""),
                reference_id=body.get("REFERENCEID", ""),
                remarks=body.get("REMARKS", ""),
                particulars=body.get("PARTICULARS", ""),
                pfx_path=pfx_path,
                pfx_password=config.creditor_password
            )

            return Response({
                "TOKEN": token,
                "gateway_url": config.gateway_url,
                "merchant_id": config.merchant_id,
                "app_id": config.app_id,
                "app_name": config.app_name,
                "txn_id": body.get("TXNID", ""),
                "txn_date": body.get("TXNDATE", ""),
                "txn_currency": body.get("TXNCRNCY", "NPR"),
                "txn_amount": body.get("TXNAMT", ""),
                "reference_id": body.get("REFERENCEID", ""),
                "remarks": body.get("REMARKS", ""),
                "particulars": body.get("PARTICULARS", ""),
                "pfx_used": os.path.basename(pfx_path),
            })

        except Exception as e:
            return Response({"error": str(e)}, status=400)



class UploadCreditorPfxView(APIView):
    def post(self, request):
        try:
            tenant_header = request.headers.get('Tenant-Header')
            if not tenant_header:
                return Response({"error": "Tenant-Header not provided"}, status=400)

            # Fetch configuration for the specific tenant
            config = CipsPayment.objects.first()  # Adjust this if needed for tenant filtering
            if not config:
                return Response({"error": "ConnectIPS configuration not found for tenant"}, status=404)

            file = request.FILES.get("file")
            if not file:
                return Response({"error": "No file uploaded"}, status=400)

            # Validate file extension
            if not file.name.lower().endswith('.pfx'):
                return Response({"error": "Only .pfx files are allowed"}, status=400)

            # Directly use tenant_header in the filename
            file_name = f"CREDITOR_{tenant_header}.pfx"
            file_path = os.path.join(settings.MEDIA_ROOT, file_name)

            with open(file_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            config.creditor_pfx_file = file_path
            config.save()

            return Response({"message": "PFX uploaded successfully"}, status=200)

        except Exception as e:
            return Response({"error": str(e)}, status=500)
class BaseCallback(APIView):
    def get_transaction_details(self, request):
        txn_id = request.query_params.get("TXNID")
        txn_amt = request.query_params.get("TXNAMT")
        if not txn_id or not txn_amt:
            return None, None, Response({"error": "TXNID or TXNAMT missing"}, status=400)
        return txn_id, txn_amt, None

    def validate_payment(self, txn_id, txn_amt, config, pfx_path):
        try:
            message = f"MERCHANTID={config.merchant_id},APPID={config.app_id},REFERENCEID={txn_id},TXNAMT={txn_amt}"

            with open(pfx_path, 'rb') as f:
                pfx_data = f.read()

            private_key, _, _ = pkcs12.load_key_and_certificates(
                pfx_data, config.creditor_password.encode(), default_backend()
            )

            signature = private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            token = base64.b64encode(signature).decode()

            response = requests.post(
                config.validation_url,
                json={
                    "merchantId": config.merchant_id,
                    "appId": config.app_id,
                    "referenceId": txn_id,
                    "txnAmt": txn_amt,
                    "token": token
                },
                auth=(config.app_id, config.password)
            )

            if response.ok:
                try:
                    data = response.json()
                    body = data.get("body", "")
                    if isinstance(body, str) and "bad credentials" in body.lower():
                        raise Exception("Bad credentials")
                    return data
                except Exception as e:
                    raise Exception(f"Response parse error: {str(e)}")
            else:
                if response.status_code == 401:
                    raise Exception("Bad credentials")
                raise Exception(f"ConnectIPS error: {response.status_code}")

        except Exception as e:
            raise Exception(f"{str(e)}")


class ConnectIpsSuccessUrl(BaseCallback):
    def get(self, request):
        txn_id, txn_amt, error = self.get_transaction_details(request)
        if error:
            return error

        tenant_header = request.headers.get("Tenant-Header")
        if not tenant_header:
            return Response({"error": "Tenant-Header not provided"}, status=400)

        config = CipsPayment.objects.first()
        if not config:
            return Response({"error": "ConnectIPS configuration not found"}, status=404)

        pfx_path = os.path.join(settings.MEDIA_ROOT, f"CREDITOR_{tenant_header}.pfx")
        if not os.path.exists(pfx_path):
            return Response({"error": f"PFX file not found for tenant: {tenant_header}"}, status=404)

        try:
            result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
            return Response({
                "message": "Transaction validated successfully",
                "data": result,
                "pfx_used": os.path.basename(pfx_path)  # Optional for debugging
            }, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)



class ConnectIpsFailureUrl(BaseCallback):
    def get(self, request):
        txn_id, txn_amt, error = self.get_transaction_details(request)
        if error:
            return error

        tenant_header = request.headers.get("Tenant-Header")
        if not tenant_header:
            return Response({"error": "Tenant-Header not provided"}, status=400)

        config = CipsPayment.objects.first()
        if not config:
            return Response({"error": "ConnectIPS configuration not found"}, status=404)

        pfx_path = os.path.join(settings.MEDIA_ROOT, f"CREDITOR_{tenant_header}.pfx")
        if not os.path.exists(pfx_path):
            return Response({"error": f"PFX file not found for tenant: {tenant_header}"}, status=404)

        try:
            result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
            return Response({
                "message": "Validation attempted on failure callback",
                "data": result,
                "pfx_used": os.path.basename(pfx_path)  # Optional for debugging
            }, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
