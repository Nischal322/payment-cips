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


# ----------------- ConnectIPS Config Management ------------------

class ConnectIpsPaymentViewSet(viewsets.ModelViewSet):
    queryset = CipsPayment.objects.all()
    serializer_class = ConnectIpsPaymentSerializer
    http_method_names = ['get', 'post', 'put', 'patch']

    def list(self, request):
        payments = self.get_queryset()
        serializer = self.get_serializer(payments, many=True)
        return Response({"data": serializer.data})

    def create(self, request):
        if CipsPayment.objects.exists():
            return Response(
                {"status": 400, "message": "CipsPayment already configured."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"status": 201, "message": "Created successfully", "data": serializer.data},
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
            serializer.save()
            return Response({"message": "Partially updated successfully", "data": serializer.data})
        return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


# ----------------- Token Generator ------------------

def generate_connectips_token(merchant_id, app_id, app_name, txn_id, txn_date,
                               txn_currency, txn_amount, reference_id, remarks,
                               particulars, pfx_path, pfx_password):
    try:
        message = (
            f"MERCHANTID={merchant_id},APPID={app_id},APPNAME={app_name},"
            f"TXNID={txn_id},TXNDATE={txn_date},TXNCRNCY={txn_currency},"
            f"TXNAMT={txn_amount},REFERENCEID={reference_id},REMARKS={remarks},"
            f"PARTICULARS={particulars},TOKEN=TOKEN"
        )

        with open(pfx_path, 'rb') as pfx_file:
            pfx_data = pfx_file.read()

        private_key, _, _ = pkcs12.load_key_and_certificates(
            pfx_data, pfx_password.encode(), default_backend()
        )

        signature = private_key.sign(
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return base64.b64encode(signature).decode()

    except Exception as e:
        raise Exception(f"Token generation failed: {str(e)}")


class ConnectIpsTokenView(APIView):
    def post(self, request):
        try:
            body = request.data
            config = CipsPayment.objects.first()
            if not config:
                return Response({"error": "ConnectIPS configuration not found"}, status=404)

            pfx_path = os.path.join(settings.MEDIA_ROOT, f"CREDITOR.pfx")
            if not os.path.exists(pfx_path):
                return Response({"error": "PFX certificate not found"}, status=404)

            params = {
                "MERCHANTID": config.merchant_id,
                "APPID": config.app_id,
                "APPNAME": config.app_name,
                "TXNID": body.get("TXNID", ""),
                "TXNDATE": body.get("TXNDATE", ""),
                "TXNCRNCY": body.get("TXNCRNCY", "NPR"),
                "TXNAMT": body.get("TXNAMT", ""),
                "REFERENCEID": body.get("REFERENCEID", ""),
                "REMARKS": body.get("REMARKS", ""),
                "PARTICULARS": body.get("PARTICULARS", "")
            }

            token = generate_connectips_token(
                merchant_id=params["MERCHANTID"],
                app_id=params["APPID"],
                app_name=params["APPNAME"],
                txn_id=params["TXNID"],
                txn_date=params["TXNDATE"],
                txn_currency=params["TXNCRNCY"],
                txn_amount=params["TXNAMT"],
                reference_id=params["REFERENCEID"],
                remarks=params["REMARKS"],
                particulars=params["PARTICULARS"],
                pfx_path=pfx_path,
                pfx_password=config.creditor_password
            )

            return Response({"TOKEN": token})

        except Exception as e:
            return Response({"error": str(e)}, status=500)


# ----------------- Upload Creditor Certificate ------------------

class UploadCreditorPfxView(APIView):
    def post(self, request):
        try:
            tenant_header = request.headers.get('Tenant-Header')
            if not tenant_header:
                return Response({"error": "Tenant-Header not provided"}, status=400)

            config = CipsPayment.objects.first()
            if not config:
                return Response({"error": "ConnectIPS configuration not found"}, status=404)

            file = request.FILES.get("file")
            if not file:
                return Response({"error": "No file uploaded"}, status=400)

            path = os.path.join(settings.MEDIA_ROOT, f"CREDITOR_{tenant_header}.pfx")
            with open(path, 'wb') as f:
                f.write(file.read())

            config.creditor_pfx_file = path
            config.save()

            return Response({"message": "PFX uploaded successfully"}, status=200)

        except Exception as e:
            return Response({"error": str(e)}, status=500)


# ----------------- Success and Failure Callback ------------------

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

            return response.json() if response.ok else {
                "error": "ConnectIPS error",
                "status": response.status_code,
                "body": response.text
            }

        except Exception as e:
            return {"error": f"Validation failed: {str(e)}"}


class ConnectIpsSuccessUrl(BaseCallback):
    def get(self, request):
        txn_id, txn_amt, error = self.get_transaction_details(request)
        if error:
            return error

        config = CipsPayment.objects.first()
        if not config:
            return Response({"error": "ConnectIPS configuration not found"}, status=404)

        pfx_path = os.path.join(settings.MEDIA_ROOT, "CREDITOR.pfx")
        if not os.path.exists(pfx_path):
            return Response({"error": "PFX file not found"}, status=404)

        result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
        return Response(result)


class ConnectIpsFailureUrl(BaseCallback):
    def get(self, request):
        txn_id, txn_amt, error = self.get_transaction_details(request)
        if error:
            return error

        config = CipsPayment.objects.first()
        if not config:
            return Response({"error": "ConnectIPS configuration not found"}, status=404)

        pfx_path = os.path.join(settings.MEDIA_ROOT, "CREDITOR.pfx")
        if not os.path.exists(pfx_path):
            return Response({"error": "PFX file not found"}, status=404)

        result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
        return Response(result)
