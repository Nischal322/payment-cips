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

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
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

            pfx_path = os.path.join(settings.MEDIA_ROOT, "CREDITOR.pfx")
            if not os.path.exists(pfx_path):
                return Response({"error": "PFX certificate not found"}, status=404)

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

            return Response({"TOKEN": token})

        except Exception as e:
            return Response({"error": str(e)}, status=400)


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

            # Validate file extension
            if not file.name.lower().endswith('.pfx'):
                return Response({"error": "Only .pfx files are allowed"}, status=400)


            path = os.path.join(settings.MEDIA_ROOT, "CREDITOR.pfx")
            with open(path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            config.creditor_pfx_file = path
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

        config = CipsPayment.objects.first()
        if not config:
            return Response({"error": "ConnectIPS configuration not found"}, status=404)

        pfx_path = os.path.join(settings.MEDIA_ROOT, "CREDITOR.pfx")
        if not os.path.exists(pfx_path):
            return Response({"error": "PFX file not found"}, status=404)

        try:
            result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
            return Response({"message": "Transaction validated successfully", "data": result}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


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

        try:
            result = self.validate_payment(txn_id, txn_amt, config, pfx_path)
            return Response({"message": "Validation attempted on failure callback", "data": result}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)
