from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ConnectIpsPaymentViewSet,
    ConnectIpsSuccessUrl,
    ConnectIpsFailureUrl,
    ConnectIpsTokenView,
    UploadCreditorPfxView,

)

router = DefaultRouter()
router.register(r'cips', ConnectIpsPaymentViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('cips-payment/success/', ConnectIpsSuccessUrl.as_view()),
    path('cips-payment/failure/', ConnectIpsFailureUrl.as_view()),
    path('cips-payment/generate-token/', ConnectIpsTokenView.as_view()),
    path('cips-payment/upload/', UploadCreditorPfxView.as_view())
]




