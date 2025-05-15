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
    path('cips/success/', ConnectIpsSuccessUrl.as_view()),
    path('cips/failure/', ConnectIpsFailureUrl.as_view()),
    path('cips/Notification/', ConnectIpsTokenView.as_view(), name='connectips_redirect'),
    path('cips/upload/', UploadCreditorPfxView.as_view(), name='upload_creditor')
]




