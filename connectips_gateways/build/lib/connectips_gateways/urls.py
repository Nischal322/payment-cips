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
router.register(r'cipspayment', ConnectIpsPaymentViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('success/', ConnectIpsSuccessUrl.as_view()),
    path('failure/', ConnectIpsFailureUrl.as_view()),
    path('Notification/', ConnectIpsTokenView.as_view(), name='connectips_redirect'),
    path('upload/', UploadCreditorPfxView.as_view(), name='upload_creditor')
]




