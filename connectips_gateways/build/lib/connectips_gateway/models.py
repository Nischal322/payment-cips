from django.db import models

class CipsPayment(models.Model):
    gateway_url = models.CharField(max_length=255)
    merchant_id = models.CharField(max_length=255)
    app_id = models.CharField(max_length=255)
    app_name = models.CharField(max_length=255)
    validation_url = models.CharField(max_length=255)  # Fixed typo
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    creditor_password = models.CharField(max_length=255)


    def __str__(self):
        return self.merchant_id  # Fixed field reference
