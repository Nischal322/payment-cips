ConnectipsGateways
ConnectipsGateways is a Django app that provides a custom payment gateway integration for processing transactions through the Connectips payment system.
Features

Seamless integration with Django projects
Multi-tenant support via header-based authentication
RESTful API endpoints for payment processing
Database models for transaction tracking and management

Installation

Install the package using pip:

pip install nps-payment-gateways
Or add it directly to your requirements.txt file.
Setup

Add to INSTALLED_APPS
In your settings.py, include:
python
INSTALLED_APPS = [
...
'connectips_gateways',
]

Add URLs to your project in core
In your main urls.py, include the app's URLs:
pythonfrom django.urls import path, include

urlpatterns = [
...
path('api/', include('connectips_gateways.urls')),
]

Run migrations\

<!-- Migrate in tenant  -->

python manage.py makemigrations connectips_gateways
python manage.py migrate
