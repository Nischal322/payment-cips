# ConnectIPS Gateway

A Django package for integrating ConnectIPS payment gateway into your Django applications.

## Installation

```bash
pip install connectips-gateway
```

## Configuration

1. Add 'connectips_gateways' to your INSTALLED_APPS in settings.py:

```python
INSTALLED_APPS = [
    ...
    'connectips_gateways',
    ...
]
```

2. Add the ConnectIPS URLs to your main urls.py:

```python
urlpatterns = [
    ...
    path('connectips/', include('connectips_gateways.urls')),
    ...
]
```

3. Place your CREDITOR.pfx certificate file in the connectips_gateway directory.

4. Configure your ConnectIPS settings in the Django admin panel or through the API.

## Usage


MIT License
