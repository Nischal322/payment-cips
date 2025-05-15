from setuptools import setup, find_packages

setup(
    name='connectips_gateways',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Django>=4.2.7',
        'djangorestframework>=3.14.0',
        'cryptography>=41.0.0',
        'pyOpenSSL>=23.2.0',
        'requests>=2.31.0',
    ],
    author='Your Name',
    author_email='your.email@example.com',
    description='ConnectIPS Payment Gateway Integration for Django',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/connectips_gateways',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'Framework :: Django :: 4.2',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    python_requires='>=3.8',
    package_data={
        'connectips_gateways': [
            'CREDITOR.pfx',
        ],
    },
    entry_points={
        'console_scripts': [
            'connectips-gateway=connectips_gateways.manage:main',
        ],
    },
)
