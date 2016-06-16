import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.1'

install_requires = [
    'acme',
    'certbot',
    'f5-icontrol-rest',
    'setuptools>=1.0',
    'zope.component',
    'zope.interface',
]

setup(
    name='certbot-bigip',
    version=version,
    description='F5 BIG-IP plugin for Certbot',
    url='https://github.com/colin-stubbs/certbot-bigip',
    author='Colin Stubbs',
    author_email='cstubbs@gmail.com',
    license='Apache License 2.0',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={},

    entry_points={
        'certbot.plugins': [
            'bigip = certbot_bigip.configurator:BigipConfigurator',
        ],
    },
    test_suite='certbot_bigip',
)
