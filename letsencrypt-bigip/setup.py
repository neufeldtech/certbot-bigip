import sys

from setuptools import setup
from setuptools import find_packages

version = '0.0.1'

install_requires = [
    'f5-icontrol-rest',
]

def read_file(filename, encoding='utf8'):
    """Read unicode from given file."""
    with codecs.open(filename, encoding=encoding) as fd:
        return fd.read()

here = os.path.abspath(os.path.dirname(__file__))
readme = read_file(os.path.join(here, 'README.rst'))

install_requires = [
    'certbot-bigip',
    'letsencrypt=={0}'.format(version),
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
)
