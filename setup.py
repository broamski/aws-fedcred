from setuptools import setup, find_packages

setup(
    name='fedcred',
    version='0.0.1',
    description='Get AWS API Credentials When using an '
                'Identity Provider/Federation',
    author='Brian Nuszkowski',
    author_email='nuszkowski@protonmail.com',
    scripts=['bin/fedcred'],
    packages=find_packages(),
    url='https://github.com/broamski/aws-fedcred',
    install_requires=['beautifulsoup4>=4.4.1', 'boto3>=1.2.3',
                      'requests>=2.8.1']
)
