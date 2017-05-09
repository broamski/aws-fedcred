fedcred: Obtain AWS API Credentials when using Federation/Identity Providers to authenticate to AWS
===================================================================================================


The following identity providers are currently supported:

* Active Directory Federation Services (ADFS)
* Okta

Installation:
-------------

Option 1
~~~~~~~~
.. code-block:: sh

    $ pip install fedcred

Option 2
~~~~~~~~

.. code-block:: sh

    1. Clone this repo
    2. $ python setup.py install


Config File Setup
----------------------

The configuation file is named ``fedcred.config`` and should exist in the users home directory.

.. code-block:: ini
    
    [fedcred]
    provider = {okta, adfs}
    aws_credential_profile = default
    sslverify = True
    
    [okta]
    organization = <yourorg>.okta.com
    app_url = <okta application url>
    
    [adfs]
    ntlmauth = {True, False}
    url = https://<adfs fqdn>/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices


Usage
-----

.. code-block:: sh

    $ fedcred
