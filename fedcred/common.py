import base64
import boto3
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import getpass
import os
import sys

import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup


DEFAULT_CONFIG_SECTION = 'fedcred'
DEFAULT_CONFIG_FILE = 'fedcred.config'


def read_config():
    CONFIG_PATH = '%s/%s' % (os.path.expanduser('~'), DEFAULT_CONFIG_FILE)
    valid_providers = ['okta', 'adfs']
    config = configparser.ConfigParser()
    if not os.path.isfile(CONFIG_PATH):
        config.add_section(DEFAULT_CONFIG_SECTION)
        config.set(DEFAULT_CONFIG_SECTION, 'sslverify', 'True')
        config.set(
            DEFAULT_CONFIG_SECTION, 'aws_credential_profile', 'federated')
        with open(CONFIG_PATH, 'w') as configfile:
            config.write(configfile)
    if os.path.isfile(CONFIG_PATH):
        config.read(CONFIG_PATH)
        if not config.has_section(DEFAULT_CONFIG_SECTION):
            sys.exit(
                "Default section '%s' is required." % (DEFAULT_CONFIG_SECTION,))
        try:
            if config.get(
                    DEFAULT_CONFIG_SECTION, 'provider') not in valid_providers:
                print("'%s' is not a valid authentication provider" % (
                    config.get(DEFAULT_CONFIG_SECTION, 'provider'),))
            return config
        except configparser.NoOptionError:
            sys.exit(
                "Default section '%s' must have a 'provider' option" %
                (DEFAULT_CONFIG_SECTION,)
            )
    else:
        sys.exit("Could not find config file.")


def get_user_credentials(prompt=None):
    if prompt is None:
        prompt_msg = 'Enter you username: '
    try:
        username = raw_input(prompt_msg).strip()
    except NameError:
        username = input(prompt_msg).strip()
    password = getpass.getpass(prompt='Enter your password: ')
    return username, password


def get_saml_assertion(response):
    """Parses a requests.Response object that contains a SAML assertion.
    Returns an base64 encoded SAML Assertion if one is found"""
    # Decode the requests.Response object and extract the SAML assertion
    soup = BeautifulSoup(response.text, "html.parser")
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            return inputtag.get('value')


def get_arns_from_assertion(assertion):
    """Parses a base64 encoded SAML Assertion and extracts the role and
    principle ARNs to be used when making a request to STS.
    Returns a dict with RoleArn, PrincipalArn & SAMLAssertion that can be
    used to call assume_role_with_saml"""
    # Parse the returned assertion and extract the principle and role ARNs
    root = ET.fromstring(base64.b64decode(assertion))
    urn = "{urn:oasis:names:tc:SAML:2.0:assertion}"
    urn_attribute = urn + "Attribute"
    urn_attributevalue = urn + "AttributeValue"
    role_url = "https://aws.amazon.com/SAML/Attributes/Role"
    raw_roles = []
    for saml2attribute in root.iter(urn_attribute):
        if (saml2attribute.get('Name') == role_url):
            for saml2attributevalue in saml2attribute.iter(urn_attributevalue):
                raw_roles.append(saml2attributevalue.text)
    parsed_roles = []
    for role in raw_roles:
        arns = role.split(',')
        arn_dict = {}
        for arn in arns:
            arn = arn.strip()
            if ":role/" in arn:
                arn_dict['RoleArn'] = arn
            elif ":saml-provider/":
                arn_dict['PrincipalArn'] = arn
        arn_dict['SAMLAssertion'] = assertion
        parsed_roles.append(arn_dict)

    if len(parsed_roles) > 1:
        print('\nPlease choose a Role you would like to assume:')
        print('----------------------------------------------\n')
        for i in range(0, len(parsed_roles)):
            print('Role [ %s ]: %s' % (i, parsed_roles[i]['RoleArn']))
        print('\n')
        role_choice_msg = 'Enter the role number you would like to assume: '
        try:
            role_choice = raw_input(role_choice_msg).strip()
        except NameError:
            role_choice = input(role_choice_msg).strip()
    else:
        role_choice = 0
    role_choice = int(role_choice)
    if role_choice > (len(parsed_roles) - 1):
        sys.exit('Sorry, that is not a valid role choice.')
    print('Success. You have obtained crentials for the assumed role of: %s' % (
        parsed_roles[role_choice]['RoleArn'],))
    return parsed_roles[role_choice]


def get_sts_creds(arn):
    client = boto3.client('sts')
    response = client.assume_role_with_saml(
        RoleArn=arn['RoleArn'],
        PrincipalArn=arn['PrincipalArn'],
        SAMLAssertion=arn['SAMLAssertion'],
    )
    creds = response['Credentials']
    return creds


def write_credentials(profile, creds):
    aws_creds_path = '%s/.aws/credentials' % (os.path.expanduser('~'),)
    config = configparser.ConfigParser()
    creds_folder = os.path.dirname(aws_creds_path)
    if not os.path.isdir(creds_folder):
        os.makedirs(creds_folder)
    if os.path.isfile(aws_creds_path):
        config.read(aws_creds_path)
    if not config.has_section(profile):
        if profile == 'default':
            configparser.DEFAULTSECT = profile
            if sys.version_info.major == 3:
                config.add_section(profile)
            config.set(profile, 'CREATE', 'TEST')
            config.remove_option(profile, 'CREATE')
        else:
            config.add_section(profile)

    options = [
        ('aws_access_key_id', 'AccessKeyId'),
        ('aws_secret_access_key', 'SecretAccessKey'),
        ('aws_session_token', 'SessionToken'),
        ('aws_security_token', 'SessionToken'),
        ('expiration', 'Expiration')
    ]

    for option, value in options:
        config.set(
            profile,
            option,
            str(creds[value])
        )

    with open(aws_creds_path, 'w') as configfile:
        config.write(configfile)
    print('Crentials successfully written to %s' % (aws_creds_path,))
