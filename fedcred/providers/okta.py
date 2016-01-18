try:
    from configparser import NoOptionError, NoSectionError
except ImportError:
    from ConfigParser import NoOptionError, NoSectionError
import json
import requests
import sys

from fedcred import common


class Okta(object):
    def __init__(self, config):
        self.config = config
        try:
            self.okta_org = self.config.get('okta', 'organization')
            self.auth_url = "https://" + self.okta_org + "/api/v1/authn"
            self.app_url = self.config.get('okta', 'app_url')
        except (NoOptionError, NoSectionError) as e:
            sys.exit(e.message)
        self.headers_dict = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def second_factor(self, factor, state_token):
        session = requests.Session()
        response = session.post(
            factor['_links']['verify']['href'],
            headers=self.headers_dict,
            data=json.dumps({"stateToken": state_token})
        )
        try:
            passcode_input = raw_input
        except NameError:
            passcode_input = input
        passcode = passcode_input("Please provide your one-time passcode: ")
        session = requests.Session()
        response = session.post(
            factor['_links']['verify']['href'],
            headers=self.headers_dict,
            data=json.dumps(
                {"stateToken": state_token,
                 "passCode": passcode
                 })
        )
        if response.status_code != 200:
            sys.exit("Second factor verification failed: %s" %
                     (json.loads(response.text)['errorSummary']),)
        return response

    def process_success(self, response):
        session_token = json.loads(response.text)['sessionToken']
        session = requests.Session()
        saml = session.get(self.app_url + "?onetimetoken=" + session_token)
        assertion = common.get_saml_assertion(saml)
        arn_dict = common.get_arns_from_assertion(assertion)
        sts_creds = common.get_sts_creds(arn_dict)
        try:
            common.write_credentials(
                self.config.get(
                    common.DEFAULT_CONFIG_SECTION,
                    'aws_credential_profile'
                ),
                sts_creds
                )
        except (NoOptionError, NoSectionError) as e:
            sys.exit(e.message)

    def auth(self):
        session = requests.Session()
        username, password = common.get_user_credentials()
        payload_dict = {
            "username": username,
            "password": password
        }

        response = session.post(
            self.auth_url,
            headers=self.headers_dict,
            data=json.dumps(payload_dict)
        )

        if response.status_code != 200:
            e = json.loads(response.text)
            sys.exit("Primary authentication failed: %s. Error code: %s" %
                     (e['errorSummary'], e['errorCode']))

        auth_response = json.loads(response.text)
        if auth_response['status'] == 'MFA_REQUIRED':
            print("Please choose a second factor:\n")
            for i in range(0, len(auth_response['_embedded']['factors'])):
                print("[%s] - %s" % (i,
                      auth_response['_embedded']['factors'][i]['factorType']))

            try:
                factor_input = raw_input
            except NameError:
                factor_input = input
            choice = int(factor_input("Chose a second factor: "))
            if choice > (len(auth_response['_embedded']['factors']) - 1):
                sys.exit('Sorry, that is not a valid role choice.')
            chosen_factor = auth_response['_embedded']['factors'][choice]

            if (chosen_factor['factorType'] == 'sms' or
                    chosen_factor['factorType'] == 'token:software:totp'):
                response = self.second_factor(
                    chosen_factor, auth_response['stateToken'])
            else:
                sys.exit("Unsupported second factor.")

            if json.loads(response.text)['status'] == 'SUCCESS':
                self.process_success(response)
            else:
                print("Authentication failed with status: %s" %
                      (json.loads(response.text)['status'],))
        elif auth_response['status'] == 'SUCCESS':
            self.process_success(response)
        else:
            print("Unable to login: %s" % (auth_response['status'],))
