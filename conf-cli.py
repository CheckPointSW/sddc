#!/usr/bin/env python

#   Copyright 2017 Check Point Software Technologies LTD
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import argparse
import collections
import copy
import json
import os
import re
import subprocess
import shutil
import sys

AZURE_ENVIRONMENTS = [
    'AzureCloud', 'AzureChinaCloud', 'AzureGermanCloud', 'AzureUSGovernment'
]

AVAILABLE_VERSIONS = ['R77.30', 'R80.10']

AWS_REGIONS = [
    'us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'ap-south-1',
    'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
    'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'sa-east-1',
    'cn-north-1', 'us-gov-west-1'
]

MIN_SIC_LENGTH = 8

USAGE_EXAMPLES = {
    'init_aws': [
        'init AWS -mn <MANAGEMENT-NAME> -tn <TEMPLATE-NAME> -otp <SIC-KEY> '
        '-v {R77.30,R80.10} -po <POLICY-NAME> -cn <CONTROLLER-NAME> -r '
        'eu-west-1,us-east-1,eu-central-1 -fi <FILE-PATH>',
        'init AWS -mn <MANAGEMENT-NAME> -tn <TEMPLATE-NAME> -otp <SIC-KEY> '
        '-v {R77.30,R80.10} -po <POLICY-NAME> -cn <CONTROLLER-NAME> -r '
        'eu-west-1,us-east-1,eu-central-1 -ak <ACCESS-KEY> -sk <SECRET-KEY> '
        '-sr <STS-ROLE>',
        'init AWS -mn <MANAGEMENT-NAME> -tn <TEMPLATE-NAME> -otp <SIC-KEY> '
        '-v {R77.30,R80.10} -po <POLICY-NAME> -cn <CONTROLLER-NAME> -r '
        'eu-west-1,us-east-1,eu-central-1 -iam'
    ],
    'init_azure': [
        'init Azure -mn <MANAGEMENT-NAME> -tn <TEMPLATE-NAME> -otp <SIC-KEY> '
        '-v {R77.30,R80.10} -po <POLICY-NAME> -cn <CONTROLLER-NAME> -sb '
        '<SUBSCRIPTION> -at <TENANT> -aci <CLIENT-ID> -acs <CLIENT-SECRET>',
        'init Azure -mn <MANAGEMENT-NAME> -tn <TEMPLATE-NAME> -otp <SIC-KEY> '
        '-v {R77.30,R80.10} -po <POLICY-NAME> -cn <CONTROLLER-NAME> -sb '
        '<SUBSCRIPTION> -au <USERNAME> -ap <PASSWORD>'
    ],
    'init_GCP': [],
    'show': ['show all',
             'show management',
             'show templates',
             'show controllers'],
    'add_template': [
        'add template -tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
        '-po <POLICY-NAME>',
        'add template -tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
        '-po <POLICY-NAME> [-hi] [-ia] [-appi]'
    ],
    'add_controller_AWS': [
        'add controller AWS -cn <NAME> -r eu-west-1,us-east-1,eu-central-1  '
        '-fi <FILE-PATH>',
        'add controller AWS -cn <NAME> -r eu-west-1,eu-central-1 -ak '
        '<ACCESS-KEY> -sk <SECRET-KEY>',
        'add controller AWS -cn <NAME> -r eu-west-1 -iam -sn '
        '<SUB-ACCOUNT-NAME> -sak <SUB-ACCOUNT-ACCESS-KEY> -ssk '
        '<SUB-ACCOUNT-SECRET-KEY>'
    ],
    'add_controller_Azure': [
        'add controller Azure -cn <NAME> -sb <SUBSCRIPTION> [-en {'
        'AzureCloud,AzureChinaCloud,AzureGermanCloud,AzureUSGovernment}] sp '
        '-at <TENANT> -aci <CLIENT-ID> -acs <CLIENT-SECRET>',
        'add controller Azure -cn <NAME> -sb <SUBSCRIPTION> user -au '
        '<USERNAME> -ap <PASSWORD>'
    ],
    'add_controller_GCP': [
        'add controller GCP -cn <NAME> -proj <PROJECT> -cr <FILE-PATH>'
    ],
    'set_delay': ['set delay 60'],
    'set_management': [
        'set management [-mn <NEW-NAME>] [-ho <NEW-HOST> [-d <DOMAIN>] [-fp '
        '<FINGERPRINT>] [-u <USER>] [-pass <PASSWORD>] [-pr <PROXY>] [-cs '
        '<CUSTOM-SCRIPT-PATH>]'
    ],
    'set_template': [
        'set template -tn <NAME> [-nn <NEW-NAME>] [-otp <SIC-KEY>] [-v {'
        'R77.30,R80.10}] [-po <POLICY>]',
        'set template -tn <NAME> [-hi] [-ia] [-appi]'
    ],
    'set_controller_AWS': [
        'set controller AWS -tn <NAME> [-nn <NEW-NAME>]',
        'set controller AWS -tn <NAME> [-fi <FILE-PATH> | -iam]'
    ],
    'set_controller_Azure': [
        'set controller Azure -cn <NAME> [-nn <NEW-NAME>] [-au <USERNAME>] ['
        '-ap <PASSWORD>]',
        'set controller Azure -cn <NAME> [-cd <DOMAIN>]'
    ],
    'set_controller_GCP': [
        'set controller GCP -cn <NAME> [-nn <NEW-NAME>] [-cr <FILE-PATH> | '
        '"IAM"]'
    ],
    'delete_management': ['delete management',
                          'delete management -pr'],
    'delete_template': [
        'delete template -tn <NAME>',
        'delete template -tn <NAME> [-pr] [-cp]'
    ],
    'delete_controller_AWS': [
        'delete controller AWS -cn <NAME> ',
        'delete controller AWS -cn <NAME> [-cd] [-ct]'
    ],
    'delete_controller_Azure': [
        'delete controller Azure -cn <NAME> ',
        'delete controller Azure -cn <NAME> [-d] [-ap]'
    ],
    'delete_controller_GCP': [
        'delete controller GCP -cn <NAME> ',
        'delete controller GCP -cn <NAME> [-ct] [-cr]'
    ]
}

CONFPATH = os.environ['FWDIR'] + '/conf/autoprovision.json'


def my_check_value(self, action, value):
    """Modified _check_value method.

    Choices are str instead of repr.
    Modified error message for empty choices list.
    """
    if action.choices is not None and value not in action.choices:
        tup = value, ', '.join(map(str, action.choices))
        if not action.choices:
            msg = (
                'invalid choice: no values to set or delete, please add first')
        else:
            msg = ('invalid choice: %r (choose from %s)') % tup
        raise argparse.ArgumentError(action, msg)


def my_error(self, message):
    """error(message: string)

    Prints a usage message incorporating the message to stderr and
    exits.

    If you override this in a subclass, it should not return -- it
    should either exit or raise an exception.
    """
    self.print_usage(sys.stderr)
    if self.epilog:
        args = {'prog': self.prog, 'message': message, 'epilog': self.epilog}
        self.exit(2, ('%(prog)s: error: %(message)s\n\n%(epilog)s\n') % args)
    else:
        args = {'prog': self.prog, 'message': message}
        self.exit(2, ('%(prog)s: error: %(message)s\n') % args)


argparse.ArgumentParser._check_value = my_check_value
argparse.ArgumentParser.error = my_error

REQUIRED_GROUP, OPTIONAL_GROUP = 'required arguments', 'optional group'

SHOW, INIT, ADD, SET, DELETE = 'show', 'init', 'add', 'set', 'delete'

DELAY = 'delay'
MANAGEMENT = 'management'
TEMPLATE = 'template'
CONTROLLER = 'controller'
TEMPLATES = 'templates'
CONTROLLERS = 'controllers'

AWS, AZURE, GCP = 'AWS', 'Azure', 'GCP'

TEMPLATE_NAME = 'template name'
CONTROLLER_NAME = 'controller name'
SUBCREDENTIALS_NAME = 'sub-credentials name'
TEMPLATE_NEW_NAME = 'template new name'
CONTROLLER_NEW_NAME = 'controller new name'
NEW_KEY = 'new key'
SUBCREDS = 'sub-creds'

KEYS_TO_UPDATE_WITH_USER_INPUT = (TEMPLATE_NAME, CONTROLLER_NAME,
                                  SUBCREDENTIALS_NAME, NEW_KEY)
NON_CONFIG_KEYS = (TEMPLATE_NAME, CONTROLLER_NAME, SUBCREDENTIALS_NAME,
                   'force', 'mode', 'branch')
MANDATORY_KEYS = {
    MANAGEMENT: ['name', 'host'],
    TEMPLATES: ['one-time-password', 'version', 'policy'],
    AWS: ['class', 'regions'],
    AZURE: ['class', 'subscription'],
    GCP: ['class', 'project', 'credentials']
}
AWS_SUBACCOUNT_ARGS = (SUBCREDENTIALS_NAME,
                       'AWS sub-credentials access key',
                       'AWS sub-credentials secret key',
                       'AWS sub-credentials file path',
                       'AWS sub-credentials IAM',
                       'AWS sub-credentials STS role',
                       'AWS sub-credentials STS external id')


def get_templates(conf):
    """Return an array of names of existing templates."""
    try:
        return conf['templates'].keys()
    except KeyError:
        return []


def get_controllers(conf, clazz):
    """Return an array of names of existing 'clazz' controllers."""
    try:
        lst = [c for c in conf[CONTROLLERS]
               if conf[CONTROLLERS][c]['class'] == clazz]
        return lst
    except KeyError:
        return []


def create_parser_dict(conf):
    """
    Structure of dictionary:
    {parser_name: [positional argument, mandatory arguments, optional
    arguments, help, epilog, defaults]

    Override default argument's kwargs by specifying a tuple (argument name,
    kwargs) instead of just the name
    """
    parsers = {
        SHOW: [SHOW, [], ['branch'],
               'show all or specific configuration settings',
               'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['show']), None],
        INIT: [INIT, [], [],
               'initialize auto-provision settings', None, None],
        ADD: [ADD, [], [], 'add a template or a controller', None, None],
        SET: [SET, [], [],
              'set configurations of a management, a template or a controller',
              None, None],
        DELETE: [DELETE, [], [],
                 'delete configurations of a management, a template or a '
                 'controller', None, None
                 ],
        'init_aws': [
            AWS,
            ['Management name', TEMPLATE_NAME, 'one time password', 'version',
             'policy', CONTROLLER_NAME, 'regions'],
            ['AWS access key', 'AWS secret key', 'AWS IAM',
             'AWS credentials file path', 'STS role', 'STS external id'],
            'initialize autoprovision settings for AWS',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['init_aws']),
            {'delay': 30, 'class': 'AWS', 'host': 'localhost'}],
        'init_azure': [
            AZURE, ['Management name', TEMPLATE_NAME, 'one time password',
                    'version', 'policy', CONTROLLER_NAME, 'subscription'],
            ['Service Principal credentials tenant',
             'Service Principal credentials client id',
             'Service Principal credentials client secret', 'Azure username',
             'Azure password'],
            'initialize autoprovision settings for Azure',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['init_azure']),
            {'delay': 30, 'class': 'Azure', 'host':
                'localhost'}
        ],
        'init_gcp': [GCP, [], [],
                     'support for GCP will be added in the future',
                     'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                                      'init_GCP']), None],
        'add_template': [
            TEMPLATE, [TEMPLATE_NAME],
            ['one time password', 'version', 'policy', 'custom parameters',
             'prototype', 'specific network', 'generation', 'proxy ports',
             'HTTPS Inspection', 'Identity Awareness', 'Application Control',
             'Intrusion Prevention', 'IPS Profile', 'URL Filtering',
             'Anti-Bot', 'Anti-Virus', 'restrictive policy'],
            'add a gateway configuration template. When a new gateway '
            'instance is detected, the template\'s name is used to '
            'determines the eventual gateway configuration',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['add_template']),
            None
        ],
        'add_controller': [
            CONTROLLER, [], [],
            'add a controller configuration. These settings will be used to '
            'connect to cloud environments such as AWS, Azure or GCP', None,
            None
        ],
        'add_controller_aws': [
            AWS, [CONTROLLER_NAME, 'regions'],
            ['controller templates', 'controller domain', 'AWS access key',
             'AWS secret key', 'AWS IAM', 'AWS credentials file path',
             'STS role', 'STS external id', SUBCREDENTIALS_NAME,
             'AWS sub-credentials access key',
             'AWS sub-credentials secret key',
             'AWS sub-credentials file path', 'AWS sub-credentials IAM',
             'AWS sub-credentials STS role',
             'AWS sub-credentials STS external id'],
            'add AWS Controller',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['add_controller_AWS']),
            {'class': 'AWS'}
        ],
        'add_controller_azure': [
            AZURE, [CONTROLLER_NAME, 'subscription'],
            ['controller templates', 'controller domain', 'environment',
             'Service Principal credentials tenant',
             'Service Principal credentials client id',
             'Service Principal credentials client secret',
             'Azure username', 'Azure password'], 'add Azure controller',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                             'add_controller_Azure']),
            {'class': 'Azure'}
        ],
        'add_controller_gcp': [
            GCP, [CONTROLLER_NAME, 'GCP project', 'GCP credentials'],
            ['controller templates', 'controller domain'],
            'add GCP Controller',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['add_controller_GCP']),
            {'class': 'GCP'}
        ],
        'set_delay': [
            DELAY, [], [DELAY], 'set delay',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['set_delay']), None
        ],
        'set_management': [
            MANAGEMENT, [],
            ['Management name', 'host', 'domain', 'fingerprint',
             'Management password', 'Management password 64bit', 'proxy',
             'custom script'], 'set management arguments',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES['set_management']),
            None
        ],
        'set_template': [
            TEMPLATE, [(TEMPLATE_NAME, {'choices': get_templates(conf),
                                        'dest': TEMPLATE_NAME})],
            [TEMPLATE_NEW_NAME, 'one time password', 'version', 'policy',
             'custom parameters', 'prototype', 'specific network',
             'generation', 'proxy ports', 'HTTPS Inspection',
             'Identity Awareness', 'Application Control',
             'Intrusion Prevention', 'IPS Profile', 'URL Filtering',
             'Anti-Bot', 'Anti-Virus', 'restrictive policy', NEW_KEY],
            'set template arguments', 'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['set_template']), None
        ],
        'set_controller': [
            CONTROLLER, [], [],
            'set an existing controller configuration. These settings will be '
            'used to connect to cloud environments such as AWS, Azure or GCP',
            None, None
        ],
        'set_controller_aws': [
            AWS, [(CONTROLLER_NAME, {'choices': get_controllers(conf, AWS),
                                     'dest': CONTROLLER_NAME})],
            [CONTROLLER_NEW_NAME, 'controller templates', 'controller domain',
             'regions', 'AWS access key', 'AWS secret key', 'AWS IAM',
             'AWS credentials file path', 'STS role', 'STS external id',
             SUBCREDENTIALS_NAME, 'AWS sub-credentials access key',
             'AWS sub-credentials secret key',
             'AWS sub-credentials file path', 'AWS sub-credentials IAM',
             'AWS sub-credentials STS role',
             'AWS sub-credentials STS external id'],
            'set AWS controller values',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['set_controller_AWS']),
            None
        ],
        'set_controller_azure': [
            AZURE,
            [(CONTROLLER_NAME, {'choices': get_controllers(conf, AZURE),
                                'dest': CONTROLLER_NAME})],
            [CONTROLLER_NEW_NAME, 'controller templates',
             'controller domain', 'subscription', 'environment',
             'Service Principal credentials tenant',
             'Service Principal credentials client id',
             'Service Principal credentials client secret',
             'Azure username', 'Azure password'],
            'set Azure controller values',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                             'set_controller_Azure']),
            None
        ],
        'set_controller_gcp': [
            GCP, [(CONTROLLER_NAME, {'choices': get_controllers(conf, GCP),
                                     'dest': CONTROLLER_NAME})],
            [CONTROLLER_NEW_NAME, 'controller templates', 'controller domain',
             'GCP project', 'GCP credentials'], 'set GCP controller values',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['set_controller_GCP']),
            None
        ],
        'delete_management': [
            MANAGEMENT, [],
            [('Management name', {'action': 'store_true'}),
             ('host', {'action': 'store_true'}),
             ('domain', {'action': 'store_true'}),
             ('fingerprint', {'action': 'store_true'}),
             ('Management password', {'action': 'store_true'}),
             ('Management password 64bit', {'action': 'store_true'}),
             ('proxy', {'action': 'store_true'}),
             ('custom script', {'action': 'store_true'})],
            'delete management arguments',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['delete_management']),
            None
        ],
        'delete_template': [
            TEMPLATE, [(TEMPLATE_NAME, {'choices': get_templates(conf)})],
            [('one time password', {'action': 'store_true'}),
             ('version', {'action': 'store_true'}),
             ('policy', {'action': 'store_true'}),
             ('custom parameters', {'action': 'store_true'}),
             ('prototype', {'action': 'store_true'}),
             ('specific network', {'action': 'store_true'}),
             ('generation', {'action': 'store_true'}),
             ('proxy ports', {'action': 'store_true'}),
             ('HTTPS Inspection', {'action': 'store_true'}),
             ('Identity Awareness', {'action': 'store_true'}),
             ('Application Control', {'action': 'store_true'}),
             ('Intrusion Prevention', {'action': 'store_true'}),
             ('IPS Profile', {'action': 'store_true'}),
             ('URL Filtering', {'action': 'store_true'}),
             ('Anti-Bot', {'action': 'store_true'}),
             ('Anti-Virus', {'action': 'store_true'}),
             ('restrictive policy', {'action': 'store_true'}),
             (NEW_KEY, {'nargs': 1,
                        'help': 'optional attributes of a gateway. Usage '
                                '-nk [KEY]'})],
            'delete a template or its values',
            'usage examples: \n' + '\n'.join(
                USAGE_EXAMPLES['delete_template']),
            None
        ],
        'delete_controller': [
            CONTROLLER, [], [],
            'delete a controller or existing controller values. These '
            'settings are used to connect to cloud environments such as AWS, '
            'Azure or GCP', None, None
        ],
        'delete_controller_aws': [
            AWS, [(CONTROLLER_NAME, {'choices': get_controllers(conf, AWS),
                                     'dest': CONTROLLER_NAME})],
            [('controller templates', {'action': 'store_true'}),
             ('controller domain', {'action': 'store_true'}),
             ('regions', {'action': 'store_true'}),
             ('AWS access key', {'action': 'store_true'}),
             ('AWS secret key', {'action': 'store_true'}),
             ('AWS IAM', {'action': 'store_true'}),
             ('AWS credentials file path', {'action': 'store_true'}),
             ('STS role', {'action': 'store_true'}),
             ('STS external id', {'action': 'store_true'}),
             SUBCREDENTIALS_NAME,
             ('AWS sub-credentials access key', {'action': 'store_true'}),
             ('AWS sub-credentials secret key', {'action': 'store_true'}),
             ('AWS sub-credentials file path', {'action': 'store_true'}),
             ('AWS sub-credentials IAM', {'action': 'store_true'}),
             ('AWS sub-credentials STS role', {'action': 'store_true'}),
             ('AWS sub-credentials STS external id', {'action': 'store_true'})
             ], 'delete an AWS controller or its values',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                             'delete_controller_AWS']),
            None
        ],
        'delete_controller_azure': [
            AZURE, [(CONTROLLER_NAME,
                     {'choices': get_controllers(conf, AZURE)})],
            [('controller templates', {'action': 'store_true'}),
             ('controller domain', {'action': 'store_true'}),
             ('subscription', {'action': 'store_true'}),
             ('environment', {'action': 'store_true'}),
             ('Service Principal credentials tenant',
              {'action': 'store_true'}),
             ('Service Principal credentials client id',
              {'action': 'store_true'}),
             ('Service Principal credentials client secret',
              {'action': 'store_true'}),
             ('Azure username', {'action': 'store_true'}),
             ('Azure password', {'action': 'store_true'})],
            'delete an Azure controller or its values',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                             'delete_controller_Azure']),
            None
        ],
        'delete_controller_gcp': [
            GCP, [(CONTROLLER_NAME, {'choices': get_controllers(conf, GCP)})],
            [('controller templates', {'action': 'store_true'}),
             ('controller domain', {'action': 'store_true'}),
             ('GCP project', {'action': 'store_true'}),
             ('GCP credentials', {'action': 'store_true'})],
            'delete a GCP controller or its values',
            'usage examples: \n' + '\n'.join(USAGE_EXAMPLES[
                                             'delete_controller_GCP']),
            None
        ]
    }
    return parsers


def validate_SIC(value):
    """Validates length and char restrictions of the SIC value."""

    if len(value) < MIN_SIC_LENGTH:
        raise argparse.ArgumentTypeError(
            'one time password should consist of at least %s characters'
            % repr(MIN_SIC_LENGTH))
    if not value.isalnum():
        raise argparse.ArgumentTypeError(
            'one time password should contain only alphanumeric characters')
    return value


def validate_guid_uuid(value):
    pattern = re.compile(
        '^[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}$',
        re.IGNORECASE)

    if not pattern.match(value):
        raise argparse.ArgumentTypeError('value %s is not a GUID.\n' % value)

    return value


def validate_ports(value):
    ports = value.split(',')
    for port in ports:
        if not port.isdigit():
            raise argparse.ArgumentTypeError('port %s is invalid.\n' % port)
    return ports


def validate_bool(value):
    if value.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif value.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('boolean value expected (yes, no, '
                                         'true, false, t, y, f, n).\n')


def validate_filepath(value):
    if os.path.exists(value):
        return value

    raise argparse.ArgumentTypeError('file %s does not exist.\n' % value)


def validate_iam_or_filepath(value):
    if value == 'IAM':
        return value

    return validate_filepath(value)


def validate_hex(value):
    try:
        int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError('value %s is not hexadecimal.\n' %
                                         value)
    return value


def validate_communities(input):
    return input.split(',')

# Structure of dictionary:
# {argument_name(unique): [flag (must be unique within each parser), path in
#  the configuration file, help, constraints (dict of type= or choices=)

ARGUMENTS = {
    'branch': ['branch', [], 'the branch of the configuration to show',
               {'choices': ['all', 'management', 'templates', 'controllers']}],
    DELAY: [DELAY, [DELAY],
            'time to wait in seconds after each poll cycle',
            {'type': int}],
    'Management name': [
        '-mn',
        [MANAGEMENT, 'name'],
        'the name of the management server', None
    ],
    'host': [
        '-mh', [MANAGEMENT, 'host'],
        '"IP-ADDRESS-OR-HOST-NAME[:PORT]" - of the management server', None
    ],
    'domain': [
        '-d', [MANAGEMENT, 'domain'],
        'the name or UID of the management domain if applicable', None
    ],
    'fingerprint': [
        '-fp', [MANAGEMENT, 'fingerprint'],
        '"sha256:FINGERPRINT-IN-HEX" - the SHA256 fingerprint '
        'of the management certificate. '
        'disable fingerprint checking by providing an empty string "" '
        '(insecure but reasonable if running locally '
        'on the management server). '
        'To retrieve the fingerprint, '
        'run the following command on the management server (in bash): '
        'cpopenssl s_client -connect 127.0.0.1:443 2>/dev/null '
        '</dev/null | cpopenssl x509 -outform DER '
        r'| sha256sum | awk "{printf "sha256:%%s\n", $1}"',
        {'type': validate_hex}
    ],
    'Management password': [
        '-pass', [MANAGEMENT, 'password'],
        'the password associated with the user', None
    ],
    'Management password 64bit': [
        '-pass64', [MANAGEMENT, 'b64password'],
        'the base64 encoded password associated with the user', None
    ],
    'proxy': [
        '-pr', [MANAGEMENT, 'proxy'],
        '"http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT" '
        '- an optional value for the https_proxy environment variable',
        None
    ],
    'custom script': [
        '-cs', [MANAGEMENT, 'custom-script'],
        '"PATH-TO-CUSTOMIZATION-SCRIPT" - '
        'an optional script to run just after the policy is installed '
        'when a gateway is provisioned, and at the beginning '
        'of the deprovisioning process. '
        'When a gateway is added the script will be run with '
        'the keyword "add", '
        'with the gateway name and the custom-parameters '
        'attribute in the template. '
        'When a gateway is deleted the script will run with the keyword '
        '"delete" and the gateway name. '
        'In the case of a configuration update '
        '(for example, a load balancing configuration change '
        'or a template/generation change), '
        'the custom script will be run with "delete" '
        'and later again with "add" and the custom parameters', None
    ],
    TEMPLATE_NAME: [
        '-tn', [TEMPLATES],
        'the name of the template. The name must be unique', None
    ],
    TEMPLATE_NEW_NAME: [
        '-nn', [],
        'the new name of the template. The name must be unique', None
    ],
    'one time password': [
        '-otp', [TEMPLATES, TEMPLATE_NAME, 'one-time-password'],
        'a random string consisting of at least %s alphanumeric characters'
        % repr(MIN_SIC_LENGTH), {'type': validate_SIC}
    ],
    'version': [
        '-v', [TEMPLATES, TEMPLATE_NAME, 'version'],
        'the gateway version (e.g. R77.30)',
        {'choices': AVAILABLE_VERSIONS}
    ],
    'policy': [
        '-po', [TEMPLATES, TEMPLATE_NAME, 'policy'],
        'the name of an existing security policy intended to be installed on '
        'the gateways', None
    ],
    'custom parameters': [
        '-cp', [TEMPLATES, TEMPLATE_NAME, 'custom-parameters'],
        'an optional string with space separated parameters or '
        'a list of string parameters to specify when a gateway is added '
        'and a custom script is specified in the management section', None
    ],
    'prototype': ['-pr', [TEMPLATES, TEMPLATE_NAME, 'proto'],
                  'a prototype for this template', None
                  ],
    'specific network': [
        '-sn', [TEMPLATES, TEMPLATE_NAME, 'specific-network'],
        'an optional name of a pre-existing network object group '
        'that defines the topology settings for the interfaces marked '
        'with "specific" topology. This attribute is mandatory '
        'if any of the scanned instances has an interface '
        'with a topology set to "specific". '
        'Typically this should point to the name of a '
        '"Group with Exclusions" object, '
        'which contains a network group holding the VPC '
        'address range and excludes a network group which contains '
        'the "external" networks of the VPC, that is,'
        'networks that are connected to the internet', None
    ],
    'generation': [
        '-g', [TEMPLATES, TEMPLATE_NAME, 'generation'],
        'an optional string or number that can be used to force '
        're-applying a template to an already existing gateway. '
        'If generation is specified and its value is different '
        'than the previous value, then the template settings '
        'will be reapplied to the gateway', None
    ],
    'proxy ports': [
        '-pp', [TEMPLATES, TEMPLATE_NAME, 'proxy-ports'],
        'an optional comma-separated list of list of TCP ports '
        'on which to enable the proxy on gateway feature. e.g. "8080,8443"',
        {'type': validate_ports}
    ],
    'HTTPS Inspection': [
        '-hi', [TEMPLATES, TEMPLATE_NAME, 'https-inspection'],
        'use this flag to specify whether to enable the HTTPS Inspection '
        'blade on the gateway',
        {'action': 'store_true'}
    ],
    'Identity Awareness': [
        '-ia', [TEMPLATES, TEMPLATE_NAME, 'identity-awareness'],
        'use this flag to specify whether to enable the Identity Awareness '
        'blade on the gateway',
        {'action': 'store_true'}
    ],
    'Application Control': [
        '-appi', [TEMPLATES, TEMPLATE_NAME, 'application-control'],
        'use this flag to specify whether to enable the Application Control '
        'blade on the gateway', {'action': 'store_true'}
    ],
    'Intrusion Prevention': [
        '-ips', [TEMPLATES, TEMPLATE_NAME, 'ips'],
        'use this flag to specify whether to enable the Intrusion Prevention '
        'System blade on the gateway',
        {'action': 'store_true'}
    ],
    'IPS Profile': [
        '-ipf', [TEMPLATES, TEMPLATE_NAME, 'ips-profile'],
        'an optional IPS profile name to associate with a pre-R80 gateway',
        None
    ],
    'URL Filtering': [
        '-uf', [TEMPLATES, TEMPLATE_NAME, 'url-filtering'],
        'use this flag to specify whether to enable the URL Filtering '
        'Awareness blade on the gateway', {'action': 'store_true'}
    ],
    'Anti-Bot': [
        '-ab', [TEMPLATES, TEMPLATE_NAME, 'anti-bot'],
        'use this flag to specify whether to enable the Anti-Bot blade on '
        'the gateway', {'action': 'store_true'}
    ],
    'Anti-Virus': [
        '-av', [TEMPLATES, TEMPLATE_NAME, 'anti-virus'],
        'use this flag to specify whether to enable the Anti-Virus blade on '
        'the gateway', {'action': 'store_true'}
    ],
    'restrictive policy': [
        '-rp', [TEMPLATES, TEMPLATE_NAME, 'restrictive-policy'],
        'an optional name of a pre-existing policy package to be '
        'installed as the first policy on a new provisioned gateway. '
        '(Created to avoid a limitation in which Access Policy and '
        'Threat Prevention Policy cannot be installed at the first '
        'time together). In the case where no attribute is provided, '
        'a default policy will be used (the default policy has only '
        'the implied rules and a drop-all cleanup rule). '
        'The value null can be used to explicitly avoid any such policy',
        None
    ],
    NEW_KEY: [
        '-nk', [TEMPLATES, TEMPLATE_NAME, NEW_KEY],
        'an optional attributes of a gateway. Usage -nk [KEY] [VALUE]',
        {'nargs': 2}
    ],
    CONTROLLER_NAME: [
        '-cn', [CONTROLLERS],
        'the name of the cloud environment controller. The name must be '
        'unique', None
    ],
    CONTROLLER_NEW_NAME: [
        '-nn', [], 'the new name of the controller. The name must be '
                   'unique', None
    ],
    'class': [
        '-cc', [CONTROLLERS, CONTROLLER_NAME, 'class'],
        'either "AWS", "Azure", "GCP"', None
    ],
    'controller domain': [
        '-cd', [CONTROLLERS, CONTROLLER_NAME, 'domain'],
        'the name or UID of the management domain if applicable (optional). '
        'In MDS, instances that are discovered by this controller, '
        'will be defined in this domain. If not specified, '
        'the domain specified in the management object '
        '(in the configuration), will be used. This attribute should not be '
        'specified if the management server is not an MDS', None
    ],
    'controller templates': [
        '-ct', [CONTROLLERS, CONTROLLER_NAME, 'templates'],
        'an optional list of of templates, which are allowed for instances '
        'that are discovered by this controller. If this attribute is '
        'missing or its value is an empty list, the meaning is that any '
        'template may be used by gateways that belong to this controller. '
        'This is useful in MDS environments, where controllers work with '
        'different domains and it is necessary to restrict a gateway to only '
        'use templates that were intended for its domain. e.g. '
        'TEMPLATE1-NAME TEMPLATE2-NAME', {'nargs': '+'}
    ],
    'regions': ['-r', [CONTROLLERS, CONTROLLER_NAME, 'regions'],
                'a comma-separated list of AWS regions, in which the '
                'gateways are being deployed. For example: eu-west-1,'
                'us-east-1,eu-central-1', None
                ],
    'AWS access key': [
        '-ak', [CONTROLLERS, CONTROLLER_NAME, 'access-key'],
        'AWS access key', None
    ],
    'AWS secret key': ['-sk', [CONTROLLERS, CONTROLLER_NAME, 'secret-key'],
                       'AWS secret key', None
                       ],
    'AWS credentials file path': [
        '-fi', [CONTROLLERS, CONTROLLER_NAME, 'cred-file'],
        'the path to a text file containing AWS credentials',
        {'type': validate_filepath}
    ],
    'AWS IAM': ['-iam', [CONTROLLERS, CONTROLLER_NAME, 'cred-file'],
                'use this flag to specify whether to use an IAM role profile',
                {'action': 'store_const', 'const': 'IAM'}],
    'STS role': ['-sr', [CONTROLLERS, CONTROLLER_NAME, 'sts-role'],
                 'the STS RoleARN of the role to assume', None],
    'STS external id': [
        '-se', [CONTROLLERS, CONTROLLER_NAME, 'sts-external-id'],
        'an optional STS ExternalId to use when assuming the role', None
    ],
    SUBCREDENTIALS_NAME: [
        '-sn', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS],
        'the name of the sub credentials object. The name must be '
        'unique', None
    ],
    'AWS sub-credentials access key': [
        '-sak', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                 SUBCREDENTIALS_NAME, 'access-key'],
        'AWS access key for the sub-account', None
    ],
    'AWS sub-credentials secret key': [
        '-ssk', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                 SUBCREDENTIALS_NAME, 'secret-key'],
        'AWS secret key for the sub-account', None
    ],
    'AWS sub-credentials file path': [
        '-sfi', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                 SUBCREDENTIALS_NAME, 'cred-file'],
        'the path to a text file containing the AWS credentials for the '
        'sub-account', {'type': validate_filepath}
    ],
    'AWS sub-credentials IAM': [
        '-siam', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                  SUBCREDENTIALS_NAME, 'cred-file'],
        'use this flag to specify whether to use an IAM role profile for '
        'the sub-account', {'action': 'store_const', 'const': 'IAM'}
    ],
    'AWS sub-credentials STS role':
        ['-ssr', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                  SUBCREDENTIALS_NAME, 'sts-role'],
         'the STS RoleARN of the role to assume for the sub-account', None],
    'AWS sub-credentials STS external id': [
        '-sse', [CONTROLLERS, CONTROLLER_NAME, SUBCREDS,
                 SUBCREDENTIALS_NAME, 'sts-external-id'],
        'an optional STS ExternalId to use when assuming the role in this '
        'sub account', None
    ],
    'subscription': [
        '-sb', [CONTROLLERS, CONTROLLER_NAME, 'subscription'],
        'the Azure subscription ID', {'type': validate_guid_uuid}
    ],
    'environment': [
        '-en', [CONTROLLERS, CONTROLLER_NAME, 'environment'],
        'an optional attribute to specify the Azure environment. '
        'The default is "AzureCloud", but one of the other environments '
        'like "AzureChinaCloud", "AzureGermanCloud" or "AzureUSGovernment"'
        ' can be specified instead', {'choices': AZURE_ENVIRONMENTS}
    ],
    'Service Principal credentials tenant': [
        '-at', [CONTROLLERS, CONTROLLER_NAME, 'credentials', 'tenant'],
        'the Azure Active Directory tenant ID', None
    ],
    'Service Principal credentials client id': [
        '-aci', [CONTROLLERS, CONTROLLER_NAME, 'credentials', 'client_id'],
        'the application ID with which the service principal is associated',
        None
    ],
    'Service Principal credentials client secret': [
        '-acs',
        [CONTROLLERS, CONTROLLER_NAME, 'credentials', 'client_secret'],
        'the service principal password', None
    ],
    'Azure username': [
        '-au', [CONTROLLERS, CONTROLLER_NAME, 'credentials', 'username'],
        'the Azure fully qualified user name', None
    ],
    'Azure password': [
        '-ap', [CONTROLLERS, CONTROLLER_NAME, 'credentials', 'password'],
        'the password for the user', None
    ],
    'GCP project': [
        '-proj', [CONTROLLERS, CONTROLLER_NAME, 'project'],
        'the GCP project ID in which to scan for VM instances', None
    ],
    'GCP credentials': [
        '-cr', [CONTROLLERS, CONTROLLER_NAME, 'credentials'],
        'either the path to a text file containing GCP credentials '
        'or "IAM" for automatic retrieval of the service account '
        'credentials from the VM instance metadata. Default: "IAM"',
        {'type': validate_iam_or_filepath, 'default': 'IAM'}
    ],

}


def verify_AWS_credentials(conf, args, creds, sub=False):
    if sub and getattr(args, SUBCREDENTIALS_NAME, None):
        name = getattr(args, SUBCREDENTIALS_NAME)
    else:
        name = getattr(args, CONTROLLER_NAME)

    # No mandatory credentials in the main account
    if not sub:
        if not ('cred-file' in creds or 'access-key' in creds):
            sys.stderr.write(
                '%s is missing credentials. To set other credentials '
                'use set.\n' % name)
            sys.exit(2)
    else:
        if not creds:
            sys.stderr.write(
                '%s is missing credentials. To remove this sub account use '
                'delete.\n' % name)
            sys.exit(2)

    # Missing either of access key or secret key (both or neither)
    if ('access-key' in creds) != ('secret-key' in creds):
        sys.stderr.write(
            'please specify both access key and secret key or specify '
            'different credentials\n')
        sys.exit(2)

    # Has too many, explicit AND cred file
    if 'cred-file' in creds and 'access-key' in creds:
        if not sub:
            explicit_keys = ('AWS access key', 'AWS secret key')
            non_explicit_keys = ('AWS credentials file path', 'AWS IAM')
            inserted_explicit_creds = [key for key in explicit_keys
                                       if getattr(args, key, None)]
            inserted_non_explicit_creds = [key for key in non_explicit_keys
                                           if getattr(args, key, None)]
        else:
            sub_explicit_keys = ('AWS sub-credentials access key',
                                 'AWS sub-credentials secret key')
            sub_non_explicit_keys = ('AWS sub-credentials file path',
                                     'AWS sub-credentials IAM')
            inserted_explicit_creds = [key for key in sub_explicit_keys
                                       if getattr(args, key, None)]
            inserted_non_explicit_creds = [key for key in sub_non_explicit_keys
                                           if getattr(args, key, None)]

        if inserted_explicit_creds and inserted_non_explicit_creds:
            sys.stderr.write(
                'please specify only one of the following credentials: '
                'explicit credentials (access and secret keys) or a file path '
                'or the IAM flag.\n')
            sys.exit(2)

        if args.force or prompt(
                'replace existing credentials for %s?' % name):
            # Check what type has been inserted in the recent command and
            # delete the other type
            if inserted_explicit_creds:
                if not sub:
                    for k in non_explicit_keys:
                        nested_delete(conf, ARGUMENTS[k][1])
                else:
                    for k in sub_non_explicit_keys:
                        nested_delete(conf, ARGUMENTS[k][1])

            if inserted_non_explicit_creds:
                if not sub:
                    for k in explicit_keys:
                        nested_delete(conf, ARGUMENTS[k][1])
                else:
                    for k in sub_explicit_keys:
                        nested_delete(conf, ARGUMENTS[k][1])
        else:
            sys.exit(0)

    if 'sts-external-id' in creds and 'sts-role' not in creds:
        sys.stderr.write(
            'please specify an STS role to assume with the STS external ID\n')
        sys.exit(2)


def validate_controller_credentials(conf, args):
    controller_name = getattr(args, CONTROLLER_NAME, None)
    credentials_keys = ['access-key', 'secret-key', 'cred-file', 'sts-role',
                        'sts-external-id']
    try:
        controller = conf[CONTROLLERS][controller_name]
    except KeyError:
        return

    if controller['class'] == AWS:
        credentials = dict((k, controller[k]) for k in credentials_keys if k in
                           controller)
        verify_AWS_credentials(conf, args, credentials)
        # verify sub-creds
        if SUBCREDS in controller:
            for k, v in controller[SUBCREDS].iteritems():
                verify_AWS_credentials(conf, args, v, sub=True)

    elif controller['class'] == 'Azure':
        credentials = controller['credentials']
        spa = {'tenant', 'grant_type', 'client_id', 'client_secret'}
        upa = {'username', 'password'}

        is_adding_spa = getattr(args, 'Service Principal credentials tenant',
                                None)
        if is_adding_spa:
            nested_set(controller, ['credentials', 'grant_type'],
                       'client_credentials')

        current = set(credentials.keys())

        if not current:
            sys.stderr.write(
                'controller %s is missing credentials. To change '
                'credentials use set\n' % controller_name)
            sys.exit(2)

        if 0 < len(current & spa) < len(spa):
            sys.stderr.write(
                'please specify tenant, client ID and client secret or '
                'specify different credentials\n')
            sys.exit(2)

        if 0 < len(current & upa) < len(upa):
            sys.stderr.write('please specify username and password or '
                             'specify different credentials\n')
            sys.exit(2)

        if current == spa | upa:
            if args.force or prompt(
                    'replace existing credentials?'):
                if is_adding_spa:
                    for key in ['Azure username', 'Azure password']:
                        nested_delete(conf, ARGUMENTS[key][1])
                else:
                    for key in ['tenant', 'grant_type', 'client_id',
                                'client_secret']:
                        nested_delete(conf, [CONTROLLERS, controller_name,
                                             'credentials', key])
            else:
                sys.exit(0)

    elif controller['class'] == 'GCP':
        # No dependencies between fields
        pass


def validate_template_dependencies(conf, args):
    template_name = getattr(args, TEMPLATE_NAME, None)

    try:
        template = conf[TEMPLATES][template_name]
    except KeyError:
        return

    if 'version' in template and template['version'] != 'R77.30':
        if 'ips-profile' in template and template['ips-profile']:
            sys.stderr.write(
                'IPS profile can only be associated with R77.30 gateway\n')
            sys.exit(2)


def validate_management(conf, args):
    if getattr(args, 'Management password', None):
        if 'b64password' in conf[MANAGEMENT]:
            if args.force or prompt(
                    'replace the base64 encoded password?'):
                nested_delete(conf, [MANAGEMENT, 'b64password'])
            else:
                sys.exit(0)
    elif getattr(args, 'Management password 64bit', None):
        if 'password' in conf[MANAGEMENT]:
            if args.force or prompt(
                    'replace the password?'):
                nested_delete(conf, [MANAGEMENT, 'password'])
            else:
                sys.exit(0)

    is_local = conf[MANAGEMENT]['host'].split(':')[0] in {'127.0.0.1',
                                                          'localhost'}
    if not is_local:
        not_local_mandatory = {'user', 'password', 'fingerprint'}
        current = set(conf[MANAGEMENT].keys())
        if current & not_local_mandatory < not_local_mandatory:
            sys.stderr.write(
                'host is not local, please specify username, password and '
                'fingerprint\n')
            sys.exit(2)


def validate_min_objects(conf):
    if MANAGEMENT not in conf:
        sys.stderr.write('management settings are missing\n')
        sys.exit(2)

    if not set(MANDATORY_KEYS[MANAGEMENT]).issubset(conf[MANAGEMENT]):
        sys.stderr.write('management is missing mandatory keys\n')
        sys.exit(2)

    templates = conf[TEMPLATES]
    if not templates:
        sys.stderr.write('there should be at least one template\n')
        sys.exit(2)

    controllers = conf[CONTROLLERS]
    if not controllers:
        sys.stderr.write('there should be at least one controller\n')
        sys.exit(2)

    for controller, values in controllers.iteritems():
        if not set(MANDATORY_KEYS[values['class']]).issubset(values.keys()):
            sys.stderr.write(
                'controller %s is missing mandatory keys\n' % controller)
            sys.exit(2)


def nested_delete(dic, keys):
    """Deletes a value in a nested dictionary.

    According to the list of keys leading to the relevant key
    """

    for key in keys[:-1]:
        dic = dic.get(key, {})

    dic.pop(keys[-1], None)


def nested_set(conf, keys, value):
    """Sets a value in a nested dictionary.

    According to the list of keys leading to the relevant key.
    """

    for key in keys[:-1]:
        conf = conf.setdefault(key, {})

    conf[keys[-1]] = value


def get_subaccounts_names(conf, controller_name):
    try:
        lst = conf[CONTROLLERS][controller_name][SUBCREDS].keys()
        return lst
    except KeyError:
        return []


def validate_regions(args, input):
    regions = input.split(',')
    for region in regions:
        if region not in AWS_REGIONS:
            if not (args.force or prompt(
                    'the region %s is not in the regions list %s. '
                    'Are you sure?' % (region, AWS_REGIONS))):
                sys.exit(0)
    return regions


def validate_conf(conf, args):
    # Validate all
    validate_min_objects(conf)
    validate_management(conf, args)

    if getattr(args, TEMPLATE_NAME, None):
        # Adding or editing a template
        validate_template_dependencies(conf, args)

    if getattr(args, CONTROLLER_NAME, None):
        # Adding or editing a controller
        validate_controller_credentials(conf, args)


def nested_get(dic, keys):
    for key in keys:
        try:
            dic = dic[key]
        except KeyError:
            return None
    return dic


def delete_branch(conf, args, branch):
    if branch is TEMPLATES:
        template_name = getattr(args, TEMPLATE_NAME)
        if args.force or prompt('are you sure you want to delete %s?' %
                                template_name):
            nested_delete(conf, [TEMPLATES, template_name])

    if branch is CONTROLLERS:
        controller_name = getattr(args, CONTROLLER_NAME)
        if args.force or prompt('are you sure you want to delete %s?' %
                                controller_name):
            nested_delete(conf, [CONTROLLERS, controller_name])

    if branch is SUBCREDS:
        sub_creds_name = getattr(args, SUBCREDENTIALS_NAME, None)
        path = ARGUMENTS[SUBCREDENTIALS_NAME][1]
        path.append(sub_creds_name)
        if args.force or prompt('are you sure you want to delete %s\'s '
                                '%s sub-account?' % (path[-3], path[-1])):
            nested_delete(conf, path)


def delete_arguments(conf, args):
    """Remove either a property or an entire object."""

    branches = (TEMPLATES, CONTROLLERS, SUBCREDS)
    for branch in branches:
        list_of_args_of_branch = [arg for arg in vars(args)
                                  if getattr(args, arg, None) and
                                  ARGUMENTS.get(arg, False) and
                                  branch in ARGUMENTS[arg][1]]

        if len(list_of_args_of_branch) == 1:
            delete_branch(conf, args, branch)

    for arg in sorted(vars(args)):
        if arg not in NON_CONFIG_KEYS and getattr(args, arg):
            path = ARGUMENTS[arg][1]
            if arg is SUBCREDENTIALS_NAME:
                path.append(getattr(args, arg))
            if not nested_get(conf, path):
                sys.stdout.write('%s does not exist in %s\n' %
                                 (path[-1], (path[-2])))
            elif args.force or prompt('are you sure you want to delete %s\'s '
                                      '%s?' % (path[-2], path[-1])):
                nested_delete(conf, path)


def handle_change_of_branch_name(conf, args):
    template_new_name = getattr(args, TEMPLATE_NEW_NAME, None)
    controller_new_name = getattr(args, CONTROLLER_NEW_NAME, None)

    if template_new_name:
        conf[TEMPLATES][template_new_name] = conf[TEMPLATES].pop(getattr(
            args, TEMPLATE_NAME))
        setattr(args, TEMPLATE_NAME, TEMPLATE_NEW_NAME)
        return True

    if controller_new_name:
        conf[CONTROLLERS][controller_new_name] = conf[CONTROLLERS].pop(getattr(
            args, CONTROLLER_NAME))
        setattr(args, CONTROLLER_NAME, CONTROLLER_NEW_NAME)
        return True

    return False


def is_adding_an_existing_object(conf, args):
    template_name = getattr(args, TEMPLATE_NAME, None)
    controller_name = getattr(args, CONTROLLER_NAME, None)

    if template_name and template_name in conf[TEMPLATES].keys():
        sys.stderr.write(
            'template %s exists. Use set to edit or delete it first\n' %
            template_name)
        sys.exit(2)

    if controller_name and controller_name in conf[CONTROLLERS].keys():
        sys.stderr.write(
            'controller %s exists. Use set to edit or delete it first\n' %
            controller_name)
        sys.exit(2)


def set_all_none_control_args(conf, args):
    changed = False
    for key, value in vars(args).iteritems():
        if value and key not in NON_CONFIG_KEYS:
            path = ARGUMENTS[key][1]
            nested_set(conf, path, value)
            changed = True

    return changed


def custom_validations(conf, args):
    """
    Validates user input on top of argparse validations
    """
    inputted_regions = getattr(args, 'regions', None)
    if inputted_regions and (args.mode == INIT or args.mode == ADD or
                                     args.mode == SET):
        setattr(args, 'regions', validate_regions(args, inputted_regions))

    if [key for key in AWS_SUBACCOUNT_ARGS if getattr(args, key, None)]:
        subcred_name = getattr(args, SUBCREDENTIALS_NAME, None)
        if not subcred_name:
            sys.stderr.write('please specify the name of the sub-account\n')
            sys.exit(2)
        else:
            if args.mode == DELETE:
                controller_name = getattr(args, CONTROLLER_NAME)
                sub_cred_names = get_subaccounts_names(conf, controller_name)
                if subcred_name not in sub_cred_names:
                    sys.stderr.write(
                        'sub-account %s does not exist. Choose from: %s\n' %
                        (subcred_name, ', '.join(sub_cred_names)))
                    sys.exit(2)
            if (args.mode == ADD or args.mode == SET) and not (any(
                    getattr(args, k) for k in
                    set(AWS_SUBACCOUNT_ARGS) - {SUBCREDENTIALS_NAME})):
                sys.stderr.write('sub-account %s is missing arguments.\n' %
                                 subcred_name)
                sys.exit(2)


def print_conf(root, indent=0):
    if type(root) == collections.OrderedDict:
        for key, value in root.items():
            if hasattr(value, '__iter__'):
                sys.stdout.write('%s%s:\n' % (' ' * indent, key))
                print_conf(value, indent + 2)
            else:
                sys.stdout.write('%s%s: %s\n' % (' ' * indent, key, value))
    elif type(root) == list:
        for value in root:
            if hasattr(value, '__iter__'):
                print_conf(value, indent + 2)
            else:
                sys.stdout.write('%s- %s\n' % (' ' * indent, value))
    else:
        sys.stdout.write('%s%s\n' % (' ' * indent, root))


def process_arguments(conf, args):
    """ Process the auxiliary and user arguments.

    Edits the configuration accordingly.
    Restarts the auto-provisioning service when done.
    """
    old_conf = copy.deepcopy(conf)

    if args.mode == 'show':
        if conf:
            if args.branch == 'all':
                print_conf(conf)
            else:
                try:
                    print_conf(conf[args.branch])
                except KeyError:
                    sys.stdout.write('no %s to display\n' % args.branch)
        else:
            sys.stdout.write(
                'configuration file was not initialized, please use init\n')

        sys.exit(0)

    custom_validations(conf, args)
    update_paths_with_user_input(args)

    if args.mode == 'init':
        if conf:
            if args.force or prompt(
                    'configuration exists, '
                    'are you sure you would like to initialize it? '
                    '(previous settings will be deleted)'):
                conf.clear()
                set_all_none_control_args(conf, args)
            else:
                sys.exit(0)
        else:
            set_all_none_control_args(conf, args)
    else:
        if not conf:
            sys.stdout.write(
                'configuration file was not initialized, please use init\n')
            sys.exit(0)

    if args.mode == 'add':
        is_adding_an_existing_object(conf, args)
        if not set_all_none_control_args(conf, args):
            sys.stdout.write(
                'too few arguments. No changes were made\n')
            sys.exit(0)

    if args.mode == 'set':
        if not (handle_change_of_branch_name(conf, args) or
                set_all_none_control_args(conf, args)):
            sys.stdout.write(
                'too few arguments. No changes were made\n')
            sys.exit(0)

    if args.mode == 'delete':
        delete_arguments(conf, args)

    validate_conf(conf, args)

    if old_conf == conf:
        sys.stdout.write(
            'no changes were made \n')
        sys.exit(0)

    if os.path.exists(CONFPATH):
        shutil.copyfile(CONFPATH, CONFPATH + '.bak')

    with open(CONFPATH, 'w') as f:
        json.dump(conf, f, indent=2, separators=(',', ': '), sort_keys=True)
        f.write('\n')

    if args.force or prompt(
            'would you like to restart the autoprovision service now?'):
        subprocess.call('service autoprovision restart', shell=True)


def update_paths_with_user_input(args):
    new_key_args = getattr(args, NEW_KEY, None)
    new_value = None

    if new_key_args:
        new_key = new_key_args[0]
        if len(new_key_args) == 2:
            new_value = new_key_args[1]
        elif len(new_key_args) == 1:  # facilitates delete
            new_value = True

        setattr(args, NEW_KEY, new_key)

    for k, v in vars(args).iteritems():
        if v and k in KEYS_TO_UPDATE_WITH_USER_INPUT:
            for argument in ARGUMENTS.values():
                path = argument[1]
                if k in path:
                    index = path.index(k)
                    path[index] = v

    if new_key_args:
        setattr(args, NEW_KEY, new_value)


def add_arguments(parser, parser_data):
    parser._optionals.title = 'global arguments'
    required_group = parser.add_argument_group('required arguments')
    optional_group = parser.add_argument_group('optional arguments')

    for argument in parser_data[1] + parser_data[2]:
        if isinstance(argument, tuple):
            argument_key = argument[0]
            custom_kwargs = argument[1]
            argument_data = ARGUMENTS[argument[0]]
        else:
            argument_key = argument
            custom_kwargs = None
            argument_data = ARGUMENTS[argument]

        kwargs = {'help': argument_data[2]}

        if argument_data[0][0] is '-':
            # not positional (e.g. not delay, branch)
            kwargs.update({'dest': argument_key})

        if custom_kwargs:
            kwargs.update(custom_kwargs)

        if not custom_kwargs and argument_data[3]:
            kwargs.update(argument_data[3])

        if argument in parser_data[1]:
            kwargs.update({'required': True})
            required_group.add_argument(argument_data[0], **kwargs)
        else:
            optional_group.add_argument(argument_data[0], **kwargs)


def add_parser(conf, father, son_key):
    parser_data = create_parser_dict(conf)[son_key]

    if parser_data[4]:  # has epilog
        subparser = father.add_parser(
            parser_data[0], help=parser_data[3], epilog=parser_data[4],
            formatter_class=argparse.RawDescriptionHelpFormatter)
    else:
        subparser = father.add_parser(parser_data[0], help=parser_data[3])

    if parser_data[5]:  # has defaults
        subparser.set_defaults(**parser_data[5])

    add_arguments(subparser, parser_data)
    return subparser


def build_parsers(conf):
    """Create the parser.

    Creates the main subparsers (init, show, add, set, delete) and
    their subparsers (delay, management, templates, controllers)
    """
    main_parser = argparse.ArgumentParser()
    main_parser.add_argument('--force', '-f', action='store_true',
                             help='skip prompts')
    main_subparsers = main_parser.add_subparsers(
        help='available actions', dest='mode')

    add_parser(conf, main_subparsers, SHOW)
    init_subparser = add_parser(conf, main_subparsers, INIT)
    add_subparser = add_parser(conf, main_subparsers, ADD)
    set_subparser = add_parser(conf, main_subparsers, SET)
    delete_subparser = add_parser(conf, main_subparsers, DELETE)

    init_subparsers = init_subparser.add_subparsers()
    add_parser(conf, init_subparsers, 'init_aws')
    add_parser(conf, init_subparsers, 'init_azure')
    add_parser(conf, init_subparsers, 'init_gcp')

    add_subparsers = add_subparser.add_subparsers(dest='branch')

    add_parser(conf, add_subparsers, 'add_template')
    add_controller_subparser = add_parser(conf, add_subparsers,
                                          'add_controller')

    add_controller_subparsers = add_controller_subparser.add_subparsers()
    add_parser(conf, add_controller_subparsers, 'add_controller_aws')
    add_parser(conf, add_controller_subparsers, 'add_controller_azure')
    add_parser(conf, add_controller_subparsers, 'add_controller_gcp')

    set_subparsers = set_subparser.add_subparsers(dest='branch')
    add_parser(conf, set_subparsers, 'set_delay')
    add_parser(conf, set_subparsers, 'set_management')
    add_parser(conf, set_subparsers, 'set_template')
    set_controller_subparser = add_parser(conf, set_subparsers,
                                          'set_controller')

    set_controller_subparsers = set_controller_subparser.add_subparsers()
    add_parser(conf, set_controller_subparsers, 'set_controller_aws')
    add_parser(conf, set_controller_subparsers, 'set_controller_azure')
    add_parser(conf, set_controller_subparsers, 'set_controller_gcp')

    delete_subparsers = delete_subparser.add_subparsers(dest='branch')
    add_parser(conf, delete_subparsers, 'delete_management')
    add_parser(conf, delete_subparsers, 'delete_template')
    delete_controller_subparser = add_parser(conf, delete_subparsers,
                                             'delete_controller')

    delete_controller_subparsers = delete_controller_subparser.add_subparsers()
    add_parser(conf, delete_controller_subparsers, 'delete_controller_aws')
    add_parser(conf, delete_controller_subparsers, 'delete_controller_azure')
    add_parser(conf, delete_controller_subparsers, 'delete_controller_gcp')

    return main_parser


def prompt(question):
    """Displays a yes/no prompt with a question to the user."""

    while True:
        sys.stdout.write(question + ' (y/n) ')
        choice = raw_input().lower()
        if choice in ['', 'n', 'no']:
            return False
        elif choice in ['y', 'yes']:
            return True
        else:
            sys.stdout.write('please respond with "y" or "n"\n')


def load_configuration():
    """Loads the configuration and the exiting templates and controllers."""
    if os.path.exists(CONFPATH):
        try:
            with open(CONFPATH) as f:
                conf = json.load(f, object_pairs_hook=collections.OrderedDict)
        except:
            if prompt('failed to read configuration file: %s. '
                      'Would you like to delete it?' % CONFPATH):
                os.remove(CONFPATH)
                sys.exit(0)
            else:
                sys.stderr.write('failed to read configuration file: %s\n' %
                                 CONFPATH)
                sys.exit(2)
    else:
        conf = collections.OrderedDict()

    return conf


def main():
    conf = load_configuration()
    parsers = build_parsers(conf)
    parsed_arguments = parsers.parse_args()
    process_arguments(conf, parsed_arguments)


if __name__ == '__main__':
    main()
