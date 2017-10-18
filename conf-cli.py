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
import json
import os
import re
import subprocess
import shutil
import sys

MANDATORY_KEYS = {
    'management': ['name', 'host'],
    'templates': ['one-time-password', 'version', 'policy'],
    'AWS': ['class', 'regions'],
    'Azure': ['class', 'subscription'],
    'GCP': ['class', 'project', 'credentials']
}

AZURE_ENVIRONMENTS = ['AzureCloud',
                      'AzureChinaCloud',
                      'AzureGermanCloud',
                      'AzureUSGovernment']

AVAILABLE_VERSIONS = ['R77.30', 'R80.10']

AWS_REGIONS = ['us-east-2',
               'us-east-1',
               'us-west-1',
               'us-west-2',
               'ap-south-1',
               'ap-northeast-2',
               'ap-southeast-1',
               'ap-southeast-2',
               'ap-northeast-1',
               'ca-central-1',
               'eu-central-1',
               'eu-west-1',
               'eu-west-2',
               'sa-east-1',
               'cn-north-1',
               'us-gov-west-1']

# Auxiliary args to ignore when inserting in to configuration
AUXILIARY_ARGUMENTS = ['mode',
                       'branch',
                       'force',
                       'templates_name',
                       'controllers_name',
                       'templates_new-name',
                       'templates_new-key',
                       'controllers_new-name']

MIN_SIC_LENGTH = 8

USAGE_EXAMPLES = {
    'init_aws': ['init AWS -mn <MANAGEMENT-NAME> '
                 '-tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
                 '-po <POLICY-NAME> -cn <CONTROLLER-NAME> '
                 '-r eu-west-1,us-east-1,eu-central-1 '
                 'file <FILE-PATH>',
                 'init AWS -mn <MANAGEMENT-NAME> '
                 '-tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
                 '-po <POLICY-NAME> -cn <CONTROLLER-NAME> '
                 '-r eu-west-1,us-east-1,eu-central-1 '
                 'explicit -ak <ACCESS-KEY> -sk <SECRET-KEY>',
                 'init AWS -mn <MANAGEMENT-NAME> '
                 '-tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
                 '-po <POLICY-NAME> -cn <CONTROLLER-NAME> '
                 '-r eu-west-1,us-east-1,eu-central-1 IAM'
                 ],
    'init_azure': ['init Azure -mn <MANAGEMENT-NAME> '
                   '-tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
                   '-po <POLICY-NAME> -cn <CONTROLLER-NAME> '
                   '-as <SUBSCRIPTION> '
                   'sp -at <TENANT> -aci <CLIENT-ID> -acs <CLIENT-SECRET>',
                   'init Azure -mn <MANAGEMENT-NAME> '
                   '-tn <TEMPLATE-NAME> -otp <SIC-KEY> -v {R77.30,R80.10} '
                   '-po <POLICY-NAME> -cn <CONTROLLER-NAME> '
                   '-as <SUBSCRIPTION> '
                   'user -au <USERNAME> -ap <PASSWORD>'
                   ],
    'init_GCP': [],
    'show': ['show all',
             'show management',
             'show templates',
             'show controllers'
             ],
    'add_template': ['add template -n <TEMPLATE-NAME> '
                     '-otp <SIC-KEY> -v {R77.30,R80.10} -po <POLICY-NAME>',
                     'add template -n <TEMPLATE-NAME> '
                     '-otp <SIC-KEY> -v {R77.30,R80.10} -po <POLICY-NAME> '
                     '[-hi true] [-ia true] [-appi true]'],
    'add_controller_AWS': ['add controller AWS '
                           '-n <NAME> '
                           '-r eu-west-1,us-east-1,eu-central-1 '
                           'file <FILE-PATH>',
                           'add controller AWS '
                           '-n <NAME> '
                           '-r eu-west-1,eu-central-1 '
                           'explicit -ak <ACCESS-KEY> '
                           '-sk <SECRET-KEY>',
                           'add controller AWS '
                           '-n <NAME> '
                           '-r eu-west-1 IAM'
                           ],
    'add_controller_Azure': ['add controller '
                             'Azure -n <NAME> '
                             '-sb <SUBSCRIPTION> '
                             '[-en {AzureCloud,AzureChinaCloud,'
                             'AzureGermanCloud,AzureUSGovernment}] '
                             'sp -at <TENANT> -aci <CLIENT-ID> '
                             '-acs <CLIENT-SECRET>',
                             'add controller '
                             'Azure -n <NAME> '
                             '-sb <SUBSCRIPTION> '
                             'user -au <USERNAME> -ap <PASSWORD>'
                             ],
    'add_controller_GCP': ['add controller GCP '
                           '-n <NAME> '
                           '-proj <PROJECT> -cr <FILE-PATH>'
                           ],
    'add_controller_OpenStack': ['add controller OpenStack '
                                 '-n <NAME> -sc {http,https} '
                                 '-ho <HOST> -fp <FINGERPRINT> '
                                 '-te <TENANT> -u <USER> -pass <PASSWORD>'],
    'set_delay': ['set delay 60'],
    'set_management': ['set management [-n <NEW-NAME>] '
                       '[-ho <NEW-HOST> [-d <DOMAIN>] '
                       '[-fp <FINGERPRINT>] [-u <USER>] '
                       '[-pass <PASSWORD>] [-pr <PROXY>] '
                       '[-cs <CUSTOM-SCRIPT-PATH>]'],
    'set_template': ['set template -n <NAME> '
                     '[-nn <NEW-NAME>] '
                     '[-otp <SIC-KEY>] '
                     '[-v {R77.30,R80.10}] [-po <POLICY>]',
                     'set template -n <NAME> '
                     '[-hi true] [-ia true] [-appi true]'
                     ],
    'set_controller_AWS': ['set controller AWS '
                           '-n <NAME> [-nn <NEW-NAME>]',
                           'set controller AWS '
                           '-n <NAME> [-cf <FILE-PATH> | -iam]'],
    'set_controller_Azure': ['set controller Azure '
                             '-n <NAME> [-nn <NEW-NAME>] '
                             '[-au <USERNAME>] '
                             '[-ap <PASSWORD>]',
                             'set controller Azure '
                             '-n <NAME> [-d <DOMAIN>]'
                             ],
    'set_controller_GCP': ['set controller GCP -n <NAME> '
                           '[-nn <NEW-NAME>] '
                           '[-cr <FILE-PATH> | "IAM"]'],
    'set_controller_OpenStack': ['set controller OpenStack '
                                 '-n <NAME> '
                                 '[-ho <HOST>] '
                                 '[-fp <FINGERPRINT>]',
                                 'set controller OpenStack '
                                 '-n <NAME> '
                                 '[-nn <NEW-NAME>]'
                                 ],
    'delete_management': ['delete management',
                          'delete management -pr'
                          ],
    'delete_template': [
        'delete template -n <NAME>',
        'delete template -n <NAME> [-pr] [-cp]'
        ],
    'delete_controller_AWS': [
        'delete controller AWS -n <NAME> ',
        'delete controller AWS '
        '-n <NAME> [-d] [-cf]'
        ],
    'delete_controller_Azure': ['delete controller Azure '
                                '-n <NAME> ',
                                'delete controller Azure '
                                '-n <NAME> [-d] [-ap]'
                                ],
    'delete_controller_GCP': [
        'delete controller GCP -n <NAME> ',
        'delete controller GCP '
        '-n <NAME> [-t] [-cr]'
        ],
    'delete_controller_OpenStack': [
        'delete controller OpenStack '
        '-n <NAME> ',
        'delete controller OpenStack '
        '-n <NAME> [-d] [-sc]'
        ],
}

CONFPATH = os.environ['FWDIR'] + '/conf/autoprovision.json'


def my_error(self, message):
    self.print_help(sys.stderr)
    self.exit(2, ('\n%s: error: %s\n') % (self.prog, message))


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


argparse.ArgumentParser._check_value = my_check_value
argparse.ArgumentParser.error = my_error


def nested_delete(dic, keys):
    """Deletes a value in a nested dictionary.

    According to the list of keys leading to the relevant key
    """

    for key in keys[:-1]:
        dic = dic.get(key, {})

    dic.pop(keys[-1], None)


def get_branch(args):
    if args.branch == 'template':
        return 'templates'
    elif args.branch == 'controller':
        return 'controllers'
    else:
        return args.branch


def delete_arguments(conf, args):
    """Remove either a property or an entire object."""

    removed_inner_argument = False
    # Check if any inner arguments were specified and remove
    for arg in vars(args):
        if arg not in AUXILIARY_ARGUMENTS and getattr(args, arg):
            path = get_value_path(arg, args)
            if args.force or prompt('Are you sure you want to delete %s\'s '
                                    '%s?' % (path[-2], path[-1])):
                nested_delete(conf, path)
                removed_inner_argument = True
            else:
                sys.exit(0)

    # Did not remove inner arguments, removing entire branch
    if not removed_inner_argument:
        # Get branch to delete (args.branch is either management, template
        # or controller).
        # Singular for usability, plural for JSON hierarchy path.
        path = get_value_path(get_branch(args), args)
        if args.force or prompt('Are you sure you want to delete %s?' %
                                path[-1]):
            nested_delete(conf, path)
        else:
            sys.exit(0)


def nested_set(dic, keys, value):
    """Sets a value in a nested dictionary.

    According to the list of keys leading to the relevant key.
    """

    for key in keys[:-1]:
        dic = dic.setdefault(key, {})

    dic[keys[-1]] = value


def validate_template_dependencies(conf, args):
    template_name = args.templates_name

    try:
        template = conf['templates'][template_name]
    except KeyError:
        return

    if 'version' in template and template['version'] != 'R77.30':
        if 'ips-profile' in template and template['ips-profile']:
            sys.stderr.write(
                "IPS profile can only be associated with R77.30 gateway")
            sys.exit(2)


def validate_controller_credentials(conf, args):
    controller_name = args.controllers_name

    try:
        controller = conf['controllers'][controller_name]
    except KeyError:
        return

    if controller['class'] == 'AWS':
        # No credentials
        if not ('cred-file' in controller or 'access-key' in controller):
            sys.stderr.write(
                "Controller %s is missing credentials." % controller_name)
            sys.exit(2)

        # Missing either of access key or secret key
        if ('access-key' in controller) != ('secret-key' in controller):
            sys.stderr.write(
                "Please specify both access key and secret key or specify "
                "different credentials.")
            sys.exit(2)

        # Has too many, credentials file and explicit
        if 'cred-file' in controller and 'access-key' in controller:
            if args.force or prompt(
                    'Replace existing credentials?'):
                # Check what has been inserted in the last command
                if getattr(args, 'controllers_cred-file', None):
                    # Editing contained credentials file, delete explicit
                    for key in ['access-key', 'secret-key']:
                        nested_delete(conf, ['controllers', controller_name,
                                             key])
                else:
                    # Editing contained credentials other than credentials
                    # file, delete the credentials file
                    nested_delete(conf, ['controllers', controller_name,
                                         'cred-file'])
            else:
                sys.exit(2)
    elif controller['class'] == 'Azure':
        credentials = controller['credentials']
        spa = {'tenant', 'grant_type', 'client_id', 'client_secret'}
        upa = {'username', 'password'}

        is_adding_spa = getattr(args, 'controllers_credentials_tenant', None)
        if is_adding_spa:
            nested_set(controller, ['credentials', 'grant_type'],
                       'client_credentials')

        current = set(credentials.keys())

        if not current:
            sys.stderr.write(
                "Controller %s is missing credentials." % controller_name)
            sys.exit(2)

        if 0 < len(current & spa) < len(spa):
            sys.stderr.write(
                "Please specify tenant, client ID and client secret or "
                "specify different credentials.")
            sys.exit(2)

        if 0 < len(current & upa) < len(upa):
            sys.stderr.write("Please specify username and password or "
                             "specify different credentials.")
            sys.exit(2)

        if current == spa | upa:
            if args.force or prompt(
                    'Replace existing credentials?'):
                if is_adding_spa:
                    for key in ['username', 'password']:
                        nested_delete(conf, ['controllers', controller_name,
                                             'credentials', key])
                else:
                    for key in ['tenant', 'grant_type', 'client_id',
                                'client_secret']:
                        nested_delete(conf, ['controllers', controller_name,
                                             'credentials', key])
            else:
                sys.exit(0)

    elif controller['class'] == 'GCP':
        # No dependencies between fields
        pass


def validate_management(conf, args):
    if getattr(args, 'management_password', None):
        if 'b64password' in conf['management']:
            if args.force or prompt(
                    'Replace the base64 encoded password?'):
                nested_delete(conf, ['management', 'b64password'])
            else:
                sys.exit(0)
    elif getattr(args, 'management_b64password', None):
        if 'password' in conf['management']:
            if args.force or prompt(
                    'Replace the password?'):
                nested_delete(conf, ['management', 'password'])
            else:
                sys.exit(0)

    # TODO: Any reason for user and password to exist when not local?
    is_local = conf['management']['host'].split(':')[0] in {'127.0.0.1',
                                                            'localhost'}
    if not is_local:
        not_local_mandatory = {'user', 'password', 'fingerprint'}
        current = set(conf['management'].keys())
        if current & not_local_mandatory < not_local_mandatory:
            sys.stderr.write(
                "Host is not local, please specify username, password and "
                "fingerprint.")
            sys.exit(2)


def validate_min_objects(conf):
    if 'management' not in conf:
        sys.stderr.write("Management settings are missing.")
        sys.exit(2)

    if not set(MANDATORY_KEYS['management']).issubset(conf['management']):
        sys.stderr.write("Management is missing mandatory keys.")
        sys.exit(2)

    templates = conf['templates']
    if not templates:
        sys.stderr.write("There should be at least one template.")
        sys.exit(2)

    controllers = conf['controllers']
    if not controllers:
        sys.stderr.write("There should be at least one controller.")
        sys.exit(2)

    for controller, values in controllers.iteritems():
        if not set(MANDATORY_KEYS[values['class']]).issubset(values.keys()):
            sys.stderr.write(
                "Controller %s is missing mandatory keys." % controller)
            sys.exit(2)


def validate_conf(conf, args):
    # Validate all
    validate_min_objects(conf)
    validate_management(conf, args)

    if getattr(args, 'templates_name'):
        # Adding or editing a template
        validate_template_dependencies(conf, args)

    if getattr(args, 'controllers_name'):
        # Adding or editing a controller
        validate_controller_credentials(conf, args)


def is_adding_an_existing_object(conf, args):
    template_name = getattr(args, 'templates_name')
    controller_name = getattr(args, 'controllers_name')
    if template_name in conf['templates'].keys():
        sys.stderr.write(
            'Template %s exists. Use set to edit or delete it first.' %
            template_name)
        sys.exit(2)

    if controller_name in conf['controllers'].keys():
        sys.stderr.write(
            'Controller %s exists. Use set to edit or delete it first.' %
            controller_name)
        sys.exit(2)


def handle_change_of_branch_name(conf, args):
    if hasattr(args, 'templates_new-name'):
        template_new_name = getattr(args, 'templates_new-name')
        if template_new_name is not None:
            conf['templates'][template_new_name] = conf['templates'].pop(
                args.templates_name)
            args.templates_name = template_new_name

    if hasattr(args, 'controllers_new-name'):
        controller_new_name = getattr(args, 'controllers_new-name')
        if controller_new_name is not None:
            conf['controllers'][controller_new_name] = conf['controllers'].pop(
                args.controller_new_name)
            args.controllers_name = controller_new_name


def get_value_path(key, args):
    """Receives a '_' delimited string and the command arguments.

    Returns the path in the configuration's JSON hierarchy
    to the relevant key-value.

    For root items, just one key. e.g: ['delay']
    For managements items, two items. e.g. ['management', 'host]
    For templates or controllers, dynamically insert the name of object
    to the path. e.g. ['templates', name_of_template, 'one_time_password']

    Path strings (destination of argparse arguments)
    should be in the format of EXACT-PARENT-NAME_EXACT-CHILD-NAME
    """

    path = key.split('_')

    if path[0] == 'management':
        if len(path) == 1:
            return ['management']
        else:
            return ['management', path[1]]
    if path[0] == 'templates':
        if len(path) == 1:
            return ['templates', args.templates_name]
        else:
            return ['templates', args.templates_name, path[1]]
    if path[0] == 'controllers':
        if len(path) == 1:
            return ['controllers', args.controllers_name]
        if len(path) == 2:
            return ['controllers', args.controllers_name, path[1]]
        if len(path) >= 3:
            # Maximum depth is 3,
            # join accommodates Azure's underscore keys such as grant_type
            return ['controllers',
                    args.controllers_name, path[1],
                    '_'.join(path[2:])]

    # depth 1, such as delay
    return [path[0]]


def set_all_none_control_args(conf, args):
    for arg in vars(args):
        value = getattr(args, arg)
        if arg not in AUXILIARY_ARGUMENTS and value is not None:
            # Custom check for regions to facilitate -f
            if 'regions' in arg:
                value = validate_regions(args, value)
            nested_set(conf,
                       get_value_path(arg, args),
                       value)


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
    if args.mode == 'show':
        if conf:
            if args.branch == 'all':
                print_conf(conf)
            else:
                try:
                    print_conf(conf[args.branch])
                except KeyError:
                    sys.stdout.write("No %s to display\n" % args.branch)
        else:
            sys.stdout.write(
                'Configuration file was not initiated, please use init\n')

        sys.exit(0)

    if args.mode == 'init':
        if conf:
            if args.force or prompt(
                    'Configuration exists, '
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
                'Configuration file was not initiated, please use init\n')
            sys.exit(0)

    if args.mode == 'add':
        is_adding_an_existing_object(conf, args)
        set_all_none_control_args(conf, args)

    if args.mode == 'set':
        handle_change_of_branch_name(conf, args)
        set_all_none_control_args(conf, args)

    if args.mode == 'delete':
        delete_arguments(conf, args)

    validate_conf(conf, args)

    if os.path.exists(CONFPATH):
        shutil.copyfile(CONFPATH, CONFPATH + '.bak')  # create backup

    # dump to JSON
    with open(CONFPATH, 'w') as f:
        json.dump(conf, f, indent=2, separators=(',', ': '))
        f.write('\n')

    if args.force or prompt(
            'Would you like to restart the autoprovision service now?'):
        subprocess.call("service autoprovision restart", shell=True)


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
            sys.stdout.write('Please respond with "y" or "n"\n')


def get_controllers(conf, clazz):
    """Return an array of names of existing 'clazz' controllers."""
    try:
        lst = [c for c in conf['controllers']
               if conf['controllers'][c]['class'] == clazz]
        return lst
    except KeyError:
        return []


def get_templates(conf):
    """Return an array of names of existing templates."""
    try:
        return conf['templates'].keys()
    except KeyError:
        return []


# Argparse validation methods

def validate_SIC(value):
    """Validates length and char restrictions of the SIC value."""

    if len(value) < MIN_SIC_LENGTH:
        raise argparse.ArgumentTypeError(
            'One time password should consist of at least %s characters.'
            % repr(MIN_SIC_LENGTH))
    if not value.isalnum():
        raise argparse.ArgumentTypeError(
            'One time password should contain only alphanumeric characters.')
    return value


def validate_guid_uuid(value):
    pattern = re.compile(
        '^[0-9A-F]{8}[-]?([0-9A-F]{4}[-]?){3}[0-9A-F]{12}$',
        re.IGNORECASE)

    if not pattern.match(value):
        raise argparse.ArgumentTypeError('value %s is not a GUID' % value)

    return value


def validate_bool(value):
    if value.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif value.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def validate_regions(args, value):
    regions = value.split(",")
    for region in regions:
        if region not in AWS_REGIONS:
            if not (args.force or prompt(
                    'The region %s is not in the regions list %s. '
                    'Are you sure?' % (region, AWS_REGIONS))):
                sys.exit(0)
    return regions


def validate_filepath(value):
    if os.path.exists(value):
        return value

    raise argparse.ArgumentTypeError('File %s does not exist' % value)


def validate_iam_or_filepath(value):
    if value == 'IAM':
        return value

    return validate_filepath(value)


# Argpars argument creation methods

def create_del_gcp_arguments(gcp_parser, conf):
    """Add delete arguments to gcp_parser."""

    required_group = gcp_parser.add_argument_group(
        'Delete GCP Required Arguments')
    optional_group = gcp_parser.add_argument_group(
        'Delete GCP Optional Arguments')
    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        choices=get_controllers(conf, 'GCP'),
        help='The name of the cloud environment controller')
    optional_group.add_argument(
        '-proj', dest='controllers_project', action='store_true',
        help='the GCP project ID in which to scan for VM instances')
    optional_group.add_argument(
        '-cr', action='store_true',
        dest='controllers_credentials',
        help='either the path to a text file containing GCP credentials '
             'or "IAM" for automatic retrieval of the '
             'service account credentials from the VM instance metadata. '
             'Default: "IAM"')


def create_del_azure_arguments(azure_parser, conf):
    """Add delete arguments to azure_parser."""

    required_group = azure_parser.add_argument_group(
        'Delete Azure Required Arguments')
    optional_group = azure_parser.add_argument_group(
        'Delete Azure Optional Arguments')
    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        choices=get_controllers(conf, 'Azure'),
        help='The name of the cloud environment controller')
    optional_group.add_argument('-as',
                                dest='controllers_subscription',
                                action='store_true',
                                help='the Azure subscription ID')
    optional_group.add_argument('-at',
                                dest='controllers_credentials_tenant',
                                action='store_true',
                                help='the Azure Active Directory tenant ID')
    optional_group.add_argument(
        '-aci', dest='controllers_credentials_client_id',
        action='store_true',
        help='the application ID with which the '
             'service principal is associated')
    optional_group.add_argument('-acs',
                                dest='controllers_credentials_client_secret',
                                action='store_true',
                                help='the service principal password')
    optional_group.add_argument('-au',
                                dest='controllers_credentials_username',
                                action='store_true',
                                help='the Azure fully qualified user name')
    optional_group.add_argument('-ap',
                                dest='controllers_credentials_password',
                                action='store_true',
                                help='the password for the user')


def create_del_aws_arguments(aws_parser, conf):
    """Add delete arguments to aws_parser."""

    required_group = aws_parser.add_argument_group(
        'Delete AWS Required Arguments')
    optional_group = aws_parser.add_argument_group(
        'Delete AWS Optional Arguments')

    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        choices=get_controllers(conf, 'AWS'),
        help='The name of the cloud environment controller')
    optional_group.add_argument('-ak',
                                dest='controllers_access-key',
                                action='store_true',
                                help='AWS-ACCESS-KEY')
    optional_group.add_argument('-sk',
                                dest='controllers_secret-key',
                                action='store_true',
                                help='AWS-SECRET-KEY')
    optional_group.add_argument(
        '-cf', dest='controllers_cred-file',
        action='store_true',
        help='Either the path to a text file containing AWS credentials '
             'or an IAM role profile. Default: "IAM"')


def create_del_templates_arguments(del_template_subparser, conf):
    """Add to del_template_subparser its arguments."""

    del_template_subparser._optionals.title = 'Global Arguments'
    required_group = del_template_subparser.add_argument_group(
        'Delete Template Required Arguments')
    optional_group = del_template_subparser.add_argument_group(
        'Delete Template Optional Arguments')

    required_group.add_argument(
        '-n',
        required=True,
        dest='templates_name',
        choices=get_templates(conf),
        help='the name of the template')

    optional_group.add_argument(
        '-otp',
        action='store_true',
        dest='templates_one-time-password',
        help='the one time password used to initiate secure internal '
             'communication between the gateway and the management')
    optional_group.add_argument(
        '-v',
        action='store_true',
        dest='templates_version',
        help='the gateway version')
    optional_group.add_argument(
        '-po',
        action='store_true',
        dest='templates_policy',
        help='the pre-existing security policy package '
             'to be installed on the gateway')
    optional_group.add_argument(
        '-cp',
        action='store_true',
        dest='templates_custom-parameters',
        help='an optional string with space separated parameters or '
             'a list of string parameters to specify when a gateway is added '
             'and a custom script is specified in the management section')
    optional_group.add_argument(
        '-pr',
        action='store_true',
        dest='templates_proto',
        help='a prototype for this template')
    optional_group.add_argument(
        '-sn',
        action='store_true',
        dest='templates_specific-network',
        help='an optional name of a pre-existing network object group '
             'that defines the topology settings for the interfaces marked '
             'with "specific" topology. This attribute is mandatory '
             'if any of the scanned instances has an interface '
             'with a topology set to "specific". ')
    optional_group.add_argument(
        '-g',
        action='store_true',
        dest='templates_generation',
        help='an optional string or number that can be used to force '
             're-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '-pp',
        action='store_true',
        dest='templates_proxy-ports',
        help='an optional comma-separated list of list '
             'of TCP ports on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '-hi',
        action='store_true',
        dest='templates_https-inspection',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTPS Inspection feature on the gateway')
    optional_group.add_argument(
        '-ia',
        action='store_true',
        dest='templates_identity-awareness',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '-appi',
        action='store_true',
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '-ips',
        action='store_true',
        dest='templates_ips',
        help='an optional boolean attribute indicating '
             'whether to enable the Intrusion Prevention System '
             'feature on the gateway')
    optional_group.add_argument(
        '-ipf',
        action='store_true',
        dest='templates_ips-profile',
        help='an optional IPS profile name to '
             'associate with a pre-R80 gateway')
    optional_group.add_argument(
        '-uf',
        action='store_true',
        dest='templates_url-filtering',
        help='an optional boolean attribute indicating whether '
             'to enable the URL Filtering Awareness feature on the gateway')
    optional_group.add_argument(
        '-ab',
        action='store_true',
        dest='templates_anti-bot',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Bot feature on the gateway')
    optional_group.add_argument(
        '-av',
        action='store_true',
        dest='templates_anti-virus',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Virus feature on the gateway')
    optional_group.add_argument(
        '-rp',
        action='store_true',
        dest='templates_restrictive-policy',
        help='an optional name of a pre-existing policy package to be '
             'installed as the first policy on a new provisioned gateway. '
             '(Created to avoid a limitation in which Access Policy and '
             'Threat Prevention Policy cannot be installed at the first '
             'time together). In the case where no attribute is provided, '
             'a default policy will be used (the default policy has only '
             'the implied rules and a drop-all cleanup rule). '
             'The value null can be used to explicitly avoid any such policy.')
    optional_group.add_argument(
        '-nk', nargs=1,
        dest='templates_new-key',
        help='optional attributes of a gateway. Usage -nk [KEY]')


def create_del_management_arguments(del_management_subparsers):
    """Add to del_management_subparsers its arguments."""

    del_management_subparsers._optionals.title = 'Global Arguments'

    optional_group = del_management_subparsers.add_argument_group(
        'Delete Management Optional Arguments')
    optional_group.add_argument(
        '-d', dest='management_domain', action='store_true',
        help='the name or UID of the management domain if applicable')
    optional_group.add_argument(
        '-u', dest='management_user', action='store_true',
        help='a SmartCenter administrator username')
    optional_group.add_argument(
        '-pass', dest='management_password', action='store_true',
        help='the password associated with the user')
    optional_group.add_argument(
        '-pass64', dest='management_b64password', action='store_true',
        help='the base64 encoded password associated with the user (for '
             'additional obscurity)')
    optional_group.add_argument(
        '-pr', dest='management_proxy', action='store_true',
        help='"http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT" '
             '- an optional value for the https_proxy environment variable')
    optional_group.add_argument(
        '-cs', dest='management_custom-script',
        action='store_true',
        help='"PATH-TO-CUSTOMIZATION-SCRIPT" - '
             'An optional script to run just after the policy is installed '
             'when a gateway is provisioned, and at the beginning '
             'of the deprovisioning process. '
             'When a gateway is added the script will be run with the keyword '
             '"add", with the gateway name and the custom-parameters '
             'attribute in the template. '
             'When a gateway is deleted the script will run with the '
             'keyword "delete" and the gateway name. '
             'In the case of a configuration update '
             '(for example, a load balancing configuration change or a '
             'template/generation change), '
             'the custom script will be run with "delete" and '
             'later again with "add" and the custom parameters')
    optional_group.add_argument(
        '-fp', dest='management_fingerprint',
        action='store_true',
        help='disable fingerprint checking by providing an empty string "" '
             '(insecure but reasonable if running locally '
             'on the management server). '
             'To retrieve the fingerprint, '
             'run the following command on the management server (in bash): '
             'cpopenssl s_client -connect 127.0.0.1:443 2>/dev/null '
             '</dev/null | cpopenssl x509 -outform DER '
             '| sha256sum | awk "{printf "sha256:%s\n", $1}"')


def create_set_gcp_arguments(gcp_parser, conf):
    """Add set arguments to gcp_parser."""

    required_group = gcp_parser.add_argument_group(
        'set GCP controller required arguments')
    optional_group = gcp_parser.add_argument_group(
        'set GCP controller optional arguments')
    required_group.add_argument(
        '-n', required=True, dest='controllers_name',
        choices=get_controllers(conf, 'GCP'),
        help='The name of the cloud environment controller')
    optional_group.add_argument(
        '-proj', dest='controllers_project',
        help='the GCP project ID in which to scan for VM instances')
    optional_group.add_argument(
        '-cr', default='IAM', dest='controllers_credentials',
        type=validate_iam_or_filepath,
        help='either the path to a text file containing GCP credentials '
             'or "IAM" for automatic retrieval of the '
             'service account credentials from the VM instance metadata. '
             'Default: "IAM"')


def create_set_azure_arguments(azure_parser, conf):
    """Add set arguments to azure_parser."""

    required_group = azure_parser.add_argument_group(
        'set Azure controller required arguments')
    optional_group = azure_parser.add_argument_group(
        'set Azure controller optional arguments')
    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        choices=get_controllers(conf, 'Azure'),
        help='The name of the cloud environment controller')
    optional_group.add_argument(
        '-en',
        dest='controllers_environment', choices=AZURE_ENVIRONMENTS,
        help='an optional attribute to specify the Azure environment. '
             'The default is "AzureCloud", but one of the other environments '
             'like "AzureChinaCloud", "AzureGermanCloud" or '
             '"AzureUSGovernment" can be specified instead')
    optional_group.add_argument('-as',
                                dest='controllers_subscription',
                                type=validate_guid_uuid,
                                help='the Azure subscription ID')
    optional_group.add_argument('-at',
                                dest='controllers_credentials_tenant',
                                help='the Azure Active Directory tenant ID')
    optional_group.add_argument(
        '-aci', dest='controllers_credentials_client_id',
        help='the application ID with which the '
             'service principal is associated')
    optional_group.add_argument('-acs',
                                dest='controllers_credentials_client_secret',
                                help='the service principal password')
    optional_group.add_argument('-au',
                                dest='controllers_credentials_username',
                                help='the Azure fully qualified user name')
    optional_group.add_argument('-ap',
                                dest='controllers_credentials_password',
                                help='the password for the user')


def create_set_aws_arguments(aws_parser, conf):
    """Add set arguments to aws_parser."""
    required_group = aws_parser.add_argument_group(
        'set AWS controller required arguments')
    optional_group = aws_parser.add_argument_group(
        'set AWS controller optional arguments')

    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        choices=get_controllers(conf, 'AWS'),
        help='The name of the cloud environment controller')
    optional_group.add_argument(
        '-r', dest='controllers_regions',
        help='a comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: eu-west-1,us-east-1,eu-central-1')
    optional_group.add_argument('-ak',
                                dest='controllers_access-key',
                                help='AWS-ACCESS-KEY')
    optional_group.add_argument('-sk',
                                dest='controllers_secret-key',
                                help='AWS-SECRET-KEY')

    me_group = optional_group.add_mutually_exclusive_group(required=False)
    me_group.add_argument(
        '-cf', dest='controllers_cred-file',
        type=validate_iam_or_filepath,
        help='the path to a text file containing AWS credentials')

    me_group.add_argument(
        '-iam', dest='controllers_cred-file',
        action='store_const', const='IAM',
        help='use the IAM role profile')


def create_set_templates_arguments(set_template_subparser, conf):
    """Add to set_template_subparser its arguments."""

    set_template_subparser._optionals.title = 'Global Arguments'
    required_group = set_template_subparser.add_argument_group(
        'Set Template Required Arguments')
    optional_group = set_template_subparser.add_argument_group(
        'Set Template Optional Arguments')

    required_group.add_argument('-n', required=True,
                                dest='templates_name',
                                choices=get_templates(conf),
                                help='the name of the template')

    optional_group.add_argument(
        '-nn', dest='templates_new-name',
        help="the new name of the template. The name must be unique.")
    optional_group.add_argument(
        '-otp', type=validate_SIC,
        dest='templates_one-time-password',
        help='a random string consisting of at least %s '
             'alphanumeric characters' % repr(MIN_SIC_LENGTH))
    optional_group.add_argument(
        '-v', dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    optional_group.add_argument(
        '-po', dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways')
    optional_group.add_argument(
        '-cp', dest='templates_custom-parameters',
        help='an optional string with space separated parameters '
             'or a list of string parameters to specify '
             'when a gateway is added and a custom script is specified '
             'in the management section')
    optional_group.add_argument(
        '-pr', dest='templates_proto',
        help='a prototype for this template')
    optional_group.add_argument(
        '-sn', dest='templates_specific-network',
        help='an optional name of a pre-existing network object group '
             'that defines the topology settings for the interfaces '
             'marked with "specific" topology. '
             'This attribute is mandatory if any of the scanned instances '
             'has an interface with a topology set to "specific". '
             'Typically this should point to the name '
             'of a "Group with Exclusions" object, '
             'which contains a network group holding the VPC address range '
             'and excludes a network group which contains '
             'the "external" networks of the VPC, that is, '
             'networks that are connected to the internet')
    optional_group.add_argument(
        '-g', dest='templates_generation',
        help='an optional string or number that can be used to '
             'force re-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '-pp', nargs='+', dest='templates_proxy-ports',
        help='an optional comma-separated list of list of TCP ports '
             'on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '-hi', type=validate_bool,
        dest='templates_https-inspection',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTPS Inspection feature on the gateway')
    optional_group.add_argument(
        '-ia', type=validate_bool,
        dest='templates_identity-awareness',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '-appi', type=validate_bool,
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '-ips', type=validate_bool,
        dest='templates_ips',
        help='an optional boolean attribute indicating '
             'whether to enable the Intrusion Prevention System '
             'feature on the gateway')
    optional_group.add_argument(
        '-ipf', dest='templates_ips-profile',
        help='an optional IPS profile name to '
             'associate with a pre-R80 gateway')
    optional_group.add_argument(
        '-uf', type=validate_bool,
        dest='templates_url-filtering',
        help='an optional boolean attribute indicating '
             'whether to enable the URL Filtering Awareness '
             'feature on the gateway')
    optional_group.add_argument(
        '-ab', type=validate_bool,
        dest='templates_anti-bot',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Bot feature on the gateway')
    optional_group.add_argument(
        '-av', type=validate_bool,
        dest='templates_anti-virus',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Virus feature on the gateway')
    optional_group.add_argument(
        '-rp',
        dest='templates_restrictive-policy',
        help='an optional name of a pre-existing policy package to be '
             'installed as the first policy on a new provisioned gateway. '
             '(Created to avoid a limitation in which Access Policy and '
             'Threat Prevention Policy cannot be installed at the first '
             'time together). In the case where no attribute is provided, '
             'a default policy will be used (the default policy has only '
             'the implied rules and a drop-all cleanup rule). '
             'The value null can be used to explicitly avoid any such policy.')

    optional_group.add_argument(
        '-nk', nargs=2,
        dest='templates_new-key',
        help='optional attributes of a gateway. Usage -nk [KEY] [VALUE]')


def create_set_management_arguments(set_management_subparser):
    """Add to set_management_subparser its arguments."""

    set_management_subparser._optionals.title = 'Global Arguments'

    optional_group = set_management_subparser.add_argument_group(
        'Set Management Optional Arguments')
    optional_group.add_argument('-n', dest='management_name',
                                help='the name of the management server')

    optional_group.add_argument(
        '-ho', dest='management_host',
        help='"IP-ADDRESS-OR-HOST-NAME[:PORT]" - of the management server')
    optional_group.add_argument(
        '-d', dest='management_domain',
        help='the name or UID of the management domain if applicable')
    optional_group.add_argument(
        '-fp', dest='management_fingerprint',
        help='"sha256:FINGERPRINT-IN-HEX" - the SHA256 fingerprint '
             'of the management certificate. '
             'disable fingerprint checking by providing an empty string "" '
             '(insecure but reasonable if running locally '
             'on the management server). '
             'To retrieve the fingerprint, '
             'run the following command on the management server (in bash): '
             'cpopenssl s_client -connect 127.0.0.1:443 2>/dev/null '
             '</dev/null | cpopenssl x509 -outform DER '
             '| sha256sum | awk "{printf "sha256:%s\n", $1}"')

    optional_group.add_argument('-u', dest='management_user',
                                help='a SmartCenter administrator username')

    mu_group = optional_group.add_mutually_exclusive_group(required=False)
    mu_group.add_argument(
        '-pass', dest='management_password',
        help='the password associated with the user')
    mu_group.add_argument(
        '-pass64', dest='management_b64password',
        help='the base64 encoded password associated with the user')

    optional_group.add_argument(
        '-pr', dest='management_proxy',
        help='"http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT" '
             '- an optional value for the https_proxy environment variable')
    optional_group.add_argument(
        '-cs', dest='management_custom-script',
        help='"PATH-TO-CUSTOMIZATION-SCRIPT" - '
             'An optional script to run just after the policy is installed '
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
             'and later again with "add" and the custom parameters')


def create_add_gcp_arguments(gcp_parser):
    """Add create arguments to gcp_parser."""

    # Default arguments when adding GCP controllers
    defaults = {'controllers_class': 'GCP'}
    gcp_parser.set_defaults(**defaults)
    required_group = gcp_parser.add_argument_group(
        'add GCP controller required arguments')

    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        help='The name of the cloud environment controller. The name must be '
             'unique.')
    required_group.add_argument(
        '-proj', required=True, dest='controllers_project',
        help='the GCP project ID in which to scan for VM instances')
    required_group.add_argument(
        '-cr', required=True, default='IAM',
        dest='controllers_credentials',
        type=validate_iam_or_filepath,
        help='either the path to a text file containing GCP credentials '
             'or "IAM" for automatic retrieval of the service account '
             'credentials from the VM instance metadata. Default: "IAM"')


def create_add_azure_arguments(azure_parser):
    """Add create arguments to azure_parser."""

    # Default arguments when adding Azure controllers
    defaults = {'controllers_class': 'Azure'}
    azure_parser.set_defaults(**defaults)
    required_group = azure_parser.add_argument_group(
        'add Azure controller required arguments')
    optional_group = azure_parser.add_argument_group(
        'add Azure controller optional arguments')

    required_group.add_argument(
        '-n', required=True,
        dest='controllers_name',
        help='The name of the cloud environment controller. '
             'The name must be unique.')
    required_group.add_argument('-sb', required=True,
                                dest='controllers_subscription',
                                type=validate_guid_uuid,
                                help='the Azure subscription ID')
    optional_group.add_argument(
        '-en', default='AzureCloud',
        dest='controllers_environment', choices=AZURE_ENVIRONMENTS,
        help='an optional attribute to specify the Azure environment. '
             'The default is "AzureCloud", but one of the other environments '
             'like "AzureChinaCloud", "AzureGermanCloud" or '
             '"AzureUSGovernment" can be specified instead')

    # Handle credentials' additional nesting
    credentials_subparsers = azure_parser.add_subparsers(
        help='an object containing one of the following alternatives '
             '(in any case the entity for which the credentials are specified '
             '(a service principal or a user) must have "read" access '
             'to the relevant resources in the subscription)')
    service_principal_subparser = credentials_subparsers.add_parser(
        'sp', help='service principal credentials')
    service_principal_subparser._optionals.title = 'Required arguments'
    user_subparser = credentials_subparsers.add_parser(
        'user', help='user name and password')
    user_subparser._optionals.title = 'Required arguments'

    defaults = {'controllers_credentials_grant_type': "client_credentials"}
    service_principal_subparser.set_defaults(**defaults)
    service_principal_subparser.add_argument(
        '-at', required=True,
        dest='controllers_credentials_tenant',
        help='the Azure Active Directory tenant ID')
    service_principal_subparser.add_argument(
        '-aci', required=True,
        dest='controllers_credentials_client_id',
        help='the application ID with which the service principal is '
             'associated')
    service_principal_subparser.add_argument(
        '-acs', required=True,
        dest='controllers_credentials_client_secret',
        help='the service principal password')

    user_subparser.add_argument(
        '-au', required=True,
        dest='controllers_credentials_username',
        help='the Azure fully qualified user name')
    user_subparser.add_argument(
        '-ap', required=True,
        dest='controllers_credentials_password',
        help='the password for the user')


def create_add_aws_arguments(aws_parser):
    """Add create arguments to aws_parser."""

    # Default arguments when adding AWS controllers
    defaults = {'controllers_class': 'AWS'}
    aws_parser.set_defaults(**defaults)

    required_group = aws_parser.add_argument_group(
        'add AWS controller required arguments')

    required_group.add_argument(
        '-n', required=True, dest='controllers_name',
        help='The name of the cloud environment controller. '
             'The name must be unique.')
    required_group.add_argument(
        '-r', required=True, dest='controllers_regions',
        help='a comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: eu-west-1,us-east-1,eu-central-1')

    # Handle credentials' additional nesting
    credentials_subparsers = aws_parser.add_subparsers(
        help='use one of these alternatives to specify credentials')
    explicit_subparser = credentials_subparsers.add_parser('explicit')
    explicit_subparser._optionals.title = 'Required arguments'
    explicit_subparser.add_argument(
        '-ak', required=True, dest='controllers_access-key',
        help='AWS-ACCESS-KEY')
    explicit_subparser.add_argument(
        '-sk', required=True, dest='controllers_secret-key',
        help='AWS-SECRET-KEY')

    file_subparser = credentials_subparsers.add_parser('file')
    file_subparser.add_argument(
        dest='controllers_cred-file',
        type=validate_filepath,
        help='The path to a text file containing AWS credentials')

    role_subparser = credentials_subparsers.add_parser('IAM')
    defaults = {'controllers_cred-file': 'IAM'}
    role_subparser.set_defaults(**defaults)


def create_add_templates_arguments(add_template_subparser):
    """Add to add_template_subparser its arguments."""

    add_template_subparser._optionals.title = 'Global Arguments'
    required_group = add_template_subparser.add_argument_group(
        'Add Template Required Arguments')
    optional_group = add_template_subparser.add_argument_group(
        'Add Template Optional Arguments')

    required_group.add_argument(
        '-n', required=True, dest='templates_name',
        help="The name of the template. The name must be unique.")
    optional_group.add_argument(
        '-otp', type=validate_SIC,
        dest='templates_one-time-password',
        help='a random string consisting of at least %s '
             'alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    optional_group.add_argument(
        '-v',
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    optional_group.add_argument(
        '-po', dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways')

    optional_group.add_argument(
        '-cp', dest='templates_custom-parameters',
        help='an optional string with space separated parameters or '
             'a list of string parameters to specify when a gateway is added '
             'and a custom script is specified in the management section')
    optional_group.add_argument(
        '-pr', dest='templates_proto',
        help='a prototype for this template')
    optional_group.add_argument(
        '-sn', dest='templates_specific-network',
        help='an optional name of a pre-existing network object group '
             'that defines the topology settings for the interfaces marked '
             'with "specific" topology. This attribute is mandatory '
             'if any of the scanned instances has an interface '
             'with a topology set to "specific". '
             'Typically this should point to the name of a '
             '"Group with Exclusions" object, '
             'which contains a network group holding the VPC '
             'address range and excludes a network group which contains '
             'the "external" networks of the VPC, that is, '
             'networks that are connected to the internet')
    optional_group.add_argument(
        '-g', dest='templates_generation',
        help='an optional string or number that can be used to force '
             're-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '-pp', nargs='+', dest='templates_proxy-ports',
        help='an optional comma-separated list of list of TCP ports '
             'on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '-hi', type=validate_bool,
        dest='templates_https-inspection',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTPS Inspection feature on the gateway')
    optional_group.add_argument(
        '-ia', type=validate_bool,
        dest='templates_identity-awareness',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '-appi', type=validate_bool,
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '-ips', type=validate_bool,
        dest='templates_ips',
        help='an optional boolean attribute indicating '
             'whether to enable the Intrusion Prevention System '
             'feature on the gateway')
    optional_group.add_argument(
        '-ipf', dest='templates_ips-profile',
        help='an optional IPS profile name to associate '
             'with a pre-R80 gateway')
    optional_group.add_argument(
        '-uf', type=validate_bool,
        dest='templates_url-filtering',
        help='an optional boolean attribute indicating '
             'whether to enable the URL Filtering Awareness '
             'feature on the gateway')
    optional_group.add_argument(
        '-ab', type=validate_bool,
        dest='templates_anti-bot',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Bot feature on the gateway')
    optional_group.add_argument(
        '-av', type=validate_bool,
        dest='templates_anti-virus',
        help='an optional boolean attribute indicating '
             'whether to enable the Anti-Virus feature on the gateway')
    optional_group.add_argument(
        '-rp',
        dest='templates_restrictive-policy',
        help='an optional name of a pre-existing policy package to be '
             'installed as the first policy on a new provisioned gateway. '
             '(Created to avoid a limitation in which Access Policy and '
             'Threat Prevention Policy cannot be installed at the first '
             'time together). In the case where no attribute is provided, '
             'a default policy will be used (the default policy has only '
             'the implied rules and a drop-all cleanup rule). '
             'The value null can be used to explicitly avoid any such policy.')
    optional_group.add_argument(
        '-nk', nargs=2,
        dest='templates_new-key',
        help='optional attributes of a gateway. Usage -nk [KEY] [VALUE]')


def create_init_GCP_arguments(GCP_init_subparser):
    pass


def create_init_azure_arguments(azure_init_subparser):
    """Add to azure_init_subparser its arguments."""

    defaults = {'delay': 30,
                'controllers_class': 'Azure',
                'management_host': 'localhost'}

    azure_init_subparser.set_defaults(**defaults)

    required_init_group = azure_init_subparser.add_argument_group(
        'Required Arguments for Initialization')

    required_init_group.add_argument(
        '-mn', required=True, dest='management_name',
        help='The name of the management server.')

    required_init_group.add_argument(
        '-tn', required=True, dest='templates_name',
        help="The name of a gateway configuration template.")
    required_init_group.add_argument(
        '-otp', type=validate_SIC, required=True,
        dest='templates_one-time-password',
        help='a random string consisting of at least '
             '%s alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    required_init_group.add_argument(
        '-v', required=True,
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    required_init_group.add_argument(
        '-po', required=True, dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways.')
    required_init_group.add_argument(
        '-cn', required=True, dest='controllers_name',
        help='The name of the cloud environment controller.')
    required_init_group.add_argument(
        '-as', required=True,
        dest='controllers_subscription',
        type=validate_guid_uuid,
        help='the Azure subscription ID')
    # Handle credentials' additional nesting
    credentials_subparsers = azure_init_subparser.add_subparsers(
        help='an object containing one of the following alternatives '
             '(in any case the entity for which the credentials are specified '
             '(a service principal or a user) must have "read" access '
             'to the relevant resources in the subscription)')

    service_principal_subparser = credentials_subparsers.add_parser(
        'sp', help='service principal credentials')
    service_principal_subparser._optionals.title = 'Required arguments'
    defaults = {'controllers_credentials_grant_type': "client_credentials"}
    service_principal_subparser.set_defaults(**defaults)

    user_subparser = credentials_subparsers.add_parser(
        'user', help='user name and password')
    user_subparser._optionals.title = 'Required arguments'

    service_principal_subparser.add_argument(
        '-at', required=True,
        dest='controllers_credentials_tenant',
        help='the Azure Active Directory tenant ID')
    service_principal_subparser.add_argument(
        '-aci', required=True,
        dest='controllers_credentials_client_id',
        help='the application ID with which the service principal is '
             'associated')
    service_principal_subparser.add_argument(
        '-acs', required=True,
        dest='controllers_credentials_client_secret',
        help='the service principal password')

    user_subparser.add_argument(
        '-au', required=True,
        dest='controllers_credentials_username',
        help='the Azure fully qualified user name')
    user_subparser.add_argument(
        '-ap', required=True,
        dest='controllers_credentials_password',
        help='the password for the user')


def create_init_aws_arguments(aws_init_subparser):
    """Add to aws_init_subparser its arguments."""

    defaults = {'delay': 30,
                'controllers_class': 'AWS',
                'management_host': 'localhost'}
    aws_init_subparser.set_defaults(**defaults)
    required_init_group = aws_init_subparser.add_argument_group(
        'Required Arguments for Initialization')

    required_init_group.add_argument(
        '-mn', required=True, dest='management_name',
        help='The name of the management server.')

    required_init_group.add_argument(
        '-tn', required=True, dest='templates_name',
        help="The name of a gateway configuration template.")
    required_init_group.add_argument(
        '-otp', type=validate_SIC,
        required=True, dest='templates_one-time-password',
        help='A random string consisting of at least '
             '%s alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    required_init_group.add_argument(
        '-v', required=True,
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='The gateway version (e.g. R77.30)')
    required_init_group.add_argument(
        '-po', required=True, dest='templates_policy',
        help='The name of an existing security policy '
             'intended to be installed on the gateways.')
    required_init_group.add_argument(
        '-cn', required=True, dest='controllers_name',
        help='The name of the cloud environment controller.')
    required_init_group.add_argument(
        '-r',
        required=True, dest='controllers_regions',
        help='A comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: eu-west-1,us-east-1,eu-central-1')

    # Handle credentials' additional nesting
    credentials_subparsers = aws_init_subparser.add_subparsers(
        help='use one of these alternatives to specify credentials')
    explicit_subparser = credentials_subparsers.add_parser('explicit')
    explicit_subparser._optionals.title = 'Required arguments'
    explicit_subparser.add_argument(
        '-ak', required=True, dest='controllers_access-key',
        help='AWS-ACCESS-KEY')
    explicit_subparser.add_argument(
        '-sk', required=True, dest='controllers_secret-key',
        help='AWS-SECRET-KEY')

    file_subparser = credentials_subparsers.add_parser('file')
    file_subparser.add_argument(
        dest='controllers_cred-file',
        type=validate_filepath,
        help='The path to a text file containing AWS credentials')

    role_subparser = credentials_subparsers.add_parser('IAM')
    defaults = {'controllers_cred-file': 'IAM'}
    role_subparser.set_defaults(**defaults)


def build_parsers(main_parser, conf):
    """Create the parser.

    Creates the main subparsers (init, show, add, set, delete) and
    their subparsers (delay, management, templates, controllers)
    """

    main_parser.add_argument(
        '--force', '-f', action='store_true', help='skip prompts')

    main_subparsers = main_parser.add_subparsers(
        help='available actions', dest='mode')
    init_subparser = main_subparsers.add_parser(
        'init', help='initialize auto-provision settings')

    print_subparser = main_subparsers.add_parser(
        'show', help='show all or specific configuration settings',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['show']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    print_subparser.add_argument(
        'branch', choices=['all', 'management', 'templates', 'controllers'],
        help='the branch of the configuration to show')

    add_subparser = main_subparsers.add_parser(
        'add', help='add a template or a controller')
    set_subparser = main_subparsers.add_parser(
        'set',
        help='set configurations of a management, a template or a controller')
    del_subparser = main_subparsers.add_parser(
        'delete',
        help='delete configurations of a management, a template or a '
             'controller')

    # init parsers
    init_subparsers = init_subparser.add_subparsers()
    aws_init_subparser = init_subparsers.add_parser(
        'AWS',
        help='initiate autoprovision settings for AWS',
        epilog='Usage Examples: \n' + '\n'.join(USAGE_EXAMPLES['init_aws']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_init_aws_arguments(aws_init_subparser)
    azure_init_subparser = init_subparsers.add_parser(
        'Azure',
        help='initiate autoprovision settings for Azure',
        epilog='Usage Examples: \n' + '\n'.join(USAGE_EXAMPLES['init_azure']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_init_azure_arguments(azure_init_subparser)
    GCP_init_subparser = init_subparsers.add_parser(
        'GCP',
        help='support for GCP will be added in the future',
        epilog='Usage Examples: \n' + '\n'.join(USAGE_EXAMPLES['init_GCP']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_init_GCP_arguments(GCP_init_subparser)

    # add parsers
    add_subparsers = add_subparser.add_subparsers(dest='branch')
    add_template_subparser = add_subparsers.add_parser(
        'template',
        help="add a gateway configuration template. When a new gateway "
             "instance is detected, the template's name is used to "
             "determines the eventual gateway configuration.",
        epilog='Usage Examples: \n' + '\n'.join(
            USAGE_EXAMPLES['add_template']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_add_templates_arguments(add_template_subparser)

    add_controller_subparser = add_subparsers.add_parser(
        'controller',
        help='add a controller configuration. '
             'These settings will be used to connect to cloud environments '
             'such as AWS, Azure, GCP or OpenStack.')
    add_controller_subparser._optionals.title = 'Global Arguments'
    subparsers = add_controller_subparser.add_subparsers(
        help='available controller classes')

    common_parser = argparse.ArgumentParser(add_help=False)

    common_parser.add_argument(
        '-d', dest='controllers_domain', metavar='domain',
        help='the name or UID of the management domain '
             'if applicable. In MDS, instances that are discovered by this '
             'controller, will be defined in this domain. If not specified, '
             'the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified '
             'if the management server is not an MDS')
    common_parser.add_argument(
        '-t', nargs='+', dest='controllers_templates', metavar='templates',
        help='an optional list of of templates, '
             'which are allowed for instances that are discovered '
             'by this controller. If this attribute is missing '
             'or its value is an empty list, the meaning is that '
             'any template may be used by gateways that belong to '
             'this controller. This is useful in MDS environments, '
             'where controllers work with different domains '
             'and it is necessary to restrict a gateway to only use '
             'templates that were intended for its domain. '
             'e.g. TEMPLATE1-NAME TEMPLATE2-NAME')

    add_aws_parser = subparsers.add_parser(
        'AWS', help='AWS Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['add_controller_AWS']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_azure_parser = subparsers.add_parser(
        'Azure', help='Azure Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['add_controller_Azure']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_gcp_parser = subparsers.add_parser(
        'GCP', help='GCP Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['add_controller_GCP']),
        formatter_class=argparse.RawDescriptionHelpFormatter)

    create_add_aws_arguments(add_aws_parser)
    create_add_azure_arguments(add_azure_parser)
    create_add_gcp_arguments(add_gcp_parser)

    # set parsers
    set_subparsers = set_subparser.add_subparsers(dest='branch')
    delay_subparser = set_subparsers.add_parser(
        'delay', help='set delay',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_delay']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    delay_subparser.add_argument(
        'delay', type=int,
        help='time to wait in seconds after each poll cycle')
    set_management_subparser = set_subparsers.add_parser(
        'management', help='set management arguments',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_management']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_set_management_arguments(set_management_subparser)

    set_template_subparser = set_subparsers.add_parser(
        'template', help='set template arguments',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_template']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_set_templates_arguments(set_template_subparser, conf)

    set_controller_subparser = set_subparsers.add_parser(
        'controller', help='set controller arguments')
    set_controller_subparser._optionals.title = 'Global Arguments'
    subparsers = set_controller_subparser.add_subparsers(
        help='Available controller classes')
    common_parser = argparse.ArgumentParser(add_help=False)
    optional_group = common_parser.add_argument_group(
        'Set Controllers Optional Arguments')
    optional_group.add_argument(
        '-nn', dest='controllers_new-name', metavar='new name',
        help='The new name of the controller. The name must be unique.')
    optional_group.add_argument(
        '-d', dest='controllers_domain', metavar='domain',
        help='the name or UID of the management domain if '
             'applicable (optional). '
             'In MDS, instances that are discovered by this controller, '
             'will be defined in this domain. '
             'If not specified, the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified '
             'if the management server is not an MDS')
    optional_group.add_argument(
        '-t', nargs='+', dest='controllers_templates', metavar='templates',
        help='an optional list of of templates, '
             'which are allowed for instances that are discovered by this '
             'controller. If this attribute is missing or its value is an '
             'empty list, the meaning is that any template '
             'may be used by gateways that belong to this controller. '
             'This is useful in MDS environments, where controllers work '
             'with different domains and it is necessary to restrict a '
             'gateway to only use templates that were intended '
             'for its domain. e.g. "TEMPLATE1-NAME TEMPLATE2-NAME"')

    set_aws_parser = subparsers.add_parser(
        'AWS', help='AWS Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_controller_AWS']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    set_azure_parser = subparsers.add_parser(
        'Azure', help='Azure Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_controller_Azure']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    set_gcp_parser = subparsers.add_parser(
        'GCP', help='GCP Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['set_controller_GCP']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_set_aws_arguments(set_aws_parser, conf)
    create_set_azure_arguments(set_azure_parser, conf)
    create_set_gcp_arguments(set_gcp_parser, conf)

    # delete parsers
    del_subparsers = del_subparser.add_subparsers(
        help='removable objects', dest='branch')
    del_management_subparsers = del_subparsers.add_parser(
        'management', help='delete management arguments',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['delete_management']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_del_management_arguments(del_management_subparsers)
    del_template_subparser = del_subparsers.add_parser(
        'template', help='delete template arguments',
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['delete_template']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    create_del_templates_arguments(del_template_subparser, conf)
    del_controller_subparser = del_subparsers.add_parser(
        'controller', help='delete controller arguments')
    del_controller_subparser._optionals.title = 'Global Arguments'

    subparsers = del_controller_subparser.add_subparsers(
        help='Available controller classes')
    common_parser = argparse.ArgumentParser(add_help=False)

    # Name argument is not included in this level
    # Included in each the different methods for each class
    # to validate via argparse if the controller actually exit
    optional_group = common_parser.add_argument_group(
        'Delete Controllers Optional Arguments')

    optional_group.add_argument(
        '-d', dest='controllers_domain',
        action='store_true',
        help='the name or UID of the management domain if '
             'applicable (optional). '
             'In MDS, instances that are discovered by this controller, '
             'will be defined in this domain. '
             'If not specified, the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified if '
             'the management server is not an MDS')
    optional_group.add_argument(
        '-t', dest='controllers_templates', action='store_true',
        help='If this attribute is missing or its value '
             'is an empty list, the meaning is that any template '
             'may be used by gateways that belong to this controller. '
             'This is useful in MDS environments, where controllers work '
             'with different domains and it is necessary to restrict a gateway'
             'to only use templates that were intended for its domain. ')

    delete_aws_parser = subparsers.add_parser(
        'AWS', help='AWS Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['delete_controller_AWS']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    delete_azure_parser = subparsers.add_parser(
        'Azure', help='Azure Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['delete_controller_Azure']),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    delete_gcp_parser = subparsers.add_parser(
        'GCP', help='GCP Controller', parents=[common_parser],
        epilog='Usage Examples: \n' +
               '\n'.join(USAGE_EXAMPLES['delete_controller_GCP']),
        formatter_class=argparse.RawDescriptionHelpFormatter)

    create_del_aws_arguments(delete_aws_parser, conf)
    create_del_azure_arguments(delete_azure_parser, conf)
    create_del_gcp_arguments(delete_gcp_parser, conf)


def handle_auxiliary_arguments(args):
    if hasattr(args, 'templates_new-key'):
        input = getattr(args, 'templates_new-key')
        if input is not None:
            key = input[0]
            # add or set
            if len(input) > 1:
                value = input[1]
            # delete
            else:
                value = True
            setattr(args, 'templates_' + key, value)
    if not hasattr(args, 'templates_name'):
        args.templates_name = None
    if not hasattr(args, 'controllers_name'):
        args.controllers_name = None


def load_configuration():
    """Loads the configuration and the exiting templates and controllers."""

    try:
        with open(CONFPATH) as f:
            conf = json.load(f, object_pairs_hook=collections.OrderedDict)
    except:
        if prompt('Failed to read configuration file: %s. '
                  'Would you like to delete it?' % CONFPATH):
            os.remove(CONFPATH)
            sys.exit(2)
        else:
            raise Exception('Failed to read configuration file: %s' % CONFPATH)

    return conf


def main():
    main_parser = argparse.ArgumentParser()

    if os.path.exists(CONFPATH):
        conf = load_configuration()
    else:
        conf = collections.OrderedDict()

    build_parsers(main_parser, conf)
    parsed_arguments = main_parser.parse_args()
    handle_auxiliary_arguments(parsed_arguments)
    process_arguments(conf, parsed_arguments)


if __name__ == '__main__':
    main()
