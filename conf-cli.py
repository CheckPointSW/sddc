#!/usr/bin/env python

import argparse
import collections
import json
import os
import subprocess
import shutil
import sys
import traceback

AZURE_ENVIRONMENTS = ['AzureCloud',
                      'AzureChinaCloud',
                      'AzureGermanCloud',
                      'AzureUSGovernment']

AVAILABLE_VERSIONS = ['R77.30',
                      'R80.10']

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
                       'controllers_new-name']

MIN_SIC_LENGTH = 8

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


argparse.ArgumentParser._check_value = my_check_value


def nested_delete(dic, keys):
    """Deletes a value in a nested dictionary.

    According to the list of keys leading to the relevant key
    """

    for key in keys[:-1]:
        dic = dic.get(key, {})

    dic.pop(keys[-1], None)


def delete_arguments(conf, args):
    """Remove either a property or an entire object."""

    removed_inner_argument = False
    # Check if any inner arguments were specified and remove
    for arg in vars(args):
        if arg not in AUXILIARY_ARGUMENTS and getattr(args, arg):
            path = get_value_path(arg, args)
            if args.force or prompt(
                    'Are you sure you want to delete %s\'s %s?'
                    % (path[-2], path[-1])):
                nested_delete(conf, path)
                removed_inner_argument = True
            else:
                sys.exit(0)

    # Did not remove inner arguments, removing entire branch
    if not removed_inner_argument:
        # Get branch to delete (args.branch is either management, template
        # or controller).
        # Singular for usability, plural for JSON hierarchy path.
        if args.branch == 'template':
            branch = 'templates'
        elif args.branch == 'controller':
            branch = 'controllers'
        else:
            branch = args.branch
        path = get_value_path(branch, args)
        if args.force or prompt(
                'Are you sure you want to delete %s?' % path[-1]):
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

    IMPORTANT: path strings (destination of argparse arguments)
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
                    sys.stdout.write("No %s to display" % args.branch)
        else:
            sys.stdout.write(
                'Configuration file was not initiated, please use init')

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
        if not conf:
            sys.stdout.write(
                'Configuration file was not initiated, please use init')
            sys.exit(0)

    if args.mode == 'add':
        set_all_none_control_args(conf, args)

    if args.mode == 'set':
        handle_change_of_branch_name(conf, args)
        set_all_none_control_args(conf, args)

    if args.mode == 'delete':
        delete_arguments(conf, args)

    if conf:
        # create backup
        shutil.copyfile(CONFPATH, CONFPATH + '.bak')

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
        sys.stdout.write(question + ' ')
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


# Validation methods

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


def validate_bool(value):
    if value.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif value.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def validate_regions(value):
    regions = value.split(",")
    for region in regions:
        if region not in AWS_REGIONS:
            raise argparse.ArgumentTypeError(
                'invalid choice: "%s" (choose from %s)'
                % (region, AWS_REGIONS))
    return regions


def validate_iam_or_filepath(value):
    if value == 'IAM':
        return value
    if os.path.exists(value):
        return value

    raise argparse.ArgumentTypeError('File %s does not exist' % value)


# Argpars argument creation methods

def create_del_openstack_arguments(openstack_parser, conf):
    """Add delete arguments to openstack_parser."""

    required_group = openstack_parser.add_argument_group(
        'Delete OpenStack Required Arguments')
    optional_group = openstack_parser.add_argument_group(
        'Delete OpenStack Optional Arguments')
    required_group.add_argument(
        '--name', '-n', required=True, dest='controllers_name',
        choices=get_controllers(conf, 'OpenStack'),
        help='the name of the controller')

    optional_group.add_argument(
        '--scheme', '-sc', action='store_true', dest='controllers_scheme',
        help='"https" or "http"')
    optional_group.add_argument(
        '--host', '-ho', dest='controllers_host', action='store_true',
        help='the IP address and port of the keystone endpoint')
    optional_group.add_argument(
        '--fingerprint', '-fp', dest='controllers_fingerprint',
        action='store_true',
        help='"sha256:FINGERPRINT-IN-HEX" - the SHA256 fingerprint of the '
             'controller certificate. disable fingerprint checking by '
             'providing an empty string "" (insecure)')
    optional_group.add_argument(
        '--tenant', '-te', dest='controllers_tenant', action='store_true',
        help='the tenant UUID')
    optional_group.add_argument(
        '--user', '-u', dest='controllers_user', action='store_true',
        help='an OpenStack username')
    optional_group.add_argument(
        '--password', '-pass', dest='controllers_password',
        action='store_true',
        help='either the password associated with the user or the base64 '
             'encoded password (for additional obscurity)')


def create_del_gcp_arguments(gcp_parser, conf):
    """Add delete arguments to gcp_parser."""

    required_group = gcp_parser.add_argument_group(
        'Delete GCP Required Arguments')
    optional_group = gcp_parser.add_argument_group(
        'Delete GCP Optional Arguments')
    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                choices=get_controllers(conf, 'GCP'),
                                help='the name of the controller')
    optional_group.add_argument(
        '--project', '-proj', dest='controllers_project', action='store_true',
        help='the GCP project ID in which to scan for VM instances')
    optional_group.add_argument(
        '--credentials', '-cr', action='store_true',
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
    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                choices=get_controllers(conf, 'Azure'),
                                help='the name of the controller')
    optional_group.add_argument('--azure-subscription', '-as',
                                dest='controllers_subscription',
                                action='store_true',
                                help='the Azure subscription ID')
    optional_group.add_argument('--azure-tenant', '-at',
                                dest='controllers_credentials_tenant',
                                action='store_true',
                                help='the Azure Active Directory tenant ID')
    optional_group.add_argument(
        '--azure-client-id', '-aci', dest='controllers_credentials_client_id',
        action='store_true',
        help='the application ID with which the '
             'service principal is associated')
    optional_group.add_argument('--azure-client-secret', '-acs',
                                dest='controllers_credentials_client_secret',
                                action='store_true',
                                help='the service principal password')
    optional_group.add_argument('--azure-username', '-au',
                                dest='controllers_credentials_username',
                                action='store_true',
                                help='the Azure fully qualified user name')
    optional_group.add_argument('--azure-password', '-ap',
                                dest='controllers_credentials_password',
                                action='store_true',
                                help='the password for the user')


def create_del_aws_arguments(aws_parser, conf):
    """Add delete arguments to aws_parser."""

    required_group = aws_parser.add_argument_group(
        'Delete AWS Required Arguments')
    optional_group = aws_parser.add_argument_group(
        'Delete AWS Optional Arguments')

    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                choices=get_controllers(conf, 'AWS'),
                                help='the name of the controller')
    optional_group.add_argument('--access-key', '-ak',
                                dest='controllers_access-key',
                                action='store_true',
                                help='AWS-ACCESS-KEY')
    optional_group.add_argument('--secret-key', '-sk',
                                dest='controllers_secret-key',
                                action='store_true',
                                help='AWS-SECRET-KEY')
    optional_group.add_argument(
        '--cred-file', '-cf', dest='controllers_cred-file',
        action='store_true',
        help='Either the path to a text file containing AWS credentials '
             'or an IAM role profile. Default: "IAM"')


def create_del_controllers_arguments(del_controller_subparser, conf):
    """Add to del_controller_subparser its arguments."""

    del_controller_subparser._optionals.title = 'Global Arguments'

    subparsers = del_controller_subparser.add_subparsers(
        help='Available controller classes')
    common_parser = argparse.ArgumentParser(add_help=False)

    # Name argument is not included in this level
    # Included in each the different methods for each class
    # so it will be possible to check if the controller actually exit
    optional_group = common_parser.add_argument_group(
        'Delete Controllers Optional Arguments')

    optional_group.add_argument(
        '--domain', '-d', dest='controllers_domain', action='store_true',
        help='the name or UID of the management domain if '
             'applicable (optional). '
             'In MDS, instances that are discovered by this controller, '
             'will be defined in this domain. '
             'If not specified, the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified if '
             'the management server is not an MDS')
    optional_group.add_argument(
        '--templates', '-t', dest='controllers_templates', action='store_true',
        help='an optional comma-separated list of of templates, '
             'which are allowed for instances that are discovered by '
             'this controller. If this attribute is missing or its value '
             'is an empty list, the meaning is that any template '
             'may be used by gateways that belong to this controller. '
             'This is useful in MDS environments, where controllers work '
             'with different domains and it is necessary to restrict a gateway'
             'to only use templates that were intended for its domain. '
             'e.g. "TEMPLATE1-NAME, TEMPLATE2-NAME"')

    aws_parser = subparsers.add_parser(
        'AWS', help='AWS Controller', parents=[common_parser])
    azure_parser = subparsers.add_parser(
        'Azure', help='Azure Controller', parents=[common_parser])
    gcp_parser = subparsers.add_parser(
        'GCP', help='GCP Controller', parents=[common_parser])
    openstack_parser = subparsers.add_parser(
        'OpenStack', help='OpenStack Controller', parents=[common_parser])

    create_del_aws_arguments(aws_parser, conf)
    create_del_azure_arguments(azure_parser, conf)
    create_del_gcp_arguments(gcp_parser, conf)
    create_del_openstack_arguments(openstack_parser, conf)


def create_del_templates_arguments(del_template_subparser, conf):
    """Add to del_template_subparser its arguments."""

    del_template_subparser._optionals.title = 'Global Arguments'
    required_group = del_template_subparser.add_argument_group(
        'Delete Template Required Arguments')
    optional_group = del_template_subparser.add_argument_group(
        'Delete Template Optional Arguments')

    required_group.add_argument(
        '--name', '-n', required=True, dest='templates_name',
        choices=get_templates(conf),
        help='the name of the template')

    optional_group.add_argument(
        '--custom-parameters', '-cp', dest='templates_custom-parameters',
        action='store_true',
        help='an optional string with space separated parameters or '
             'a list of string parameters to specify when a gateway is added '
             'and a custom script is specified in the management section')
    optional_group.add_argument(
        '--proto', '-pr', dest='templates_proto', action='store_true',
        help='a prototype for this template')
    optional_group.add_argument(
        '--specific-network', '-sn', dest='templates_specific-network',
        action='store_true',
        help='an optional name of a pre-existing network object group '
             'that defines the topology settings for the interfaces marked '
             'with "specific" topology. This attribute is mandatory '
             'if any of the scanned instances has an interface '
             'with a topology set to "specific". '
             'Typically this should point to the name of a '
             '"Group with Exclusions" object, '
             'which contains a network group holding the VPC address range '
             'and excludes a network group which contains the "external" '
             'networks of the VPC, that is, '
             'networks that are connected to the internet')
    optional_group.add_argument(
        '--generation', '-g', dest='templates_generation', action='store_true',
        help='an optional string or number that can be used to force '
             're-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '--proxy-ports', '-pp', dest='templates_proxy-ports',
        action='store_true',
        help='an optional comma-separated list of list '
             'of TCP ports on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '--https-inspection', '-hi', dest='templates_https-inspection',
        action='store_true',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTP Inspection feature on the gateway')
    optional_group.add_argument(
        '--identity-awareness', '-ia', dest='templates_identity-awareness',
        action='store_true',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '--application-control', '-appi', action='store_true',
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '--ips', '-ips', dest='templates_ips',
        action='store_true',
        help='an optional boolean attribute indicating '
             'whether to enable the IPS feature on the gateway')
    optional_group.add_argument(
        '--ips-profile', '-ipf', dest='templates_ips-profile',
        action='store_true',
        help='an optional IPS profile name to '
             'associate with a pre-R80 gateway')
    optional_group.add_argument(
        '--url-filtering', '-uf', dest='templates_url-filtering',
        action='store_true',
        help='an optional boolean attribute indicating whether '
             'to enable the URL Filtering Awareness feature on the gateway')


def create_del_management_arguments(del_management_subparsers):
    """Add to del_management_subparsers its arguments."""

    del_management_subparsers._optionals.title = 'Global Arguments'

    optional_group = del_management_subparsers.add_argument_group(
        'Delete Management Optional Arguments')
    optional_group.add_argument(
        '--domain', '-d', dest='management_domain', action='store_true',
        help='the name or UID of the management domain if applicable')
    optional_group.add_argument(
        '--user', '-u', dest='management_user', action='store_true',
        help='a SmartCenter administrator username')
    optional_group.add_argument(
        '--password', '-pass', dest='management_password', action='store_true',
        help='either the password associated with the user '
             'or the base64 encoded password (for additional obscurity)')
    optional_group.add_argument(
        '--proxy', '-pr', dest='management_proxy', action='store_true',
        help='"http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT" '
             '- an optional value for the https_proxy environment variable')
    optional_group.add_argument(
        '--custom-script', '-cs', dest='management_custom-script',
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


def create_set_openstack_arguments(openstack_parser, conf):
    """Add set arguments to openstack_parser."""

    required_group = openstack_parser.add_argument_group(
        'Set OpenStack Required Arguments')
    optional_group = openstack_parser.add_argument_group(
        'Set OpenStack Optional Arguments')
    required_group.add_argument(
        '--name', '-n', required=True, dest='controllers_name',
        choices=get_controllers(conf, 'OpenStack'),
        help='the name of the controller')

    optional_group.add_argument(
        '--scheme', '-sc', choices=['http', 'https'],
        dest='controllers_scheme', help='"https" or "http"')
    optional_group.add_argument(
        '--host', '-ho', dest='controllers_host',
        help='the IP address and port of the keystone endpoint')
    optional_group.add_argument(
        '--fingerprint', '-fp', dest='controllers_fingerprint',
        help='"sha256:FINGERPRINT-IN-HEX" - the SHA256 fingerprint of the '
             'controller certificate. disable fingerprint checking by '
             'providing an empty string "" (insecure)')
    optional_group.add_argument(
        '--tenant', '-te', dest='controllers_tenant', help='the tenant UUID')
    optional_group.add_argument(
        '--user', '-u', dest='controllers_user', help='an OpenStack username')
    optional_group.add_argument(
        '--password', '-pass', dest='controllers_password',
        help='either the password associated with the user or the base64 '
             'encoded password (for additional obscurity)')


def create_set_gcp_arguments(gcp_parser, conf):
    """Add set arguments to gcp_parser."""

    required_group = gcp_parser.add_argument_group(
        'Set GCP Required Arguments')
    optional_group = gcp_parser.add_argument_group(
        'Set GCP Optional Arguments')
    required_group.add_argument(
        '--name', '-n', required=True, dest='controllers_name',
        choices=get_controllers(conf, 'GCP'),
        help='the name of the controller')
    optional_group.add_argument(
        '--project', '-proj', dest='controllers_project',
        help='the GCP project ID in which to scan for VM instances')
    optional_group.add_argument(
        '--credentials', '-cr', default='IAM', dest='controllers_credentials',
        type=validate_iam_or_filepath,
        help='either the path to a text file containing GCP credentials '
             'or "IAM" for automatic retrieval of the '
             'service account credentials from the VM instance metadata. '
             'Default: "IAM"')


def create_set_azure_arguments(azure_parser, conf):
    """Add set arguments to azure_parser."""

    required_group = azure_parser.add_argument_group(
        'Set Azure Required Arguments')
    optional_group = azure_parser.add_argument_group(
        'Set Azure Optional Arguments')
    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                choices=get_controllers(conf, 'Azure'),
                                help='the name of the controller')
    optional_group.add_argument('--azure-subscription', '-as',
                                dest='controllers_subscription',
                                help='the Azure subscription ID')
    optional_group.add_argument('--azure-tenant', '-at',
                                dest='controllers_credentials_tenant',
                                help='the Azure Active Directory tenant ID')
    optional_group.add_argument(
        '--azure-client-id', '-aci', dest='controllers_credentials_client_id',
        help='the application ID with which the '
             'service principal is associated')
    optional_group.add_argument('--azure-client-secret', '-acs',
                                dest='controllers_credentials_client_secret',
                                help='the service principal password')
    optional_group.add_argument('--azure-username', '-au',
                                dest='controllers_credentials_username',
                                help='the Azure fully qualified user name')
    optional_group.add_argument('--azure-password', '-ap',
                                dest='controllers_credentials_password',
                                help='the password for the user')


def create_set_aws_arguments(aws_parser, conf):
    """Add set arguments to aws_parser."""
    required_group = aws_parser.add_argument_group(
        'Set AWS Required Arguments')
    optional_group = aws_parser.add_argument_group(
        'Set AWS Optional Arguments')

    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                choices=get_controllers(conf, 'AWS'),
                                help='the name of the controller')
    optional_group.add_argument(
        '--regions', '-r', dest='controllers_regions',
        type=validate_regions,
        help='a comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: us-east-1,eu-central-1,ap-southeast-1')
    optional_group.add_argument('--access-key', '-ak',
                                dest='controllers_access-key',
                                help='AWS-ACCESS-KEY')
    optional_group.add_argument('--secret-key', '-sk',
                                dest='controllers_secret-key',
                                help='AWS-SECRET-KEY')
    optional_group.add_argument(
        '--cred-file', '-cf', default='IAM', dest='controllers_cred-file',
        type=validate_iam_or_filepath,
        help='Either the path to a text file containing '
             'AWS credentials or an IAM role profile. Default: "IAM"')


def create_set_controllers_arguments(set_controller_subparser, conf):
    """Add to set_controller_subparser its arguments."""

    set_controller_subparser._optionals.title = 'Global Arguments'

    subparsers = set_controller_subparser.add_subparsers(
        help='Available controller classes')
    common_parser = argparse.ArgumentParser(add_help=False)

    optional_group = common_parser.add_argument_group(
        'Set Controllers Optional Arguments')

    optional_group.add_argument(
        '--new-name', '-nn', dest='controllers_new-name',
        help='The new name of the template')
    optional_group.add_argument(
        '--domain', '-d', dest='controllers_domain',
        help='the name or UID of the management domain if '
             'applicable (optional). '
             'In MDS, instances that are discovered by this controller, '
             'will be defined in this domain. '
             'If not specified, the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified '
             'if the management server is not an MDS')
    optional_group.add_argument(
        '--templates', '-t', nargs='+', dest='controllers_templates',
        help='an optional comma-separated list of of templates, '
             'which are allowed for instances that are discovered by this '
             'controller. If this attribute is missing or its value is an '
             'empty list, the meaning is that any template '
             'may be used by gateways that belong to this controller. '
             'This is useful in MDS environments, where controllers work '
             'with different domains and it is necessary to restrict a '
             'gateway to only use templates that were intended '
             'for its domain. e.g. "TEMPLATE1-NAME, TEMPLATE2-NAME"')

    aws_parser = subparsers.add_parser(
        'AWS', help='AWS Controller', parents=[common_parser])
    azure_parser = subparsers.add_parser(
        'Azure', help='Azure Controller', parents=[common_parser])
    gcp_parser = subparsers.add_parser(
        'GCP', help='GCP Controller', parents=[common_parser])
    openstack_parser = subparsers.add_parser(
        'OpenStack', help='OpenStack Controller', parents=[common_parser])

    create_set_aws_arguments(aws_parser, conf)
    create_set_azure_arguments(azure_parser, conf)
    create_set_gcp_arguments(gcp_parser, conf)
    create_set_openstack_arguments(openstack_parser, conf)


def create_set_templates_arguments(set_template_subparser, conf):
    """Add to set_template_subparser its arguments."""

    set_template_subparser._optionals.title = 'Global Arguments'
    required_group = set_template_subparser.add_argument_group(
        'Set Template Required Arguments')
    optional_group = set_template_subparser.add_argument_group(
        'Set Template Optional Arguments')

    required_group.add_argument('--name', '-n', required=True,
                                dest='templates_name',
                                choices=get_templates(conf),
                                help='the name of the template')

    optional_group.add_argument('--new-name', '-nn', dest='templates_new-name',
                                help='the new name of the template')
    optional_group.add_argument(
        '--one-time-password', '-otp', type=validate_SIC,
        dest='templates_one-time-password',
        help='a random string consisting of at least %s '
             'alphanumeric characters' % repr(MIN_SIC_LENGTH))
    optional_group.add_argument(
        '--version', '-v',
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    optional_group.add_argument(
        '--policy', '-po', dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways')
    optional_group.add_argument(
        '--custom-parameters', '-cp', dest='templates_custom-parameters',
        help='an optional string with space separated parameters '
             'or a list of string parameters to specify '
             'when a gateway is added and a custom script is specified '
             'in the management section')
    optional_group.add_argument(
        '--proto', '-pr', dest='templates_proto',
        help='a prototype for this template')
    optional_group.add_argument(
        '--specific-network', '-sn', dest='templates_specific-network',
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
        '--generation', '-g', dest='templates_generation',
        help='an optional string or number that can be used to '
             'force re-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '--proxy-ports', '-pp', nargs='+', dest='templates_proxy-ports',
        help='an optional comma-separated list of list of TCP ports '
             'on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '--https-inspection', '-hi', type=validate_bool,
        dest='templates_https-inspection',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTP Inspection feature on the gateway')
    optional_group.add_argument(
        '--identity-awareness', '-ia', type=validate_bool,
        dest='templates_identity-awareness',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '--application-control', '-appi', type=validate_bool,
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '--ips', '-ips', type=validate_bool,
        dest='templates_ips',
        help='enable/Disable the IPS feature on the gateway')
    optional_group.add_argument(
        '--ips-profile', '-ipf', dest='templates_ips-profile',
        help='an optional IPS profile name to '
             'associate with a pre-R80 gateway')
    optional_group.add_argument(
        '--url-filtering', '-uf', type=validate_bool,
        dest='templates_url-filtering',
        help='an optional boolean attribute indicating '
             'whether to enable the URL Filtering Awareness '
             'feature on the gateway')


def create_set_management_arguments(set_management_subparser):
    """Add to set_management_subparser its arguments."""

    set_management_subparser._optionals.title = 'Global Arguments'

    optional_group = set_management_subparser.add_argument_group(
        'Set Management Optional Arguments')
    optional_group.add_argument('--name', '-n', dest='management_name',
                                help='the name of the management server')

    optional_group.add_argument(
        '--host', '-ho', dest='management_host',
        help='"IP-ADDRESS-OR-HOST-NAME[:PORT]" - of the management server')
    optional_group.add_argument(
        '--domain', '-d', dest='management_domain',
        help='the name or UID of the management domain if applicable')
    optional_group.add_argument(
        '--fingerprint', '-f', dest='management_fingerprint',
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

    optional_group.add_argument('--user', '-u', dest='management_user',
                                help='a SmartCenter administrator username')
    optional_group.add_argument(
        '--password', '-pass', dest='management_password',
        help='either the password associated with the user or '
             'the base64 encoded password (for additional obscurity)')
    optional_group.add_argument(
        '--proxy', '-pr', dest='management_proxy',
        help='"http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT" '
             '- an optional value for the https_proxy environment variable')
    optional_group.add_argument(
        '--custom-script', '-cs', dest='management_custom-script',
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


def create_add_openstack_arguments(openstack_parser):
    """Add create arguments to openstack_parser."""

    defaults = {'controllers_class': 'OpenStack'}
    openstack_parser.set_defaults(**defaults)

    required_group = openstack_parser.add_argument_group(
        'Add OpenStack Required Arguments')

    required_group.add_argument('--name', '-n', dest='controllers_name',
                                help='the name of the controller')

    required_group.add_argument('--scheme', '-sc', required=True,
                                choices=['http', 'https'],
                                dest='controllers_scheme',
                                help='"https" or "http"')
    required_group.add_argument(
        '--host', '-ho', required=True, dest='controllers_host',
        help='the IP address and port of the keystone endpoint')
    required_group.add_argument(
        '--fingerprint', '-fp', required=True, dest='controllers_fingerprint',
        help='"sha256:FINGERPRINT-IN-HEX" - the SHA256 fingerprint '
             'of the controller certificate. '
             'disable fingerprint checking by providing '
             'an empty string "" (insecure)')
    required_group.add_argument('--tenant', '-te', required=True,
                                dest='controllers_tenant',
                                help='the tenant UUID')
    required_group.add_argument('--user', '-u', required=True,
                                dest='controllers_user',
                                help='an OpenStack username')
    required_group.add_argument(
        '--password', '-pass', required=True, dest='controllers_password',
        help='either the password associated with the user '
             'or the base64 encoded password (for additional obscurity)')


def create_add_gcp_arguments(gcp_parser):
    """Add create arguments to gcp_parser."""

    # Default arguments when adding GCP controllers
    defaults = {'controllers_class': 'GCP'}
    gcp_parser.set_defaults(**defaults)
    required_group = gcp_parser.add_argument_group(
        'Add GCP Required Arguments')

    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                help='the name of the controller')
    required_group.add_argument(
        '--project', '-proj', required=True, dest='controllers_project',
        help='the GCP project ID in which to scan for VM instances')
    required_group.add_argument(
        '--credentials', '-cr', required=True, default='IAM',
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
        'Add Azure Required Arguments')
    optional_group = azure_parser.add_argument_group(
        'Add Azure Optional Arguments')

    required_group.add_argument('--name', '-n', required=True,
                                dest='controllers_name',
                                help='the name of the controller')
    required_group.add_argument('--subscription', '-sb', required=True,
                                dest='controllers_subscription',
                                help='the Azure subscription ID')
    optional_group.add_argument(
        '--environment', '-en', default='AzureCloud',
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
        '--azure-tenant', '-at', required=True,
        dest='controllers_credentials_tenant',
        help='the Azure Active Directory tenant ID')
    service_principal_subparser.add_argument(
        '--azure-client-id', '-aci', required=True,
        dest='controllers_credentials_client_id',
        help='the application ID with which the service principal is '
             'associated')
    service_principal_subparser.add_argument(
        '--azure-client-secret', '-acs', required=True,
        dest='controllers_credentials_client_secret',
        help='the service principal password')

    user_subparser.add_argument(
        '--azure-username', '-au', dest='controllers_credentials_username',
        help='the Azure fully qualified user name')
    user_subparser.add_argument(
        '--azure-password', '-ap', dest='controllers_credentials_password',
        help='the password for the user')


def create_add_aws_arguments(aws_parser):
    """Add create arguments to aws_parser."""

    # Default arguments when adding AWS controllers
    defaults = {'controllers_class': 'AWS'}
    aws_parser.set_defaults(**defaults)

    required_group = aws_parser.add_argument_group(
        'Add AWS Required Arguments')

    required_group.add_argument(
        '--name', '-n', required=True, dest='controllers_name',
        help='the name of the controller')
    required_group.add_argument(
        '--regions', '-r', required=True, dest='controllers_regions',
        type=validate_regions,
        help='a comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: us-east-1,eu-central-1,ap-southeast-1')

    credentials_subparsers = aws_parser.add_subparsers(
        help='use one of these alternatives to specify credentials')
    explicit_subparser = credentials_subparsers.add_parser('explicit')
    explicit_subparser._optionals.title = 'Required arguments'
    explicit_subparser.add_argument('--access-key', '-ak', required=True,
                                    dest='controllers_access-key',
                                    help='AWS-ACCESS-KEY')
    explicit_subparser.add_argument('--secret-key', '-sk', required=True,
                                    dest='controllers_secret-key',
                                    help='AWS-SECRET-KEY')

    file_subparser = credentials_subparsers.add_parser('file')
    file_subparser.add_argument(
        '--cred-file', '-cf', default='IAM',
        dest='controllers_cred-file',
        type=validate_iam_or_filepath,
        help='Either the path to a text file containing AWS credentials '
             'or an IAM role profile. Default: "IAM"')


def create_add_controllers_arguments(add_controller_subparser):
    """Add to add_controller_subparser its arguments."""

    add_controller_subparser._optionals.title = 'Global Arguments'

    subparsers = add_controller_subparser.add_subparsers(
        help='Available controller classes')
    common_parser = argparse.ArgumentParser(add_help=False)

    optional_group = common_parser.add_argument_group(
        'Add Controllers Optional Arguments')

    optional_group.add_argument(
        '--domain', '-d', dest='controllers_domain',
        help='the name or UID of the management domain '
             'if applicable (optional). '
             'In MDS, instances that are discovered by this controller, '
             'will be defined in this domain. If not specified, '
             'the domain specified in the management object '
             '(in the configuration), will be used. '
             'This attribute should not be specified '
             'if the management server is not an MDS')
    optional_group.add_argument(
        '--templates', '-t', nargs='+', dest='controllers_templates',
        help='an optional comma-separated list of of templates, '
             'which are allowed for instances that are discovered '
             'by this controller. If this attribute is missing '
             'or its value is an empty list, the meaning is that '
             'any template may be used by gateways that belong to '
             'this controller. This is useful in MDS environments, '
             'where controllers work with different domains '
             'and it is necessary to restrict a gateway to only use '
             'templates that were intended for its domain. '
             'e.g. "TEMPLATE1-NAME, TEMPLATE2-NAME"')

    aws_parser = subparsers.add_parser('AWS', help='AWS Controller',
                                       parents=[common_parser])
    azure_parser = subparsers.add_parser('Azure', help='Azure Controller',
                                         parents=[common_parser])
    gcp_parser = subparsers.add_parser('GCP', help='GCP Controller',
                                       parents=[common_parser])
    openstack_parser = subparsers.add_parser('OpenStack',
                                             help='OpenStack Controller',
                                             parents=[common_parser])

    create_add_aws_arguments(aws_parser)
    create_add_azure_arguments(azure_parser)
    create_add_gcp_arguments(gcp_parser)
    create_add_openstack_arguments(openstack_parser)


def create_add_templates_arguments(add_template_subparser):
    """Add to add_template_subparser its arguments."""

    add_template_subparser._optionals.title = 'Global Arguments'
    required_group = add_template_subparser.add_argument_group(
        'Add Template Required Arguments')
    optional_group = add_template_subparser.add_argument_group(
        'Add Template Optional Arguments')

    required_group.add_argument(
        '--name', '-n', required=True, dest='templates_name',
        help='The name of the template.')
    required_group.add_argument(
        '--one_time_password', '-otp', type=validate_SIC, required=True,
        dest='templates_one-time-password',
        help='a random string consisting of at least %s '
             'alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    required_group.add_argument(
        '--version', '-v', required=True,
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    required_group.add_argument(
        '--policy', '-po', required=True, dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways')

    optional_group.add_argument(
        '--custom-parameters', '-cp', dest='templates_custom-parameters',
        help='an optional string with space separated parameters or '
             'a list of string parameters to specify when a gateway is added '
             'and a custom script is specified in the management section')
    optional_group.add_argument('--proto', '-pr', dest='templates_proto',
                                help='a prototype for this template')
    optional_group.add_argument(
        '--specific-network', '-sn', dest='templates_specific-network',
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
        '--generation', '-g', dest='templates_generation',
        help='an optional string or number that can be used to force '
             're-applying a template to an already existing gateway. '
             'If generation is specified and its value is different '
             'than the previous value, then the template settings '
             'will be reapplied to the gateway')
    optional_group.add_argument(
        '--proxy-ports', '-pp', nargs='+', dest='templates_proxy-ports',
        help='an optional comma-separated list of list of TCP ports '
             'on which to enable the proxy on gateway feature. '
             'e.g. "8080, 8443"')
    optional_group.add_argument(
        '--https-inspection', '-hi', type=validate_bool,
        dest='templates_https-inspection',
        help='an optional boolean attribute indicating '
             'whether to enable the HTTP Inspection feature on the gateway')
    optional_group.add_argument(
        '--identity-awareness', '-ia', type=validate_bool,
        dest='templates_identity-awareness',
        help='an optional boolean attribute indicating '
             'whether to enable the Identity Awareness feature on the gateway')
    optional_group.add_argument(
        '--application-control', '-appi', type=validate_bool,
        dest='templates_application-control',
        help='enable/Disable the Application Control blade')
    optional_group.add_argument(
        '--ips', '-ips', type=validate_bool,
        dest='templates_application-control',
        help='an optional IPS profile name to '
             'associate with a pre-R80 gateway')
    optional_group.add_argument(
        '--ips-profile', '-ipf', dest='templates_ips-profile',
        help='an optional IPS profile name to associate '
             'with a pre-R80 gateway')
    optional_group.add_argument(
        '--url-filtering', '-uf', type=validate_bool,
        dest='templates_url-filtering',
        help='an optional boolean attribute indicating '
             'whether to enable the URL Filtering Awareness '
             'feature on the gateway')


def create_init_azure_arguments(azure_init_subparser):
    """Add to azure_init_subparser its arguments."""

    defaults = {'delay': 30, 'controllers_class': 'Azure'}
    azure_init_subparser.set_defaults(**defaults)

    required_init_group = azure_init_subparser.add_argument_group(
        'Required Arguments for Initialization')
    optional_init_group = azure_init_subparser.add_argument_group(
        'Optional Arguments for Initialization')

    required_init_group.add_argument(
        '--management-name', '-mn', required=True, dest='management_name',
        help='The name of the management server.')

    required_init_group.add_argument(
        '--template-name', '-tn', required=True, dest='templates_name',
        help='The name of the template.')
    required_init_group.add_argument(
        '--template-one-time-password', '-otp',
        type=validate_SIC, required=True,
        dest='templates_one-time-password',
        help='a random string consisting of at least '
             '%s alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    required_init_group.add_argument(
        '--version', '-v', required=True,
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='the gateway version (e.g. R77.30)')
    required_init_group.add_argument(
        '--policy', '-po', required=True, dest='templates_policy',
        help='the name of an existing security policy '
             'intended to be installed on the gateways.')
    required_init_group.add_argument(
        '--controller-name', '-cn', required=True, dest='controllers_name',
        help='the name of the controller.')
    required_init_group.add_argument(
        '--azure-subscription', '-as', required=True,
        dest='controllers_subscription', help='the Azure subscription ID')
    optional_init_group.add_argument(
        '--management-host', '-mh', dest='management_host',
        default='localhost', help='AWS access key')

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
        '--azure-tenant', '-at', required=True,
        dest='controllers_credentials_tenant',
        help='the Azure Active Directory tenant ID')
    service_principal_subparser.add_argument(
        '--azure-client-id', '-aci', required=True,
        dest='controllers_credentials_client_id',
        help='the application ID with which the service principal is '
             'associated')
    service_principal_subparser.add_argument(
        '--azure-client-secret', '-acs', required=True,
        dest='controllers_credentials_client_secret',
        help='the service principal password')

    user_subparser.add_argument(
        '--azure-username', '-au', required=True,
        dest='controllers_credentials_username',
        help='the Azure fully qualified user name')
    user_subparser.add_argument(
        '--azure-password', '-ap', required=True,
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
        '--management-name', '-mn', required=True, dest='management_name',
        help='The name of the management server.')

    required_init_group.add_argument(
        '--template-name', '-tn', required=True, dest='templates_name',
        help='The name of the template.')
    required_init_group.add_argument(
        '--template-one-time-password', '-otp', type=validate_SIC,
        required=True, dest='templates_one-time-password',
        help='A random string consisting of at least '
             '%s alphanumeric characters.' % repr(MIN_SIC_LENGTH))
    required_init_group.add_argument(
        '--version', '-v', required=True,
        dest='templates_version', choices=AVAILABLE_VERSIONS,
        help='The gateway version (e.g. R77.30)')
    required_init_group.add_argument(
        '--policy', '-po', required=True, dest='templates_policy',
        help='The name of an existing security policy '
             'intended to be installed on the gateways.')
    required_init_group.add_argument(
        '--controller-name', '-cn', required=True, dest='controllers_name',
        help='The name of the controller.')
    required_init_group.add_argument(
        '--regions', '-r', type=validate_regions,
        required=True, dest='controllers_regions',
        help='A comma-separated list of AWS regions, '
             'in which the gateways are being deployed. '
             'For example: us-east-1,eu-central-1,ap-southeast-1')

    # Handle credentials' additional nesting
    credentials_subparsers = aws_init_subparser.add_subparsers(
        help='use one of these alternatives to specify credentials')
    explicit_subparser = credentials_subparsers.add_parser('explicit')
    explicit_subparser._optionals.title = 'Required arguments'
    explicit_subparser.add_argument(
        '--access-key', '-ak', required=True, dest='controllers_access-key',
        help='AWS-ACCESS-KEY')
    explicit_subparser.add_argument(
        '--secret-key', '-sk', required=True, dest='controllers_secret-key',
        help='AWS-SECRET-KEY')

    file_subparser = credentials_subparsers.add_parser('file')
    file_subparser.add_argument(
        '--cred_file', '-cf', default='IAM', dest='controllers_cred-file',
        type=validate_iam_or_filepath,
        help='Either the path to a text file containing AWS credentials '
             'or an IAM role profile. Default: "IAM"')


def build_parsers(main_parser, conf):
    """Create the parser.

    Creates the main subparsers (init, show, add, set, delete) and
    their subparsers (delay, management, templates, controllers, etc.)
    """

    main_parser.add_argument(
        '--force', '-f', action='store_true', help='skip prompts')

    main_subprsers = main_parser.add_subparsers(
        help='available actions', dest='mode')

    init_subparser = main_subprsers.add_parser(
        'init', help='initialize auto-provision settings')
    print_subparser = main_subprsers.add_parser(
        'show', help='show all or specific configuration settings')
    print_subparser.add_argument(
        'branch', choices=['all', 'management', 'templates', 'controllers'],
        help='the branch of the configuration to show')
    add_subparser = main_subprsers.add_parser(
        'add', help='add a template or a controller')
    set_subparser = main_subprsers.add_parser(
        'set',
        help='set configurations of a management, a template or a controller')
    del_subparser = main_subprsers.add_parser(
        'delete',
        help='delete configurations of a management, a template or a '
             'controller')

    # init parers
    init_subparsers = init_subparser.add_subparsers()
    aws_init_subparser = init_subparsers.add_parser(
        'AWS', help='initiate management for AWS')
    create_init_aws_arguments(aws_init_subparser)
    azure_init_subparser = init_subparsers.add_parser(
        'Azure', help='initiate management for Azure')
    create_init_azure_arguments(azure_init_subparser)

    # add parsers
    add_subparsers = add_subparser.add_subparsers(dest='branch')
    add_template_subparser = add_subparsers.add_parser(
        'template', help='add a template')
    create_add_templates_arguments(add_template_subparser)
    add_controller_subparser = add_subparsers.add_parser(
        'controller', help='add a controller')
    create_add_controllers_arguments(add_controller_subparser)

    # set parsers
    set_subparsers = set_subparser.add_subparsers(dest='branch')
    delay_subparser = set_subparsers.add_parser('delay', help='set delay')
    delay_subparser.add_argument(
        'delay', type=int,
        help='time to wait in seconds after each poll cycle')
    set_management_subparser = set_subparsers.add_parser(
        'management', help='set management arguments')
    create_set_management_arguments(set_management_subparser)
    set_template_subparser = set_subparsers.add_parser(
        'template', help='set template arguments')
    create_set_templates_arguments(set_template_subparser, conf)
    set_controller_subparser = set_subparsers.add_parser(
        'controller', help='set controller arguments')
    create_set_controllers_arguments(set_controller_subparser, conf)

    # delete parsers
    del_subparsers = del_subparser.add_subparsers(
        help='removable objects', dest='branch')
    del_management_subparsers = del_subparsers.add_parser(
        'management', help='delete management arguments')
    create_del_management_arguments(del_management_subparsers)
    del_template_subparser = del_subparsers.add_parser(
        'template', help='delete template arguments')
    create_del_templates_arguments(del_template_subparser, conf)
    del_controller_subparser = del_subparsers.add_parser(
        'controller', help='delete controller arguments')
    create_del_controllers_arguments(del_controller_subparser, conf)


def add_auxiliary_arguments(args):
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
        traceback.print_exc()
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
    add_auxiliary_arguments(parsed_arguments)
    process_arguments(conf, parsed_arguments)


if __name__ == '__main__':
    main()
