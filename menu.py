import os
import sys
import getpass
import subprocess
from collections import OrderedDict

conf = __import__('conf-cli')

AVAILABLE_VERSIONS = ['R80.20']

SOFTWARE_BLADES = OrderedDict([('-hi', 'HTTPS Inspection'),
                               ('-ia', 'Identity Awareness'),
                               ('-appi', 'Application Control'),
                               ('-ips', 'IPS'),
                               ('-uf', 'URL Filtering'),
                               ('-ab', 'Anti-Bot'),
                               ('-av', 'Anti-Virus')])

DISPLAY = {'warning': '\nThis program is a CloudGuard Auto Scaling Transit '
                      'Gateway first-time wizard.\n'
                      'All existing configuration will be lost.\n'
                      'Are you sure you want to continue?',
           'headline': '\nWelcome to the Transit Gateway first-time wizard. '
                       'The wizard will configure the following:\n----------'
                       '----------------------------------------------------'
                       '----------------------------\n\n'
                       '1. AWS account credentials\n\n'
                       '2. Automatic Provisioning with a Security '
                       'Management Server\n\n3. CloudGuard outbound '
                       'and east/west Transit Gateway Auto Scaling Group\n\n'
                       '4. CloudGuard inbound Auto Scaling Group '
                       '(optional)\n\n----------------------------------------'
                       '--------------------------------------------------\n\n'
                       'Note: default values are annotated with square '
                       'brackets, press Enter to use them.',
           'aws_cred': '\n\nAWS account credentials:\n'
                       '------------------------\n'
                       'The credentials are used by the Security Management '
                       'Server to connect to your\nAWS environment, read '
                       'information from it and make changes that are '
                       'necessary\nfor the automatic provisioning of '
                       'Transit Gateway. You can use the management\n'
                       'server AWS IAM profile if it is deployed in AWS'
                       ' or provide access keys.\n\n1. IAM\n\n2. Access'
                       ' Keys\n\nPlease enter your choice: (1-2) [IAM]: ',
           'sub_cred':  '\n\nSub-account credentials:'
                        '\n------------------------\n\n'
                        '1. STS role ARN\n\n2. Access Keys''\n\n'
                        'Please enter your choice: (1-2) [STS role ARN]: ',
           'access_keys': '\n\nAccess keys:\n------------\n'
                          '1. Provide access key ID and secret key\n\n'
                          '2. Provide a file path\n\n'
                          'Please enter your choice: (1-2) [Input]: '
           }


def run_mgmt_command(command, err_msg):
    proc = subprocess.Popen(
        command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    out, err = proc.communicate()
    rc = proc.wait()
    if 'failed' in err.lower() or rc:
        sys.stderr.write(err_msg + err)
        exit(2)
    return out


def run_conf_command(command):
    result = os.popen(command).read()
    if 'autoprovision' not in result:
        sys.stdout.write('\nFailed to initialize configuration.\n')
        exit()

    elif 'FAILED' in result.split('\n')[1]:
        sys.stdout.write('\nFailed to start automatic provisioning.\n')
        exit()


def blades_output(blades):
    output = ''
    if blades:
        output = '\n    Software Blades: '
        for blade in blades:
            output += '\n      ' + SOFTWARE_BLADES[blade]
    return output


def sub_account_output(sub_account_access):
    output = '\n  Sub-account credentials:\n    ' \
        + 'Name: ' + sub_account_access[1]
    if len(sub_account_access) > 4:
        output += '\n    Access Key: ' + sub_account_access[3] \
            + '\n    Secret Key: ********'
    elif '-sfi' in sub_account_access[2]:
        output += '\n    File path: ' + sub_account_access[3]
    else:
        output += '\n    Security Token Service (STS) role: ' \
                  + sub_account_access[3]
    return output


def configuration_output(access_cred, controller_name,
                         advanced_access_cred, region, mgmt_name,
                         template, ver, policy, community, blades,
                         mds='', inbound_template='', inbound_ver='',
                         inbound_policy='', inbound_blades=''):

    conf_output = '\n\nConfiguration summary:' \
                  '\n----------------------\nAWS Account Controller:' \
                  '\n  Name: ' + controller_name

    if 'iam' in access_cred:
        conf_output += '\n  Account Credentials: IAM'
    else:
        access = access_cred.split()
        if len(access) > 2:
            conf_output += '\n  Access Key: ' + access[1]\
                           + '\n  Secret Key: ********'
        else:
            conf_output += '\n  File path: ' + access[1]
    if advanced_access_cred:
        advanced_access = advanced_access_cred.split()
        if advanced_access[0] == '-sr':
            conf_output += '\n  Security Token Service (STS) role: '\
                           + advanced_access[1]
            if len(advanced_access) > 2:
                conf_output += sub_account_output(advanced_access[2:])
        else:
            conf_output += sub_account_output(advanced_access)
    conf_output += '\n  Region: ' + region \
                   + '\nSecurity Management Server: ' \
                   + '\n  Name: ' + mgmt_name

    if mds:
        conf_output += '\n  Domain: ' + mds.split()[1]

    conf_output += '\nConfiguration Templates:\n  ' \
                   + template + ':\n    Check Point VPN community: ' \
                   + community \
                   + '\n    One time password (SIC): ******** \n' \
                     '    Policy name: ' + policy \
                   + '\n    Security Gateway version: ' + ver

    blades = blades.split()
    conf_output += blades_output(blades)

    if inbound_template:
        conf_output += '\n  ' + inbound_template \
                       + ':\n    One time password (SIC): ******** \n' \
                         '    Policy name: ' + inbound_policy \
                       + '\n    Security Gateway version: ' + inbound_ver

        blades = inbound_blades.split()
        conf_output += blades_output(blades)

    sys.stdout.write(conf_output)


def get_user_input(question, default_name='', empty_msg=''):
    if default_name:
        default_output = ' [' + default_name + ']'
    else:
        default_output = ''
    name = ''
    while not name:
        name = raw_input(question + default_output + ': ')
        if not name:
            if default_name:
                name = default_name
                break
            elif empty_msg:
                if not conf.prompt(empty_msg):
                    name = ''
                    break
    return name


def get_password(passowrd_type):
    while True:
        try:
            password = getpass.getpass('\n' + passowrd_type + ': ')
            if 'SIC' in passowrd_type:
                password = conf.validate_SIC(password)
            if not password:
                raise Exception('\nYou need to enter your ' + passowrd_type)
            validate_password = getpass.getpass('Re-enter'
                                                ' AWS Secret Access Key: ')
            if password != validate_password:
                raise Exception(passowrd_type + ' doesn\'t match')
            return password
        except Exception, e:
            sys.stdout.write(str(e) + '\nPlease enter a valid '
                             + passowrd_type + '\n')


def get_sic():
    return get_password('one time password (SIC)')


def get_version():
    version = get_user_input(
        '\nSecurity Gateway version', AVAILABLE_VERSIONS[0])

    while version.upper() not in AVAILABLE_VERSIONS:
        version = raw_input('Invalid version. Available versions: {' +
                            ', '.join(
                                AVAILABLE_VERSIONS)
                            + '} \nPlease enter a valid Security '
                              'Gateway version from the above list: ')
    return version


def get_region():
    display_headline('Available AWS regions:')
    region_selection = ''
    regions = conf.AWS_REGIONS
    region_len = len(regions)
    if region_len % 2 != 0:
        regions[' '] = ' '

    example = '(e.g. 2 for ' + regions.keys()[1] + ') : '
    for i, (region_name, region_val) in enumerate(regions.iteritems()):
        if i < region_len / 2:
            region_idx_row_2 = region_len / 2 + i
            region_name_row_2 = regions.keys()[region_idx_row_2]
            region_val_row_2 = regions.values()[region_idx_row_2]
            len_pair_row_1 = len(region_name) + len(region_val)
            separation = '|'.rjust(50 - len_pair_row_1)
            region_selection += '\n\n' + str(i + 1) + '. ' + region_name \
                                + ': ' + region_val + separation \
                                + str(region_idx_row_2).rjust(10) + '. ' \
                                + region_name_row_2 + ': ' + region_val_row_2

    region_selection += '\n\nPlease enter your region number ' + example
    region = raw_input(region_selection)
    while not region.isdigit() or int(region) not in range(1, region_len):
        region = raw_input('Invalid region. Please enter a valid choice '
                           'from the above list ' + example)
    return regions.values()[int(region) - 1]


def display_blades():
    blades_choice = '\n\nCheck Point Software Blades:' \
                    '\n----------------------------'
    for i, blade in enumerate(SOFTWARE_BLADES.iteritems()):
        blades_choice += '\n\n' + str(i + 1) + '. ' + blade[1]

    blades_choice += '\n\nPlease enter your choices, ' \
                     'separated by comma (e.g. 1,4,5) '

    return blades_choice


def enable_blades(display):
    if conf.prompt('\nDo you want to enable Software Blades?'):
        blades_command = SOFTWARE_BLADES.keys()
        blades_value = SOFTWARE_BLADES.values()
        while True:
            blades_choice = get_user_input(
                display, empty_msg='\nMissing a choice. '
                'Are you sure you want to enable Software Blades on the'
                ' Security Gateways?')
            blades_choice = blades_choice.split(',')
            choice_range =\
                [str(i) for i in range(1, len(SOFTWARE_BLADES) + 1)]
            if not all(blade in choice_range for blade in blades_choice):
                sys.stdout.write('Invalid choice. Choose from '
                                 'the following list: {'
                                 + ','.join(choice_range) + '}')
                continue
            enable_blades = 'The following Software Blades will be enabled: '
            enable_blades_command = ''
            for blade in blades_choice:
                idx = int(blade) - 1
                enable_blades += blades_value[idx] + ', '
                enable_blades_command += ' ' + blades_command[idx]

            if conf.prompt(
                enable_blades[:-2]
                    + '.\nIs the above configuration correct?'):
                return enable_blades_command
            else:
                continue
    return ''


def add_template(action, template, otp='', ver='', policy='', transit='',
                 blades=''):
    command = 'autoprov-cfg -f ' + action + ' template -tn ' + template \
              + otp + ver + policy + transit + blades
    run_conf_command(command)


def add_controller(
        controller, mds='', community='', controller_access='', lb=''):
    command = 'autoprov-cfg -f set controller AWS -cn ' + controller + mds \
              + ' -sg -sv -com ' + community + controller_access + lb
    run_conf_command(command)


def init_conf(managment, template, otp, ver, policy, controller, regions,
              credentials, deployment):
    command = 'autoprov-cfg -f init AWS -mn ' + managment + ' -tn ' \
              + template + ' -cn ' + controller + ' -po ' \
              + policy + ' -otp ' + otp + ' -r ' + regions \
              + ' -ver ' + ver + credentials + ' -dt ' + deployment
    run_conf_command(command)


def access_keys(sub_account=False):
    while True:
        access_input = raw_input(DISPLAY['access_keys'])
        if access_input == '1' or not access_input:
            access_key = raw_input('\nAWS Access Key ID: ')
            if not access_key:
                sys.stdout.write('You need to enter your AWS Access Key ID\n')
                continue
            secret_key = get_password('AWS Secret Access Key')
            if not sub_account:
                return ' -ak ' + access_key + ' -sk ' + secret_key
            else:
                return ' -sak ' + access_key + ' -ssk ' + secret_key
        elif access_input == '2':
            file_path = ''
            while not file_path:
                try:
                    file_path = raw_input('\nFile-path: ')
                    conf.validate_filepath(file_path)
                except Exception, e:
                    sys.stdout.write(str(e))
                    file_path = ''
            if not sub_account:
                return ' -fi ' + file_path
            else:
                return ' -sfi ' + file_path
        else:
            sys.stdout.write('\nInvalid choice. Enter "1" or "2".\n')


def advanced_access_cred():
    controller_access = ''
    if conf.prompt(
            '\nWould you like to configure advanced AWS account credentials, '
            'such as STS roles and/or additional account?'):
        if conf.prompt(
                '\nWould you like to assume a different IAM identity using'
                'AWS Security Token Service (STS) in your primary account?'):
            assume_role = get_user_input(
                '\nSecurity Token Service (STS) role ARN',
                empty_msg='\nYou did not enter an STS role ARN. '
                'Is this configuration required in your environment?')
            if assume_role:
                controller_access = ' -sr ' + assume_role
        if conf.prompt(
                '\nWould you like to configure an additional AWS account for '
                'the Transit Gateway?'):
            sub_account_name = get_user_input(
                '\nSelect a unique sub-account name', 'tgw-sub-account')
            controller_access += ' -sn ' + sub_account_name
            while True:
                sub_account_access = raw_input(DISPLAY['sub_cred'])
                if sub_account_access == '1' or not sub_account_access:
                    assume_role = get_user_input(
                        '\nSub-account STS role ARN',
                        empty_msg='\nYou did not enter a '
                        'Sub-account STS role ARN. Is this '
                        'configuration required in your environment?')
                    if assume_role:
                        controller_access += ' -ssr ' + assume_role
                        break
                    else:
                        controller_access = \
                            controller_access.split(' -sr ')[0]
                        break
                elif sub_account_access == '2':
                    controller_access += access_keys(sub_account=True)
                    break
                else:
                    sys.stdout.write('\nInvalid choice. Enter "1" or "2".\n')
    return controller_access


def access_cred():
    # Account access
    while True:
        required_access = raw_input(DISPLAY['aws_cred'])
        if required_access == '1' or not required_access:
            access = ' -iam '
            break
        elif required_access == '2':
            access = access_keys()
            break
        else:
            sys.stdout.write('\nInvalid choice. Enter "1" or "2".\n')

    controller_access = advanced_access_cred()

    return access, controller_access


def display_headline(step):
    sys.stdout.write('\n\n' + step + '\n' + '-'*len(step))


def configure_tgw():
    # Head line
    if not conf.prompt(DISPLAY['warning']):
        exit()

    # welcome message
    sys.stdout.write(DISPLAY['headline'])

    raw_input('\n\nPress Enter to continue...')

    display_headline('Step 1: AWS account credentials')

    controller = get_user_input(
        '\nSelect a name for this AWS Account Controller', 'aws-tgw')

    access, controller_access = access_cred()

    region = get_region()

    display_headline(
        'Step 2: Automatic Provisioning with a Security Management Server')

    mgmt = get_user_input(
        '\nSelect a unique Security Management Server name', 'cp-management')

    mds = domain_name = ''
    if conf.prompt(
            '\nIs this a Multi-Domain Security Management Server (MDS)?'):
        mds = ' -cd '
        while True:
            domain_name = get_user_input(
                '\nDomain name or UID',
                empty_msg='\nYou did not enter a Domain name or UID. '
                'Is this a Multi-Domain Security Management (MDS)?')
            if not domain_name:
                mds = ''
                break
            else:
                domain_name = domain_name.translate(None, '\'\"')
                domains = run_mgmt_command(
                    'mgmt_cli -r true  show domains',
                    '\nError connecting to Management Server: \n\n')
                if '\n- uid: "' + domain_name not in domains and '\n  name: "'\
                        + domain_name not in domains:
                    sys.stdout.write(
                        'Domain name not found. '
                        'please Enter an existing domain\n')
                else:
                    mds += domain_name
                    break

    display_headline(
        'Step 3: CloudGuard outbound and east/west Transit Gateway '
        'Auto Scaling Group')

    template = get_user_input(
        '\nSelect a name for this Transit Gateways configuration template',
        'TGW-ASG-configuration')

    community = get_user_input(
        '\nCheck Point VPN community name', 'tgw-community')

    sic = get_password('one time password (SIC)')

    version = AVAILABLE_VERSIONS[0]

    policy = get_user_input('\nPolicy Package name', 'Standard')

    # adding tgw template
    blades_display = display_blades()
    blades = enable_blades(blades_display)

    inbound = False
    inbound_template \
        = inbound_sic = inbound_blades \
        = inbound_version = inbound_policy = lb = ''
    if conf.prompt(
            '\nEnable support for the inbound Auto Scaling Group '
            'through the AWS Transit Gateway?'):
        inbound = True
        lb = ' -slb '

        display_headline(
            'Step 4: CloudGuard inbound Auto Scaling Group')

        inbound_template = get_user_input(
            '\nSelect a name for the inbound Auto Scaling Group '
            'Gateways configuration template', 'Inbound-ASG-configuration')
        # adding inbound template
        if not conf.prompt(
                '\nUse the same one time password (SIC) '
                'as the Transit Gateway Auto Scaling Group?'):
            inbound_sic = get_password('one time password (SIC)')
        else:
            inbound_sic = sic
        inbound_version = AVAILABLE_VERSIONS[0]
        inbound_policy = get_user_input(
            '\nPolicy Package name for inbound '
            'Auto Scaling Group', 'Standard')
        inbound_blades = enable_blades(blades_display)

    configuration_output(
        access, controller, controller_access, region, mgmt, template,
        version, policy, community, blades, mds, inbound_template,
        inbound_version, inbound_policy, inbound_blades)

    if not conf.prompt('\n\nIs the above configuration correct? '):
        sys.stdout.write(
            'Configuration was not applied. '
            'To start the wizard, run the script again.\n')
        exit()

    sys.stdout.write('\n\nApplying the configuration...\n')

    command = '/etc/fw/scripts/autoprovision/config-community.sh ' \
              + community + ' ' + domain_name

    run_mgmt_command(
        command, '\nFailed to create Check Point VPN community.'
        '\n\nError message: \n\n')

    init_conf(
        mgmt, template, sic, version, policy,
        controller, region, access, 'TGW')

    add_template('set', template, ' -vpn -vd "" -con ' + community, blades)

    if inbound:
        add_template(
            'add', inbound_template, ' -otp ' + inbound_sic,
            ' -ver ' + inbound_version, ' -po '
            + inbound_policy, inbound_blades)

    add_controller(controller, mds, community, controller_access, lb)

    tag = \
        mgmt + '/' + domain_name \
        + '/' + community if mds else mgmt + '/' + community
    sys.stdout.write(
        '\n\nYour Transit Gateway configuration is ready!'
        '\n\nYour Transit Gateway tag is: ' + tag + '\n')


if __name__ == '__main__':
    configure_tgw()
