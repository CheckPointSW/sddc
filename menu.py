import os
import sys
import getpass
import subprocess

conf = __import__('conf-cli')

AVAILABLE_VERSIONS = ['R80.20']

SOFTWARE_BLADES = [('-hi', 'HTTPS Inspection'), ('-ia', 'Identity Awareness'), ('-appi', 'Application Control'),
              ('-ips', 'IPS'), ('-uf', 'URL Filtering'), ('-ab', 'Anti-Bot'),
              ('-av', 'Anti-Virus')]

DISPLAY = {'warning' : '\nThis program is a CloudGuard Auto Scaling Transit Gateway first-time wizard.\n'
                       'This wizard will configure a Transit Gateway from scratch. All existing configration will be lost.\n'
                       'Are you sure you want to continue?',
           'headline' : """
Welcome to the Transit Gateway first-time wizard. The following will be configured:
-----------------------------------------------------------------------------------
1. AWS account credentials

2. Automatic Provisioning with Security Management Server

3. CloudGuard Outbound and East\West Transit Gateway Auto Scaling Group

4. CloudGuard Inbound Auto Scaling Group (Optional) 
-----------------------------------------------------------------------------------

Note: When given in brackets a default value, press Enter to apply it, e.g. [NAME]""",
           'aws_cred' : """
AWS account credentials for provisioning the Transit Gateways Auto Scaling Group:
---------------------------------------------------------------------------------
1. IAM (Security Management Server is deployed in AWS)

2. Access Keys

Please enter your choice: (1-2) [IAM]: """,
           'sub_cred' :  """
Sub-account credentials:
------------------------
1. STS role ARN

2. Access Keys

Please enter your choice: (1-2) [STS role ARN]: """,
           'access_keys' : """
Access keys input:
------------------
1. Hard coded Access key ID and Secret key

2. File path containing AWS credentials

Please enter your choice: (1-2) [Hard-coded]: """,
           'blades' : """
                \nEnabling Software Blades:
-------------------------
1. HTTPS Inspection

2. Identity Awareness

3. Application Control

4. IPS 

5. URL Filtering

6. Anti-Bot

7. Anti-Virus

Please enter your choices, separated by comma (e.g. 1,4,5) : """}

def run_command(command):
  #  proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    result = os.popen(command).read()#proc.stdout.read()#
    if not 'autoprovision' in result:
        sys.stdout.write('\nFailed to Initialize configuratiom due to the above Error.\nFix the issue, and run the script again.\n')#\nError message:\n' + result)
        exit()
    elif 'FAILED' in result.split('\n')[1]:
       sys.stdout.write('\nFailed to start provisioning. Make sure you have the correct add-on installed on your Check Point Management Server.\n')
       exit()

def blades_output(blades, blades_dict):
    output = ''
    if blades:
        output = '\n  Software Blades: '
        for blade in blades:
            output += '\n    ' + blades_dict[blade]
    return output

def configuration_output(access, controller, advanced_access, region, mgmt, template,
                version, policy, community, blades, mds = '', inbound_template = '',
                inbound_version = '', inbound_policy = '', inbound_blades = ''):

    conf_output = '\n\nConfiguration summary:\n----------------------\nAWS Account Controller:\n  name: ' \
                  + controller

    if 'iam' in access:
        conf_output += '\n  Credentials File: IAM'
    else:
        access = access.split()
        conf_output += '\n  Access Key: ' + access[1] + '\n  Secret Key: ********' #+ access[3]
    if advanced_access:
        advanced_access = advanced_access.split()
        if advanced_access[0] == '-sr':
            conf_output += '\n  Security Token Service (STS) role: ' + advanced_access[1]
            if len(advanced_access) > 2:
                conf_output += '\n  Sub-account Credentials:\n    ' + advanced_access[3] + ':\n      Security Token Service (STS) role:' + advanced_access[5]
        else:
            conf_output += '\n  Sub-account credentials:\n    ' + advanced_access[1] + ':\n      Security Token Service (STS) role:' + advanced_access[3]
    conf_output += '\n  Region: ' + region + '\nCheck Point Management Server: ' + '\n  Name: ' + mgmt

    if mds:
        conf_output += '\n  Domain: ' + mds.split()[1]

    conf_output += '\nConfiguration Templates:\n  ' + template + ':\n    Check Point VPN community: ' + community \
                   + '\n    one time password (SIC): ******** \n    Policy name: ' + policy + '\n    Security Gateway version: ' + version

    blades = blades.split()
    blades_dict = dict(SOFTWARE_BLADES)
    conf_output += blades_output(blades, blades_dict)

    if inbound_template:#SIC Activation Key
        conf_output += '\n  ' + inbound_template + ':\n    one time password (SIC): ******** \n    Policy name: ' \
                       + inbound_policy + '\n    Security Gateway version: ' + inbound_version

        blades = inbound_blades.split()
        conf_output += blades_output(blades, blades_dict)

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
            else:
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
            validate_password = getpass.getpass('Re-enter AWS Secret Access Key: ')
            if password != validate_password:
                raise Exception(passowrd_type + ' doesn\'t match')
            return password
        except Exception, e:
            sys.stdout.write(str(e) + '\nPlease enter a valid ' + passowrd_type + '\n')

def get_sic():
    return get_password('one time password (SIC)')

def get_version():
    version = get_user_input('\nSecurity Gateway version', AVAILABLE_VERSIONS[0])

    while version.upper() not in AVAILABLE_VERSIONS:
        version = raw_input('Invalid version. Available versions: {' +
                            ', '.join(
                                AVAILABLE_VERSIONS) + '} \nPlease enter a valid Security Gateway version from the above list: ')
    return version

def get_region():
    display_headline('Available AWS regions:')
    region_selection = ''
    regions = conf.AWS_REGIONS
    region_len = len(regions)
    if region_len % 2 != 0:
        regions[' '] = ' '

    example = '(e.g. 2 for ' + regions.keys()[1]  + ') : '
    #region_slice = regions[:region_len / 2]
    for i, (region_name, region_val) in enumerate(regions.iteritems()):
        if i < region_len / 2:
            region_idx_row_2 = region_len / 2 + i
            region_name_row_2 = regions.keys()[region_idx_row_2]
            region_val_row_2 = regions.values()[region_idx_row_2]
            len_pair_row_1 = len(region_name) + len(region_val)
            separation = '|'.rjust(50 - len_pair_row_1)
            #separation = separation.ljust(40)
            region_selection += '\n\n' + str(i + 1) + '. ' + region_name + ' : ' + region_val + separation \
                              + str(region_idx_row_2).rjust(10) + '. ' + region_name_row_2 + ' : ' + region_val_row_2

    region_selection += '\n\nPlease enter your region number ' + example
    region = raw_input(region_selection)
    while not region.isdigit() or int(region) not in list(range(1,region_len)):
        region = raw_input('Invalid region. Please enter a valid choice from the above list ' + example)
    return regions.values()[int(region) - 1]

def enable_blades():
    if conf.prompt('\nDo you want to enabled Software Blades on the Security Gateways?'):
        choice_range = ['1', '2', '3', '4', '5', '6', '7']  # list(range(1,8))
        while True:
            blades_choice = get_user_input(DISPLAY['blades'],  empty_msg='\nMissing a choice. Are you sure you want to enable Software Blades on the Security Gateways?')
       #while True:
       #   blades_choice = raw_input(DISPLAY['blades'])
       #   if not blades_choice:
       #       if conf.prompt('\nMissing a choice. Are you sure you want to enable Software Blades on the Security Gateways?'):
       #           continue
       #       else:
       #           return ''

            blades_choice = blades_choice.split(',')
            if not all(blade in choice_range for blade in blades_choice):
                sys.stdout.write('Invalid choice. Choose from the following list: {' + ','.join(choice_range) + '}')
                continue
            enable_blades = 'The following Software Blades will be enabled: '
            enable_blades_command = ''
            for blade in blades_choice:
                blade_tup = SOFTWARE_BLADES[int(blade) - 1]
                enable_blades += blade_tup[1] + ', '
                enable_blades_command += ' ' + blade_tup[0]

            if conf.prompt(enable_blades[:-2] + '.\nIs the above configuration correct?'):
                return enable_blades_command
            else:
                continue
    return ''

def add_template(action, template, otp='', ver='', policy='', transit='', blades=''):
    command = 'autoprov-cfg -f ' + action + ' template -tn ' + template + otp + ver + policy + transit + blades# + ' > /dev/null'
    run_command(command)

def add_controller(controller, mds = '', community = '', controller_access = '', lb =''):
    command = 'autoprov-cfg -f set controller AWS -cn ' + controller + mds + ' -sg -sv -com ' + community + controller_access + lb# + ' > /dev/null'
    run_command(command)

def init_conf(managment, template, otp, ver, policy, controller, regions, credentials, deployment):
    command = 'autoprov-cfg -f init AWS -mn ' + managment + ' -tn ' + template + ' -cn ' + controller + ' -po '\
              + policy + ' -otp ' + otp + ' -r ' + regions + ' -ver ' + ver + credentials + ' -dt ' + deployment# + ' > /dev/null'
    run_command(command)

def access_keys(sub_account = False):
    while True:
        access_input = raw_input(DISPLAY['access_keys'])
        if access_input == '1' or not access_input:
            access_key = raw_input('\nAWS Access Key ID: ')
            if not access_key:
                sys.stdout.write('You need to enter your AWS Access Key ID\n')
                continue
            secret_key = get_password('AWS Secret Access Key')
            if sub_account:
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
            if sub_account:
                return ' -fi ' + file_path
            else:
                return ' -sfi ' + file_path
        else:
            sys.stdout.write('\nInvalid choice. Enter "1" or "2".\n')

def advanced_access_cred():
    controller_access = ''
    if conf.prompt('\nDo you require Advanced AWS credentials? (e.g. Transit Gateway in different account)'):
        if conf.prompt('\nDo you require an Assume Role for the primary account?'):
            assume_role = get_user_input('\nSecurity Token Service (STS) role ARN: '
                           , '\nYou did not enter an STS role ARN. Is this configuration required in your environment?')
            if assume_role:
                controller_access = ' -sr ' + assume_role
            #while True:
            #    assume_role = raw_input('\nSecurity Token Service (STS) role ARN: ')
            #    if not assume_role:
            #        if not conf.prompt(
            #                '\nYou did not enter an STS role ARN. Is this configuration required in your environment?'):
            #            break
            #    else:
            #        controller_access = ' -sr ' + assume_role
            #        break

        if conf.prompt('\nDo you require a sub-account?'):
            sub_account_name = get_user_input('\nUnique Sub-account name', 'tgw-sub-account')
            while True:
                sub_accoun_access = raw_input(DISPLAY['sub_cred'])
                if sub_accoun_access == '1' or not sub_accoun_access:
                    assume_role = raw_input('\nSub-account Security Token Service (STS) role ARN: ')
                    if not assume_role:
                        if not conf.prompt(
                                'You did not enter a Sub-account STS role ARN. Is this configuration required in your environment?'):
                            break
                    else:
                        controller_access += ' -sn ' + sub_account_name + ' -ssr ' + assume_role
                        break
                elif sub_accoun_access == '2':
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

    raw_input('\n\nPress Enter to start configuring the Transit Gateway...')

    display_headline('Step 1: Configure the AWS account credentials')

    controller = get_user_input('\nAWS Account Controller', 'aws-tgw')

    access, controller_access = access_cred()

    region = get_region()

    display_headline('Step 2: Configure Security Management provisioning')

    mgmt = get_user_input('\nUnique Security Management name', 'cp-management')

    mds = ''
    if conf.prompt('\nIs this a Multi-Domain Security Management (MDS)?'):
        mds = ' -cd '
    domain_name = ''
    if mds:
        while True:
            domain_name = get_user_input('\nDomain name or UID',  empty_msg='You did not enter a Domain name or UID. Is this a Multi-Domain Security Management (MDS)?')
            #while True:
            #    domain_name = raw_input('\nDomain name or UID: ')
            #    if not domain_name:
            #        if not conf.prompt('You did not enter a Domain name or UID. Is this a Multi-Domain Security Management (MDS)?'):
            #            mds = ''
            #            break
            if not domain_name:
                mds = ''
                break
            else:
                domain_name = domain_name.translate(None, '\'\"')
                domains = os.popen('mgmt_cli -r true  show domains').read()
                if '\n- uid: "' + domain_name not in domains and '\n  name: "' + domain_name not in domains:
                    sys.stdout.write('Domain name not found. please Enter an existing domain\n')
                else:
                  mds += domain_name
                  break

        display_headline('Step 3: Configure CloudGuard Transit Gateway Auto Scaling Group')

    template = get_user_input('\nConfiguration Template name for the Transit Gateways', 'TGW-ASG-configuration')

    community = get_user_input('\nCheck Point VPN community name', 'tgw-community')

    sic = get_password('one time password (SIC)')

    version = AVAILABLE_VERSIONS[0] #get_version()

    policy = get_user_input('\nPolicy Package name', 'Standard')

    # adding tgw template
    blades = enable_blades()

    inbound = False
    inbound_template = inbound_sic = inbound_blades = inbound_version = inbound_policy = lb = ''
    if conf.prompt('\nEnable support for the Inbound Auto Scaling Group through the AWS Transit Gateway?'):
        inbound = True
        lb = ' -slb '

        display_headline('Step 4: Configure CloudGuard Inbound Auto Scaling Group')

        inbound_template = get_user_input('\nConfiguration Template name for the Inbound Auto Scaling Group Gateways', 'Inbound-ASG-configuration')
        # adding inbound template
        if not conf.prompt('\nUsing same one time password (SIC) as previous Auto Scaling Group?'):
            inbound_sic = get_password('one time password (SIC)')
        else:
            inbound_sic = sic
        inbound_version = AVAILABLE_VERSIONS[0] #get_version()
        inbound_policy = get_user_input('\nPolicy Package name for Inbound Auto Scaling Group', 'Standard')
        inbound_blades = enable_blades()

    configuration_output(access, controller, controller_access, region, mgmt, template,
                version, policy, community, blades, mds, inbound_template,
                inbound_version, inbound_policy, inbound_blades)

    if not conf.prompt('\n\nIs the above configuration correct? '):
        sys.stdout.write('Configuration was not applied. To start the wizard, run the script again.\n')
        exit()

    sys.stdout.write('\n\nApplying the configuration...\n\n')

    command = '/etc/fw/scripts/autoprovision/config-community.sh ' + community + ' ' + domain_name + ' &> output.txt'
    #result = subprocess.popen(command).read()
    os.system(command)  #
    result = open('output.txt', 'r').read()
    os.system('rm output.txt\n')
    # os.system('/etc/fw/scripts/autoprovision/config-community.sh ' + community + ' ' + domain_name + ' &> /dev/null')
    if 'failed' in result:
        sys.stdout.write('\nFailed to create Check Point VPN community.\nFix the issue, and run the script again.\n\nError message:\n\n' + result)
        exit()

    init_conf(mgmt, template, sic, version, policy, controller, region, access, 'TGW')

    add_template('set', template, ' -vpn -vd "" -con ' + community, blades)

    if inbound:
        add_template('add', inbound_template, ' -otp ' + inbound_sic, ' -ver ' + inbound_version, ' -po ' + inbound_policy, inbound_blades)

    add_controller(controller, mds, community, controller_access, lb)

    tag = mgmt + '/' + domain_name + '/' + community if mds else mgmt + '/' + community
    sys.stdout.write('\n\nYour Transit Gateway configuration is ready!\n\nYour Transit Gateway tag is: ' + tag + '\n')

if __name__ == '__main__':
    configure_tgw()