#!/usr/bin/env python

#   Copyright 2015 Check Point Software Technologies LTD
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

import StringIO
import argparse
import base64
import collections
import contextlib
import datetime
import hashlib
import httplib
import json
import os
import os.path
import re
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urlparse
import xml.dom.minidom

import api

TAG = 'managed-virtual-gateway'
WEB_DIR = os.path.dirname(sys.argv[0]) + '/web'
STATE_FILE = WEB_DIR + '/gateways.json'

if os.path.isfile('/etc/cp-release'):
    os.environ['AWS_CA_BUNDLE'] = os.environ['CPDIR'] + '/conf/ca-bundle.crt'
    os.environ['AWS_CURL'] = 'curl_cli'

conf = {}


def log(msg):
    sys.stderr.write(msg)


def debug(msg):
    if conf.get('debug'):
        log(msg)


def dump(obj):
    debug('%s\n' % json.dumps(obj, indent=2))


# avoid printing sensitive data
@contextlib.contextmanager
def censor(active, pattern, replacement):
    line = []
    if active:
        stdout = sys.stdout
        pattern = re.compile(pattern)

        def write(buf):
            while buf:
                end, newline, start = buf.partition('\n')
                line.append(end)
                if not newline:
                    return
                buf = ''.join(line) + '\n'
                m = pattern.match(buf)
                if m:
                    buf = buf[:m.start(1)] + replacement + buf[m.end(1):]
                log('%s' % buf)
                line[:] = []
                buf = start

        sys.stdout = StringIO.StringIO()
        sys.stdout.write = write
    yield
    if active:
        log('%s' % ''.join(line))
        sys.stdout = stdout


class Template(object):
    EXCLUDED = set(['proto'])
    templates = {None: None}

    def __init__(self, name, **options):
        self.name = name
        self.proto = self.templates[options.get('proto')]
        self.self = self
        self.options = {
            k: v for k, v in options.items() if k not in self.EXCLUDED}
        self.templates[self.name] = self

    def __getattr__(self, attr):
        if attr in self.options:
            return self.options[attr]
        if self.proto:
            return getattr(self.proto, attr)
        raise AttributeError()

    @staticmethod
    def get(name, attr, default=None):
        template = Template.templates[name]
        return getattr(template, attr, default)

    @staticmethod
    def get_dict(template):
        result = {}
        if not isinstance(template, Template):
            template = Template.templates[template]
        for k in template.options:
            result[k] = template.options[k]
        if template.proto:
            for k, v in Template.get_dict(template.proto).items():
                if k not in result:
                    result[k] = v
        return result


class Instance(object):
    def __init__(self, name, ip_address, interfaces, template):
        self.name = name
        self.ip_address = ip_address
        self.interfaces = interfaces
        self.template = template

    def __str__(self):
        return ' '.join([
            self.name, self.ip_address, json.dumps(self.interfaces),
            self.template])


class Controller(object):
    SEPARATOR = '--'

    def __init__(self, **options):
        self.name = options['name']
        self.management = options['management']

    def get_instances(self):
        raise Exception('not implemented')


class AWS(Controller):
    def __init__(self, **options):
        super(AWS, self).__init__(**options)
        self.aws = api.AWS(
            key=options.get('access-key'), secret=options.get('secret-key'),
            token=options.get('session-token'),
            key_file=options.get('cred-file'))
        self.regions = options['regions']

    def retrieve_subnets(self):
        subnets = {}
        for region in self.regions:
            subnets[region] = {}
            headers, body = self.aws.request(
                'ec2', region, 'GET', '/?Action=DescribeSubnets', '')
            for s in api.as_list(body['subnetSet'], 'item'):
                subnets[region][s['subnetId']] = s
        return subnets

    def retrieve_interfaces(self):
        interfaces = {}
        for region in self.regions:
            interfaces[region] = {}
            headers, body = self.aws.request(
                'ec2', region, 'GET',
                '/?Action=DescribeNetworkInterfaces', '')
            for i in api.as_list(body['networkInterfaceSet'], 'item'):
                interfaces[region][i['networkInterfaceId']] = i
        return interfaces

    def retrieve_instances(self):
        instances = {}
        for region in self.regions:
            instances[region] = []
            next_token = None
            while True:
                extra_params = ''
                if next_token:
                    extra_params += '&' + urllib.urlencode({
                        'NextToken', next_token})
                headers, body = self.aws.request(
                    'ec2', region, 'GET',
                    '/?Action=DescribeInstances' +
                    '&Filter.1.Name=tag:x-chkp-management&Filter.1.Value=' +
                    self.management + extra_params, '')
                object = api.listify(body, 'item')
                for r in object['reservationSet']:
                    instances[region] += r['instancesSet']
                next_token = object.get('nextToken')
                if not next_token:
                    break
        return instances

    def get_topology(self, eni, subnets):
        tags = api.get_ec2_tags(eni)
        topology = tags.get('x-chkp-topology', '').lower()
        anti_spoofing = (tags.get('x-chkp-anti-spoofing', 'true').lower()
                         == 'true')
        if not topology:
            if eni.get('association', {}).get('publicIp'):
                topology = 'external'
            else:
                topology = 'internal'

        interface = {
            'name': 'eth' + eni['attachment']['deviceIndex'],
            'ipv4-address': eni['privateIpAddress'],
            'ipv4-mask-length':
                int(subnets[eni['subnetId']][
                    'cidrBlock'].partition('/')[2]),
            'anti-spoofing': anti_spoofing,
            'topology': topology
        }

        if topology == 'internal':
            interface['topology-settings'] = {
                'ip-address-behind-this-interface':
                    'network defined by the interface ip and net mask'
            }

        return interface

    def get_instances(self):
        ec2_instances = self.retrieve_instances()
        enis = self.retrieve_interfaces()
        subnets = self.retrieve_subnets()
        instances = []
        for region in self.regions:
            for instance in ec2_instances[region]:
                interfaces = []
                instance_name = self.SEPARATOR.join(
                    [self.name, instance['instanceId'], region])
                if instance['instanceState']['name'] not in [
                        'running', 'stopping', 'stopped']:
                    continue

                tags = api.get_ec2_tags(instance)
                ip_address = tags.get('x-chkp-ip-address', 'public')

                if ip_address == 'private':
                    ip_address = instance['privateIpAddress']
                elif ip_address == 'public':
                    ip_address = instance.get('ipAddress')

                if not ip_address:
                    log('no ip address for %s\n' % instance_name)
                    continue

                for interface in instance['networkInterfaceSet']:
                    interfaces.append(self.get_topology(
                        enis[region][interface['networkInterfaceId']],
                        subnets[region]))

                instances.append(Instance(
                    instance_name, ip_address, interfaces,
                    tags['x-chkp-template']))
        return instances


class OpenStack(Controller):
    def __init__(self, **options):
        super(OpenStack, self).__init__(**options)
        self.scheme = options.get('scheme', 'https')
        self.fingerprint = None
        if self.scheme == 'https':
            self.fingerprint = options['fingerprint']
        self.host = options['host']
        self.user = options['user']
        if 'b64password' in options:
            self.password = base64.b64decode(options['b64password'])
        else:
            self.password = options['password']
        self.tenant = options['tenant']
        self.token = None
        self.expiration = 0
        self.services = None

    def __call__(self, service, method, path, data=None, desired_status=200):
        # FIXME: need to "censor" tokens in auth reply and other requests
        def check_http(desired_status, path, url, resp_headers, resp_body):
            if resp_headers['_status'] != desired_status:
                log('\n%s\n' % url)
                log('%s\n' % resp_headers)
                log('%s\n' % resp_body)
                msg = '%s (%d != %d)' % (
                    resp_headers['_reason'], resp_headers['_status'],
                    desired_status)
                if resp_headers['content-type'] == 'application/json':
                    message = json.loads(resp_body).get('message')
                    if message:
                        msg = message
                raise Exception('failed API call: %s: %s' % (path, msg))
        headers = {'content-type': 'application/json'}
        if time.time() + 30 > self.expiration:
            log('+')
            auth_data = {
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": self.user,
                                "domain": {"id": "default"},
                                "password": self.password
                            }
                        }
                    },
                    "scope": {
                        "project": {
                            "name": self.tenant,
                            "domain": {"id": "default"}
                        }
                    }
                }
            }
            auth_path = '/v3/auth/tokens'
            auth_url = self.scheme + '://' + self.host + auth_path
            resp_headers, resp_body = http(
                'POST', auth_url, self.fingerprint,
                headers, json.dumps(auth_data))
            check_http(201, auth_path, auth_url, resp_headers, resp_body)
            resp_data = json.loads(resp_body)
            self.token = resp_headers['x-subject-token']
            self.expiration = (
                datetime.datetime.strptime(resp_data['token']['expires_at'],
                                           '%Y-%m-%dT%H:%M:%S.%fZ') -
                datetime.datetime.utcfromtimestamp(0)).total_seconds() - 30
            self.services = {}
            for svc in resp_data['token']['catalog']:
                for endpoint in svc['endpoints']:
                    if endpoint['interface'] == 'public':
                        self.services[svc['type']] = endpoint['url']
                        break
                else:
                    raise Exception('no public endpoint for %s' %
                                    svc['type'])
        log('.')
        headers['x-auth-token'] = self.token
        if data:
            data = json.dumps(data)
        url = self.services[service] + path
        resp_headers, resp_body = http(
            method, url, self.fingerprint, headers, data)
        check_http(desired_status, path, url, resp_headers, resp_body)
        if resp_body:
            return json.loads(resp_body)

    def retrieve_ports(self):
        ports = {}
        for port in self('network', 'GET', '/v2.0/ports.json')['ports']:
            if port['device_id'] not in ports:
                ports[port['device_id']] = []
            ports[port['device_id']].append(port)
        return ports

    def retrieve_subnets(self):
        subnets = {}
        for subnet in self('network', 'GET', '/v2.0/subnets.json')['subnets']:
            subnets[subnet['id']] = subnet
        return subnets

    def retrieve_networks(self):
        networks = {}
        for net in self('network', 'GET', '/v2.0/networks.json')['networks']:
            if net['name'] in networks:
                raise Exception('duplicate network name: "%s"' % net['name'])
            networks[net['name']] = net
        return networks

    def retrieve_instances(self):
        servers = []
        # FIXME: paging?
        for server in self('compute', 'GET', '/servers/detail')['servers']:
            if 'x-chkp-management' in server['metadata'] and server[
                    'metadata']['x-chkp-management'] == self.management:
                servers.append(server)
        return servers

    def get_instances(self):
        nova_instances = self.retrieve_instances()
        ports = self.retrieve_ports()
        subnets = self.retrieve_subnets()
        networks = self.retrieve_networks()
        instances = []
        for instance in nova_instances:
            instance_name = self.SEPARATOR.join([self.name, instance['id']])
            if instance['status'] not in ['ACTIVE', 'SUSPENDED', 'STOPPED']:
                continue
            # FIXME: assumes external interface iff has floating ip
            ip_address = None
            interfaces = []
            if len(instance['addresses']) == 1:
                net2if = {instance['addresses'].keys()[0]: 'eth0'}
            else:
                if 'x-chkp-interfaces' not in instance['metadata']:
                    raise Exception(
                        'could not find interface mapping: %s for %s' % (
                            'x-chkp-interfaces', instance_name))
                net2if = {}
                for i, net in enumerate(
                        instance['metadata']['x-chkp-interfaces'].split(',')):
                    if net:
                        net2if[net] = 'eth%d' % i
            for net in instance['addresses']:
                interface = {
                    'name': net2if[net],
                    'anti-spoofing': True,
                    'topology': 'internal'
                }
                for address in instance['addresses'][net]:
                    # FIXME: taking only the first fixed address
                    if 'ipv4-address' not in address and address[
                            'OS-EXT-IPS:type'] == 'fixed' and address[
                            'version'] == 4:
                        interface['ipv4-address'] = address['addr']
                        subnet_id = None
                        for port in ports[instance['id']]:
                            if port['network_id'] != networks[net]['id']:
                                continue
                            for fixed_ip in port['fixed_ips']:
                                if fixed_ip['ip_address'] == address['addr']:
                                    subnet_id = fixed_ip['subnet_id']
                                    break
                            if subnet_id:
                                break
                        if subnet_id:
                            cidr = subnets[subnet_id]['cidr']
                            interface['ipv4-mask-length'] = int(
                                cidr.partition('/')[2])
                        else:
                            raise Exception(
                                'could not find subnet for %s: %s' % (
                                    instance_name, address['addr']))
                    elif address['OS-EXT-IPS:type'] == 'floating':
                        ip_address = address['addr']
                        interface['topology'] = 'external'
                interfaces.append(interface)
            if not ip_address:
                ip_address = interfaces[0]['ipv4-address']
            instances.append(Instance(
                instance_name, ip_address, interfaces,
                instance['metadata']['x-chkp-template']))
        return instances


class HTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock = ssl.wrap_socket(
            self.sock, self.key_file, self.cert_file,
            cert_reqs=ssl.CERT_NONE)
        if self.fingerprint:
            alg, colon, digest = self.fingerprint.partition(':')
            fingerprint = hashlib.new(
                alg, self.sock.getpeercert(True)).hexdigest()
            if fingerprint != digest.replace(':', '').lower():
                raise Exception('fingerprint mismatch: %s' % fingerprint)


def http(method, url, fingerprint, headers, body):
    url_parts = urlparse.urlsplit(url)
    path = url_parts.path
    if url_parts.query:
        path += '?' + url_parts.query
    headers['host'] = url_parts.netloc
    headers['accept'] = '*/*'
    connection = HTTPSConnection
    if url_parts.scheme == 'http':
        connection = httplib.HTTPConnection
    with contextlib.closing(connection(url_parts.netloc)) as conn:
        conn.fingerprint = fingerprint
        debuglevel = int(os.environ.get('HTTP_DEBUG_LEVEL', '0'))
        with censor(debuglevel > 0,
                    r'send: .*"password":\s*"([^"]*)".*$', '***'):
            conn.set_debuglevel(debuglevel)
            conn.connect()
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            headers['_status'] = resp.status
            headers['_reason'] = resp.reason
            headers['_version'] = resp.version
        body = resp.read()
        if debuglevel > 1:
            log('body: %s\n' % repr(body))
    return headers, body


class Management(object):
    INSTALLED = '__installed__'

    def __init__(self, **options):
        self.host = options['host']
        self.fingerprint = options['fingerprint']
        self.user = options['user']
        if 'b64password' in options:
            self.password = base64.b64decode(options['b64password'])
        else:
            self.password = options['password']
        if 'surrogates' in options:
            self.surrogates = set(options['surrogates'])
        self.sid = None
        self.targets = {}

    def __call__(self, command, body, login=True, publish=True,
                 aggregate=None, silent=False):
        # FIXME: need to "censor" session ids in login replies and other
        #        requests
        if command == 'login':
            c = '+'
        elif command == 'logout':
            if not self.sid:
                return None
            c = '-'
        else:
            if not self.sid:
                self.__enter__()
            c = '.'
        log(c)
        debug('%s\n' % command)
        headers = {'content-type': 'application/json'}
        if command != 'login':
            headers['x-chkp-sid'] = self.sid
        objects = []
        offset = 0
        while True:
            if offset:
                body['offset'] = offset
            debug('request body\n')
            dump(body)
            resp_headers, resp_body = http(
                'POST', 'https://%s/web_api/%s' % (self.host, command),
                self.fingerprint, headers, json.dumps(body))
            dump(resp_headers)
            debug('%s\n' % resp_body)
            if resp_headers['_status'] != 200:
                if not silent:
                    log('\n%s\n' % command)
                    log('%s\n' % resp_headers)
                    log('%s\n' % resp_body)
                try:
                    msg = ': ' + json.loads(resp_body)['message']
                except Exception:
                    msg = ''
                if 'Wrong session id' in msg:
                    self.sid = None
                raise Exception('failed API call: %s%s' % (command, msg))
            if resp_body:
                payload = json.loads(resp_body)
            if payload.get('task-id'):
                # FIXME: it takes some time for the task to appear
                time.sleep(2)
                while True:
                    task = self('show-task',
                                {'task-id': payload['task-id']})['tasks'][0]
                    if task['status'] != 'INPROGRESS':
                        break
                    log('_')
                    time.sleep(2)
                if task['status'] == 'FAILED':
                    # FIXME: what about partial success and warnings
                    msg = task['task-details'][0]['stagesInfo'][0][
                        'messages'][0]['message']
                    raise Exception('%s failed: %s' % (command, msg))

            if publish and (
                    command.startswith('set-') or
                    command.startswith('add-') or
                    command.startswith('delete-') or
                    command.startswith('install-')):
                self('publish', {})
            if command == 'logout':
                self.sid = None
            if not aggregate:
                return payload
            objects += payload[aggregate]
            if payload['total'] == 0 or payload['total'] <= payload['to']:
                return objects
            offset = payload['to']

    def __enter__(self):
        # FIXME: if the polling period is longer than the session timeout
        #        we need to request a longer session or add keepalive
        try:
            resp = self('login',
                        {'user': self.user, 'password': self.password})
            self.sid = resp['sid']
            return self
        except:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, type, value, tb):
        try:
            if self.sid:
                self('discard', {})
                self('logout', {})
        except Exception:
            log('%s' % traceback.format_exc())

    def get_gateways(self):
        objects = self('show-simple-gateways', {}, aggregate='objects')
        gateways = {}
        for name in (o['name'] for o in objects):
            try:
                gw = self('show-simple-gateway', {'name': name}, silent=True)
            except Exception:
                # FIXME: remove when all gateways are able to show
                if str(sys.exc_info()[1]).endswith(
                        'Runtime error: Unmarshalling Error: Unable to ' +
                        'create an instance of com.checkpoint.management.' +
                        'dlecommon.ngm_api.CpmiOwned '):
                    continue
                else:
                    raise
            if TAG not in self.get_gateway_tags(gw):
                continue
            gateways[gw['name']] = gw
            if hasattr(self, 'surrogates'):
                if 'ipv4-address' in gw:
                    self.surrogates.discard(gw['ipv4-address'])
        if hasattr(self, 'surrogates'):
            log('\navailable surrogates: ' + ', '.join(list(self.surrogates)))
        return gateways

    def get_gateway_tags(self, gw):
        tags = []
        comments = gw.get('comments', '')
        match = re.match(r'.*\{tags=([^}]*)\}.*$', comments)
        if match and match.group(1):
            tags = match.group(1).split('|')
        return tags

    def put_gateway_tags(self, gw, tags):
        comments = gw.get('comments', '')
        match = re.match(r'([^{]*)(\{tags=[^}]*\})?(.*)$', comments)
        gw['comments'] = match.group(1) + (
            '{tags=%s}' % '|'.join(tags)) + match.group(3)

    def add_gateway_tags(self, name, tags):
        gw = self('show-simple-gateway', {'name': name})
        tag_list = self.get_gateway_tags(gw)
        tag_set = set(tag_list)
        for t in tags:
            if t not in tag_set:
                tag_list.append(t)
                tag_set.add(t)
        self.put_gateway_tags(gw, tag_list)
        self('set-simple-gateway', {'name': name, 'comments': gw['comments']})

    def gw2str(self, gw):
        return ' '.join([gw['name'],
                        '|'.join(self.get_gateway_tags(gw)),
                         self.targets.get(gw['name'], '-')])

    def dbedit(self, cmds, update=True):
        cmds = cmds[:]
        if update:
            cmds.append('update_all')
        cmds.append('')
        p = subprocess.Popen(
            ['dbedit', '-local', '-f', '/dev/fd/0'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, err = p.communicate('\n'.join(cmds))
        return out, err

    def set_proxy(self, name, proxy_ports):
        path = 'network_objects %s' % name
        if not proxy_ports:
            self.dbedit(['modify %s proxy_on_gw_enabled false' % path])
            return
        out, err = self.dbedit(['printxml %s' % path], update=False)
        doc = xml.dom.minidom.parseString(out)
        port_count = len(
            doc.getElementsByTagName(
                'proxy_on_gw_settings')[0].getElementsByTagName(
                    'ports')[0].getElementsByTagName(
                        'unnamed_element'))
        for i in xrange(port_count):
            self.dbedit(['rmbyindex %s proxy_on_gw_settings:ports 0' % path])
        cmds = [
            'modify %s proxy_on_gw_enabled true' % path,
            'modify %s proxy_on_gw_settings:interfaces_type all_interfaces'
            % path,
            'modify %s proxy_on_gw_settings:tarnsparent_mode false' % path]
        for port in proxy_ports:
            cmds.append('addelement %s proxy_on_gw_settings:ports %s' %
                        (path, port))
        self.dbedit(cmds)

    def update_targets(self):
        """map instance name to a policy where it is an install target"""
        policy_summaries = self('show-packages', {},
                                aggregate='packages')
        targets = {}
        for summary in policy_summaries:
            policy_name = summary['name']
            policy = self('show-package', {'name': policy_name})
            if policy['installation-targets'] == 'all':
                continue
            for target in policy['installation-targets']:
                targets[target['name']] = policy_name
        self.targets = targets

    def set_policy(self, name, policy):
        old_policy = None
        if name in self.targets:
            old_policy = self.targets[name]
        if old_policy:
            self('set-package', {
                'name': old_policy,
                'installation-targets': {'remove': name}})
            del self.targets[name]
        if not policy:
            return

        self('set-package', {
            'name': policy,
            'installation-targets': {'add': name}})
        self.targets[name] = policy

        self('install-policy', {
            'policy-package': policy, 'targets': name})

        self.add_gateway_tags(name, [self.INSTALLED])

    def delete_gateway(self, name):
        log('\ndeleting: %s' % name)
        self.set_policy(name, None)
        if hasattr(self, 'surrogates'):
            ip_address = self(
                'show-simple-gateway', {'name': name})['ipv4-address']
        self('delete-simple-gateway', {'name': name})
        if hasattr(self, 'surrogates'):
            log('\nfreeing: %s' % ip_address)
            self.surrogates.add(ip_address)

    def add_gateway(self, instance, exists):
        log('\n%s: %s' % ('updating' if exists else 'creating', instance.name))
        simple_gateway = Template.get_dict(instance.template)
        tags = simple_gateway.pop('tags', [])
        proxy_ports = simple_gateway.pop('proxy-ports', None)
        policy = simple_gateway.pop('policy')
        # FIXME: network info is not updated once the gateway exists
        if not exists:
            if hasattr(self, 'surrogates'):
                ip_address = self.surrogates.pop()
                log('\nusing: %s' % ip_address)
                subprocess.check_call([
                    'ssh', 'admin@' + ip_address, 'bash', '-c',
                    '"cp_conf sic init %s </dev/null"' % (
                        simple_gateway['one-time-password'])])
            else:
                ip_address = instance.ip_address
            simple_gateway['name'] = instance.name
            simple_gateway['ip-address'] = ip_address
            simple_gateway['interfaces'] = instance.interfaces
            if len(simple_gateway['interfaces']) == 1:
                simple_gateway['interfaces'][0]['anti-spoofing'] = False
            self.put_gateway_tags(
                simple_gateway, tags + [TAG, instance.template])
            try:
                self('add-simple-gateway', simple_gateway)
            except:
                if hasattr(self, 'surrogates'):
                    log('\nfreeing: %s' % ip_address)
                    self.surrogates.add(ip_address)
                raise
        self.set_proxy(instance.name, proxy_ports)
        self.set_policy(instance.name, policy)


def set_state(state, name, status):
    if name:
        log('\n%s: %s' % (name, status))
    if status:
        state[name] = status
    elif name in state:
        del state[name]
    with open(STATE_FILE, 'w') as f:
        json.dump([{'name': n, 'status': state[n]} for n in state], f)


def is_SIC_open(instance):
    with contextlib.closing(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(3)
        if s.connect_ex((instance.ip_address, 18211)):
            return False
        time.sleep(5)
        return True


def sync(controller, management, gateways, state):
    log('\n' + controller.name)
    instances = {}
    for instance in controller.get_instances():
        instances[instance.name] = instance
    log('\n' + '\n'.join([str(instances[i]) for i in instances] + ['']))
    filtered_gateways = set(name for name in gateways
                            if name.startswith(
                                controller.name + Controller.SEPARATOR))
    for name in filtered_gateways - set(instances):
        try:
            set_state(state, name, 'DELETING')
            management.delete_gateway(name)
        except Exception:
            log('%s' % traceback.format_exc())
        finally:
            set_state(state, name, None)

    for name in set(instances):
        exists = name in gateways
        if exists and management.INSTALLED in (
                management.get_gateway_tags(gateways[name])):
            set_state(state, name, 'COMPLETE')
            continue

        if not exists:
            if not is_SIC_open(instances[name]):
                set_state(state, name, 'INITIALIZING')
                continue

        try:
            set_state(state, name, 'ADDING')
            management.add_gateway(instances[name], exists)
            set_state(state, name, 'COMPLETE')
        except Exception:
            log('%s' % traceback.format_exc())
            try:
                set_state(state, name, 'RESETTING')
                management.delete_gateway(name)
            except Exception:
                log('%s' % traceback.format_exc())
            finally:
                set_state(state, name, None)


def loop(management, controllers, delay):
    state = {}
    set_state(state, None, None)
    while True:
        try:
            management.update_targets()
            gateways = management.get_gateways()
            log('\ngateways (before):\n')
            log('\n'.join(
                [management.gw2str(gateways[gw]) for gw in gateways] + ['']))
            for c in controllers:
                try:
                    sync(c, management, gateways, state)
                except Exception:
                    log('%s' % traceback.format_exc())
            log('\n')
            gateways = management.get_gateways()
            log('\ngateways (after):\n')
            log('\n'.join(
                [management.gw2str(gateways[gw]) for gw in gateways] + ['']))
        except Exception:
            log('%s' % traceback.format_exc())
        log('\n')
        time.sleep(delay)


@contextlib.contextmanager
def web_server(port):
    if not int(port):
        yield
        return
    sudo = []
    if int(port) < 1024:
        sudo = ['sudo']
    server = subprocess.Popen(
        sudo + [sys.executable, '-m', 'SimpleHTTPServer', port],
        cwd=WEB_DIR)
    yield
    server.terminate()
    time.sleep(1)
    if not server.poll():
        server.kill()


def main(argv=None):
    global conf

    parser = argparse.ArgumentParser(prog=argv[0] if argv else None)
    parser.add_argument('config', metavar='CONFIG',
                        help='@JSON-FILE or a literal json expression')
    parser.add_argument('-p', '--port', metavar='PORT', default='0',
                        help='Listening port for the web server')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    args = parser.parse_args(argv[1:] if argv else None)

    if args.config[0] == '@':
        with open(args.config[1:]) as f:
            conf = json.load(f, object_pairs_hook=collections.OrderedDict)
    else:
        conf = json.loads(args.config,
                          object_pairs_hook=collections.OrderedDict)

    if args.debug:
        conf['debug'] = True

    for t in conf['templates']:
        Template(t, **conf['templates'][t])
    controllers = []
    for c in conf['controllers']:
        controller = conf['controllers'][c]
        controllers += [globals()[controller['class']](
            name=c, management=conf['management']['name'], **controller)]
    with web_server(args.port):
        with Management(**conf['management']) as management:
            loop(management, controllers, conf['delay'])


if __name__ == '__main__':
    main()
