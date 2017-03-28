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
import email.utils
import fcntl
import hashlib
import httplib
import json
import logging
import logging.handlers
import os
import os.path
import random
import re
import signal
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib
import urlparse

import aws
import azure
import gcp

TAG = 'managed-virtual-gateway'

conf = collections.OrderedDict()
log_buffer = [None]


def log(msg, level=logging.INFO):
    logger = conf.get('logger')
    if logger:
        current_level = log_buffer[0]
        if current_level != level:
            line = ''.join(log_buffer[1:])
            del log_buffer[:]
            log_buffer.append(level)
            if line:
                logger.log(current_level, line)
        if '\n' not in msg:
            if msg:
                log_buffer.append(msg)
            return
        lines = msg.split('\n')
        lines[0] = ''.join(log_buffer[1:]) + lines[0]
        if current_level != level and not lines[0]:
            lines.pop(0)
        del log_buffer[:]
        log_buffer.append(level)
        last = lines.pop()
        if last:
            log_buffer.append(last)
        for line in lines:
            logger.log(level, '%s', line)
    else:
        sys.stderr.write(msg)


def progress(msg):
    if conf.get('logger'):
        log('', level=None)
    else:
        log(msg)


def debug(msg):
    if conf.get('debug'):
        log(msg, level=logging.DEBUG)


def dump(obj):
    debug('%s\n' % json.dumps(obj, indent=2))


# avoid printing sensitive data
@contextlib.contextmanager
def censor(active, log, pattern, replacement):
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
            self.template, json.dumps(getattr(self, 'load_balancers', None))])


class Controller(object):
    SEPARATOR = '--'

    def __init__(self, **options):
        self.name = options['name']
        self.management = options['management']
        self.templates = options.get('templates', [])

    def get_instances(self):
        raise Exception('not implemented')

    def filter_instances(self):
        return [i for i in self.get_instances()
                if not self.templates or i.template in self.templates]

    @staticmethod
    @contextlib.contextmanager
    def Tester(cls, **options):
        controller = cls(**options)
        yield controller
        instances = controller.filter_instances()
        log('\n'.join([''] + [str(i) for i in instances] + ['']))

    @staticmethod
    def test(cls, **options):
        with Controller.Tester(cls, **options) as controller:
            controller  # do nothing but keep pyflakes happy


class AWS(Controller):
    def __init__(self, **options):
        super(AWS, self).__init__(**options)
        self.aws = aws.AWS(
            key=options.get('access-key'), secret=options.get('secret-key'),
            token=options.get('session-token'),
            key_file=options.get('cred-file'))
        self.regions = options['regions']

    def request(self, service, *args, **kwargs):
        headers, body = self.aws.request(service, *args, **kwargs)
        if headers.get('_code') == '200':
            return headers, body
        error = None
        code = None
        if headers.get('_parsed'):
            if 'Errors' in body:
                errors = aws.listify(body['Errors'], 'Error')
            else:
                errors = [body.get('Error')]
            error = errors[0] if errors else {}
            code = error.get('Code')
        if not error or not code:
            raise Exception('UnparsedError: %s (%s)' % (
                headers.get('_reason', '-'), headers.get('_code', '-')))
        raise Exception('%s: %s' % (code, error.get('Message', '-')))

    def retrieve_subnets(self):
        subnets = {}
        for region in self.regions:
            subnets[region] = {}
            headers, body = self.request(
                'ec2', region, 'GET', '/?Action=DescribeSubnets', '')
            for s in aws.listify(body, 'item')['subnetSet']:
                subnets[region][s['subnetId']] = s
        return subnets

    def retrieve_interfaces(self):
        interfaces = {}
        for region in self.regions:
            interfaces[region] = {}
            headers, body = self.request(
                'ec2', region, 'GET',
                '/?Action=DescribeNetworkInterfaces', '')
            for i in aws.listify(body, 'item')['networkInterfaceSet']:
                interfaces[region][i['networkInterfaceId']] = i
        return interfaces

    def retrieve_classic_lbs(self, region, subnets, auto_scaling_groups,
                             by_template, by_instance):
        i2lb_names = {}
        lb_name2cidrs = {}
        headers, body = self.request(
            'elasticloadbalancing', region, 'GET',
            '/?Action=DescribeLoadBalancers', '')
        elb_list = aws.listify(body['DescribeLoadBalancersResult'][
            'LoadBalancerDescriptions'], 'member')
        for elb in elb_list:
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?Action=DescribeTags&LoadBalancerNames.member.1=' +
                elb['LoadBalancerName'], '')
            tags = self.get_tags(aws.listify(
                body['DescribeTagsResult']['TagDescriptions'],
                'member')[0]['Tags'])
            cidrs = [subnets[s]['cidrBlock'] for s in elb['Subnets']]
            dns_name = elb['DNSName']
            front_protocol_ports = []
            back_protocol_ports = []
            for listener in elb['ListenerDescriptions']:
                front_protocol_ports.append('%s-%s' % (
                    listener['Listener']['Protocol'],
                    listener['Listener']['LoadBalancerPort']))
                back_protocol_ports.append('%s-%s' % (
                    listener['Listener']['InstanceProtocol'],
                    listener['Listener']['InstancePort']))
            if tags.get('x-chkp-management') == self.management:
                template = tags.get('x-chkp-template')
                ignore_ports = tags.get('x-chkp-ignore-ports', [])
                if ignore_ports:
                    ignore_ports = set(ignore_ports.split(':'))
                front_protocol_ports = [
                    pp for pp in front_protocol_ports
                    if pp.split('-')[1] not in ignore_ports]
                by_template.setdefault(template, {})
                by_template[template][dns_name] = front_protocol_ports
            lb_name = elb['LoadBalancerName']
            for i in elb['Instances']:
                i2lb_names.setdefault(i['InstanceId'], set()).add(
                    elb['LoadBalancerName'])
            lb_name2cidrs.setdefault(lb_name, {})
            for protocol_port in back_protocol_ports:
                lb_name2cidrs[lb_name][protocol_port] = cidrs

        for group in auto_scaling_groups:
            for i in group['Instances']:
                i2lb_names.setdefault(i['InstanceId'], set()).update(
                    group['LoadBalancerNames'])

        for i in i2lb_names:
            by_instance.setdefault(i, {})
            for lb_name in i2lb_names[i]:
                for protocol_port in lb_name2cidrs.get(lb_name, {}):
                    by_instance[i].setdefault(protocol_port, []).extend(
                        lb_name2cidrs[lb_name].get(protocol_port, []))

    def retrieve_application_lbs(self, region, subnets, auto_scaling_groups,
                                 by_template, by_instance):
        i2target_groups = {}
        for auto_scale_group in auto_scaling_groups:
            for i in auto_scale_group['Instances']:
                for target in auto_scale_group['TargetGroupARNs']:
                    i2target_groups.setdefault(i['InstanceId'], {}).setdefault(
                        target, set())

        headers, body = self.request(
            'elasticloadbalancing', region, 'GET',
            '/?Version=2015-12-01&Action=DescribeTargetGroups', '')
        target_groups = aws.listify(body['DescribeTargetGroupsResult'][
            'TargetGroups'], 'member')
        for target_group in target_groups:
            default_protocol = '%s-' % target_group['Protocol']
            default_protocol_port = default_protocol + target_group['Port']
            for i in i2target_groups:
                if target_group['TargetGroupArn'] in i2target_groups[i]:
                    i2target_groups[i][target_group['TargetGroupArn']].add(
                        default_protocol_port)
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?' + urllib.urlencode({
                    'Version': '2015-12-01',
                    'Action': 'DescribeTargetHealth',
                    'TargetGroupArn': target_group['TargetGroupArn']}), '')
            targets = aws.listify(body['DescribeTargetHealthResult'][
                'TargetHealthDescriptions'], 'member')
            for target in targets:
                i2target_groups.setdefault(
                    target['Target']['Id'], {}).setdefault(
                        target_group['TargetGroupArn'], set()).add(
                            default_protocol + target['Target']['Port'])

        headers, body = self.request(
            'elasticloadbalancing', region, 'GET',
            '/?Version=2015-12-01&Action=DescribeLoadBalancers', '')
        alb_list = aws.listify(body['DescribeLoadBalancersResult'][
            'LoadBalancers'], 'member')
        dns_name2cidrs = {}
        target_group2dns_names = {}
        for alb in alb_list:
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?' + urllib.urlencode({
                    'Version': '2015-12-01',
                    'Action': 'DescribeTags',
                    'ResourceArns.member.1': alb['LoadBalancerArn']}), '')
            tags = self.get_tags(aws.listify(
                body['DescribeTagsResult']['TagDescriptions'],
                'member')[0]['Tags'])
            dns_name = alb['DNSName']
            cidrs = [
                subnets[az['SubnetId']]['cidrBlock']
                for az in alb['AvailabilityZones']]
            dns_name2cidrs.setdefault(dns_name, []).extend(cidrs)
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?' + urllib.urlencode({
                    'Version': '2015-12-01',
                    'Action': 'DescribeListeners',
                    'LoadBalancerArn': alb['LoadBalancerArn']}), '')
            listeners = aws.listify(
                body['DescribeListenersResult']['Listeners'], 'member')
            front_protocol_ports = []
            for listener in listeners:
                front_protocol_ports.append('%s-%s' % (
                    listener['Protocol'], listener['Port']))
                headers, body = self.request(
                    'elasticloadbalancing', region, 'GET',
                    '/?' + urllib.urlencode({
                        'Version': '2015-12-01',
                        'Action': 'DescribeRules',
                        'ListenerArn': listener['ListenerArn']}), '')
                rules = aws.listify(
                    body['DescribeRulesResult']['Rules'], 'member')
                for rule in rules:
                    for action in rule['Actions']:
                        target_group2dns_names.setdefault(
                            action['TargetGroupArn'], set()).add(dns_name)
            if tags.get('x-chkp-management') == self.management:
                template = tags.get('x-chkp-template')
                ignore_ports = tags.get('x-chkp-ignore-ports', [])
                if ignore_ports:
                    ignore_ports = set(ignore_ports.split(':'))
                front_protocol_ports = [
                    pp for pp in front_protocol_ports
                    if pp.split('-')[1] not in ignore_ports]
                by_template.setdefault(template, {})
                by_template[template][dns_name] = front_protocol_ports

        for i in i2target_groups:
            by_instance.setdefault(i, {})
            for target_group in i2target_groups[i]:
                for protocol_port in i2target_groups[i][target_group]:
                    for dns_name in target_group2dns_names.get(
                            target_group, set()):
                        by_instance[i].setdefault(protocol_port, []).extend(
                            dns_name2cidrs[dns_name])

    def retrieve_elbs(self, subnets):
        by_template = {}
        by_instance = {}
        for region in self.regions:
            by_template[region] = {}
            by_instance[region] = {}
            headers, body = self.request(
                'autoscaling', region, 'GET',
                '/?Action=DescribeAutoScalingGroups', '')
            auto_scaling_groups = aws.listify(
                body['DescribeAutoScalingGroupsResult']['AutoScalingGroups'],
                'member')
            self.retrieve_classic_lbs(
                region, subnets[region], auto_scaling_groups,
                by_template[region], by_instance[region])
            self.retrieve_application_lbs(
                region, subnets[region], auto_scaling_groups,
                by_template[region], by_instance[region])
        return {'by-template': by_template, 'by-instance': by_instance}

    def retrieve_all(self, region, path, top_set, collect_set):
        objects = []
        next_token = None
        while True:
            extra_params = ''
            if next_token:
                extra_params += '&' + urllib.urlencode({
                    'NextToken', next_token})
            headers, body = self.request(
                'ec2', region, 'GET', path + extra_params, '')
            obj = aws.listify(body, 'item')
            for r in obj[top_set]:
                objects += r[collect_set]
            next_token = obj.get('nextToken')
            if not next_token:
                break
        return objects

    def retrieve_instances(self):
        instances = {}
        for region in self.regions:
            instances[region] = self.retrieve_all(
                region,
                '/?Action=DescribeInstances' +
                '&Filter.1.Name=tag-key&Filter.1.Value=x-chkp-management',
                'reservationSet', 'instancesSet')
            instances[region] += self.retrieve_all(
                region,
                '/?Action=DescribeInstances' +
                '&Filter.2.Name=tag-key&Filter.2.Value=x-chkp-tags',
                'reservationSet', 'instancesSet')
            instances[region] = [
                i for i in instances[region]
                if self.get_tags(i['tagSet']).get(
                    'x-chkp-management') == self.management]
        return instances

    def get_tags(self, tag_list):
        tags = collections.OrderedDict()
        for t in tag_list:
            tags[t.get('key', t.get('Key'))] = t.get(
                'value', t.get('Value', ''))
        joined_tags = tags.get('x-chkp-tags')
        if joined_tags:
            for part in joined_tags.split(':'):
                key, es, value = part.partition('=')
                tags.setdefault('x-chkp-' + key, value)
        return tags

    def get_topology(self, eni, subnets):
        tags = self.get_tags(eni['tagSet'])
        topology = tags.get('x-chkp-topology', '').lower()
        anti_spoofing = (tags.get('x-chkp-anti-spoofing', 'true').lower() ==
                         'true')
        if not topology:
            if eni.get('association', {}).get('publicIp') or (
                    eni['attachment']['deviceIndex'] == '0'):
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

        return interface

    def get_instances(self):
        ec2_instances = self.retrieve_instances()
        enis = self.retrieve_interfaces()
        subnets = self.retrieve_subnets()
        elbs = self.retrieve_elbs(subnets)
        instances = []
        for region in self.regions:
            for instance in ec2_instances[region]:
                interfaces = []
                instance_name = self.SEPARATOR.join(
                    [self.name, instance['instanceId'], region])
                if instance['instanceState']['name'] in {
                        'shutting-down', 'terminated'}:
                    continue

                tags = self.get_tags(instance['tagSet'])
                ip_address = tags.get('x-chkp-ip-address', 'public')

                if ip_address == 'private':
                    ip_address = instance['privateIpAddress']
                elif ip_address == 'public':
                    ip_address = instance.get('ipAddress')

                if not ip_address:
                    log('no ip address for %s\n' % instance_name)
                    continue

                for interface in sorted(
                        instance['networkInterfaceSet'],
                        key=lambda i: int(i['attachment']['deviceIndex'])):
                    interfaces.append(self.get_topology(
                        enis[region][interface['networkInterfaceId']],
                        subnets[region]))

                instance_obj = Instance(
                    instance_name, ip_address, interfaces,
                    tags['x-chkp-template'])
                load_balancers = {}
                internal_elbs = elbs['by-template'].get(
                    region, {}).get(instance_obj.template, {})
                external_elbs = elbs['by-instance'].get(region, {}).get(
                    instance['instanceId'], {})
                for dns_name in internal_elbs:
                    for protocol_port in internal_elbs[dns_name]:
                        load_balancers.setdefault(
                            dns_name, {})[protocol_port] = external_elbs.get(
                                protocol_port, [])
                instance_obj.load_balancers = load_balancers
                instances.append(instance_obj)
        return instances

    @staticmethod
    def test(cls, **options):
        for key in ['regions']:
            if key not in options or not options[key]:
                raise Exception('The parameter "%s" is missing or empty' % key)
        if not isinstance(options['regions'], list):
            raise Exception('The parameter "regions" should be an array')
        url = ''.join([
            'https://', aws.get_host_service('ec2', options['regions'][0])[0],
            '/'])
        h, b = aws.http('GET', url, '')
        d = h.get('date')
        t1 = datetime.datetime(*email.utils.parsedate(d)[:6])
        t2 = datetime.datetime.utcnow()
        log('\nTime difference is ' + str(abs(t2 - t1)) + '\n')
        if abs(t2 - t1) > datetime.timedelta(seconds=5):
            raise Exception(
                'Your system clock is not accurate, please set up NTP')

        Controller.test(cls, **options)


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
            progress('+')
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
        progress('.')
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


class Azure(Controller):
    def __init__(self, **options):
        super(Azure, self).__init__(**options)
        self.sub = '/subscriptions/' + options['subscription']
        self.azure = azure.Azure(subscription=options['subscription'],
                                 environment=options.get('environment'),
                                 credentials=options.get('credentials'))

    def retrieve_vms_and_interfaces(self):
        vms = {}
        interfaces = {}
        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Compute/virtualMachines' % self.sub)
        for vm in body['value']:
            if vm.get('tags', {}).get(
                    'x-chkp-management') != self.management:
                continue
            vm = self.azure.arm(
                'GET', vm['id'] + '/?$expand=instanceView')[1]
            vms[vm['id']] = vm

        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Network/networkInterfaces' % self.sub)
        for interface in body['value']:
            interfaces[interface['id']] = interface

        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Compute/virtualMachineScaleSets' %
            self.sub)
        for vmss in body['value']:
            if vmss.get('tags', {}).get(
                    'x-chkp-management') != self.management:
                continue
            vmss_vms = self.azure.arm(
                'GET', vmss['id'] +
                '/virtualMachines/?$expand=instanceView')[1]['value']
            for vm in vmss_vms:
                vms[vm['id']] = vm

            for interface in self.azure.arm(
                    'GET', vmss['id'] + '/networkInterfaces')[1]['value']:
                interface.setdefault('tags', {})
                interface['tags'].setdefault(
                    'x-chkp-topology',
                    vmss.get('tags', {}).get('x-chkp-topology', 'external'))
                interfaces[interface['id']] = interface

        return vms, interfaces

    def retrieve_interfaces(self):
        interfaces = {}
        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Network/networkInterfaces' % self.sub)
        for interface in body['value']:
            interfaces[interface['id']] = interface

        return interfaces

    def retrieve_public_addresses(self):
        addresses = {}
        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Network/publicIpAddresses' % self.sub)
        for address in body['value']:
            addresses[address['id']] = address
        return addresses

    def retrieve_subnets(self):
        subnets = {}
        headers, body = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Network/virtualNetworks' % self.sub)
        for vnet in body['value']:
            for subnet in vnet['properties'].get('subnets', []):
                subnets[subnet['id']] = subnet
        return subnets

    def get_primary_configuration(self, interface):
        configurations = interface['properties']['ipConfigurations']
        for configuration in configurations:
            if configuration['properties'].get('primary'):
                break
        else:
            if len(configurations) != 1:
                log('no primary configuration for %s\n' % interface['id'])
                return None
            configuration = configurations[0]
        return configuration['properties']

    def get_topology(self, index, tags, configuration, subnets):
        topology = tags.get('x-chkp-topology', '').lower()
        anti_spoofing = (tags.get('x-chkp-anti-spoofing', 'true').lower() ==
                         'true')
        if not topology:
            if configuration.get('publicIPAddress') or index == 0:
                topology = 'external'
            else:
                topology = 'internal'

        interface = {
            'name': 'eth%s' % index,
            'ipv4-address': configuration['privateIPAddress'],
            'ipv4-mask-length':
                int(subnets[configuration['subnet']['id']]['properties'][
                    'addressPrefix'].partition('/')[2]),
            'anti-spoofing': anti_spoofing,
            'topology': topology
        }

        return interface

    def get_instances(self):
        vms, interfaces = self.retrieve_vms_and_interfaces()
        public_addresses = self.retrieve_public_addresses()
        subnets = self.retrieve_subnets()
        instances = []
        for vm in vms.values():
            instance_name = self.SEPARATOR.join([
                self.name, vm['name'], vm['id'].split('/')[4]])
            tags = vm.get('tags', {})

            instance_interfaces = []
            ip_address = tags.get('x-chkp-ip-address', 'public')
            for index, interface in enumerate(
                    vm['properties']['networkProfile']['networkInterfaces']):
                interface = interfaces[interface['id']]
                configuration = self.get_primary_configuration(interface)
                if not configuration:
                    instance_interfaces = []
                    break
                instance_interfaces.append(self.get_topology(
                    index, interface.get('tags', {}), configuration, subnets))
                if interface['properties'].get('primary'):
                    if ip_address == 'private':
                        ip_address = configuration['privateIPAddress']
                    elif ip_address == 'public':
                        ip_address = public_addresses.get(
                            configuration.get('publicIPAddress', {}).get(
                                'id'), {}).get('properties', {}).get(
                                    'ipAddress')
            if not instance_interfaces:
                log('problem in retrieving interfaces for %s\n' %
                    instance_name)
                continue
            if not ip_address or ip_address == 'public':
                log('no ip address for %s\n' % instance_name)
                continue

            instances.append(Instance(
                instance_name, ip_address, instance_interfaces,
                tags['x-chkp-template']))
        return instances

    @staticmethod
    def test(cls, **options):
        for key in ['subscription', 'credentials']:
            if key not in options or not options[key]:
                raise Exception('The parameter "%s" is missing or empty' % key)

        with Controller.Tester(cls, **options) as controller:
            try:
                controller.azure.arm(
                    'GET', '/subscriptions/' + options['subscription'])
            except azure.RequestException as e:
                if e.code == 401 or 'unauthorized_client' in e.body or (
                        'invalid_grant' in e.body or
                        'unsupported_grant_type' in e.body or
                        'No service namespace named ' in e.body or
                        'The request body must contain the '
                        'following parameter: \'grant_type\'' in e.body):
                    log('\n%s' % traceback.format_exc())
                    raise Exception('Bad credentials')
                elif e.code == 403:
                    log('\n%s' % traceback.format_exc())
                    raise Exception('The credentials were not authorized '
                                    'for any resource in the subscription')
                else:
                    raise


class GCP(Controller):
    def __init__(self, **options):
        super(GCP, self).__init__(**options)
        self.project = options['project']
        self.gcp = gcp.GCP(
            project=options['project'], credentials=options.get('credentials'))

    def retrieve_aggregated(self, what):
        h, body = self.gcp.rest(
            'GET', '/projects/%s/aggregated/%s' % (self.project, what),
            aggregate=True)
        objs = sum([body[key].get(what, []) for key in body], [])
        return collections.OrderedDict([
            (obj['selfLink'], obj) for obj in objs])

    def get_tags(self, obj):
        tags = collections.OrderedDict()
        for t in obj.get('tags', {}).get('items', []):
            k, _, v = t.partition(self.SEPARATOR)
            tags[k] = v
        return tags

    def get_topology(self, index, instance, subnets):
        interface = instance['networkInterfaces'][index]
        name = 'eth%s' % index
        tags = self.get_tags(instance)
        tags = {
            k[:-len(name) - 1]: tags[k]
            for k in tags if k.endswith('-%s' % name)}
        topology = tags.get('x-chkp-topology', '').lower()
        anti_spoofing = (tags.get('x-chkp-anti-spoofing', 'true').lower() ==
                         'true')
        if not topology:
            access_configs = interface.get('accessConfigs', [])
            if access_configs or index == 0:
                topology = 'external'
            else:
                topology = 'internal'

        instance_interface = {
            'name': name,
            'ipv4-address': interface['networkIP'],
            'ipv4-mask-length': subnets[interface['subnetwork']][
                'ipCidrRange'].partition('/')[2],
            'anti-spoofing': anti_spoofing,
            'topology': topology
        }
        return instance_interface

    def get_instances(self):
        gcp_instances = self.retrieve_aggregated('instances')
        subnets = self.retrieve_aggregated('subnetworks')
        instances = []
        for instance in gcp_instances.values():
            tags = self.get_tags(instance)
            if tags.get('x-chkp-management') != self.management:
                continue
            instance_name = self.SEPARATOR.join([self.name, instance['name']])
            instance_interfaces = []
            ip_address = None
            for index, interface in enumerate(instance['networkInterfaces']):
                instance_interfaces.append(self.get_topology(
                    index, instance, subnets))
                if not ip_address:
                    ip_address = tags.get('x-chkp-ip-address', 'public')
                    if ip_address == 'private':
                        ip_address = interface['networkIP']
                    elif ip_address == 'public':
                        access_configs = interface.get('accessConfigs', [])
                        if access_configs:
                            ip_address = access_configs[0]['natIP']
            if not instance_interfaces:
                log('problem in retrieving interfaces for %s\n' %
                    instance_name)
                continue
            if not ip_address or ip_address == 'public':
                log('no ip address for %s\n' % instance_name)
                continue

            instances.append(Instance(
                instance_name, ip_address, instance_interfaces,
                tags['x-chkp-template']))
        return instances

    @staticmethod
    def test(cls, **options):
        for key in ['project', 'credentials']:
            if key not in options or not options[key]:
                raise Exception('The parameter "%s" is missing or empty' % key)

        Controller.test(cls, **options)


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
        debuglevel = 2 if conf.get('debug') else 0
        with censor(debuglevel > 0, debug,
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
            debug('body: %s\n' % repr(body))
    return headers, body


class Management(object):
    IN_PROGRESS = 'in progress'
    FAILED = 'failed'
    SUCCEEDED = 'succeeded'
    LOCALHOST = {'127.0.0.1', 'localhost'}
    TEMPLATE_PREFIX = '__template__'
    GENERATION_PREFIX = '__generation__'
    LOAD_BALANCER_PREFIX = '__load_balancer__'
    MONITOR_PREFIX = '__monitor__-'
    DUMMY_PREFIX = MONITOR_PREFIX + 'dummy-'
    SECTION = MONITOR_PREFIX + 'section'
    GATEWAY_PREFIX = '__gateway__'

    CPMI_IDENTITY_AWARE_BLADE = (
        'com.checkpoint.objects.classes.dummy.CpmiIdentityAwareBlade')
    CPMI_PORTAL_SETTINGS = (
        'com.checkpoint.objects.classes.dummy.CpmiPortalSettings')
    CPMI_REALM_BLADE_ENTRY = (
        'com.checkpoint.objects.classes.dummy.CpmiRealmBladeEntry')
    CPMI_REALM_FETCH_OPTIONS = (
        'com.checkpoint.objects.realms_schema.dummy.CpmiRealmFetchOptions')
    CPMI_REALM_AUTHENTICATION = (
        'com.checkpoint.objects.realms_schema.dummy.CpmiRealmAuthentication')
    CPMI_REALM_AUTH_SCHEME = (
        'com.checkpoint.objects.realms_schema.dummy.CpmiRealmAuthScheme')
    CPMI_LOGICAL_SERVER = (
        'com.checkpoint.objects.classes.dummy.CpmiLogicalServer')

    BAD_SESSION_PATTERNS = [
        re.compile(r'.*Wrong session id'),
        re.compile(r'.* locked[: ]'),
        re.compile(r'.* has no permission '),
        re.compile(r'.*Operation is not allowed in read only mode')]

    def __init__(self, **options):
        self.name = options['name']
        self.host = options['host']
        self.domain = options.get('domain')
        self.fingerprint = options.get('fingerprint', '')
        self.user = options.get('user')
        self.password = options.get(
            'password', base64.b64decode(options.get('b64password', '')))
        if self.host.partition(':')[0] not in self.LOCALHOST:
            if not self.user or not self.password:
                raise Exception('Missing credentials for management user')
        self.custom_script = options.get('custom-script')
        self.auto_publish = True
        self.sid = None
        self.targets = {}
        if 'proxy' in options:
            os.environ['https_proxy'] = options['proxy']

        no_proxy = set(os.environ.get('no_proxy', '').split(','))
        no_proxy -= {''}
        no_proxy |= {'127.0.0.1', 'localhost'}
        os.environ['no_proxy'] = ','.join(no_proxy)

    def __call__(self, command, body, login=True, aggregate=None,
                 silent=False):
        # FIXME: need to "censor" session ids in login replies and other
        #        requests
        if command == 'login':
            c = '+'
        elif command == 'logout':
            if not self.sid:
                return None
            c = '-'
        elif command == 'publish':
            c = '|'
        else:
            if not self.sid:
                self.__enter__()
            c = '.'
        progress(c)
        debug('%s\n' % command)
        headers = {'content-type': 'application/json'}
        if command != 'login':
            headers['x-chkp-sid'] = self.sid
        objects = []
        offset = 0
        while True:
            if offset:
                body['offset'] = offset
            if aggregate:
                body['limit'] = 500
            resp_headers, resp_body = http(
                'POST', 'https://%s/web_api/%s' % (self.host, command),
                self.fingerprint, headers, json.dumps(body))
            if resp_headers['_status'] != 200:
                if not silent:
                    log('\n%s\n' % command)
                    log('%s\n' % resp_headers)
                    log('%s\n' % resp_body)
                try:
                    msg = ': ' + json.loads(resp_body)['message']
                except Exception:
                    msg = ''
                if any(p.match(msg) for p in self.BAD_SESSION_PATTERNS):
                    self.sid = None
                raise Exception('failed API call: %s%s' % (command, msg))
            if resp_body:
                payload = json.loads(resp_body)
            else:
                raise Exception('empty API call response for: %s' % command)
            task_id = payload.get('task-id')
            if not task_id:
                task_id = payload.get(
                    'tasks', [{}])[0].get('task-id')
            if command != 'show-task' and task_id:
                # FIXME: it takes some time for the task to appear
                time.sleep(2)
                while True:
                    task = self('show-task',
                                {'task-id': task_id})['tasks'][0]
                    if task['status'] != self.IN_PROGRESS:
                        break
                    progress('_')
                    time.sleep(2)
                task = self('show-task',
                            {'task-id': task_id,
                             'details-level': 'full'})['tasks'][0]
                status = task['status']
                if status == self.SUCCEEDED:
                    payload = task
                else:
                    details = json.dumps(
                        task.get('task-details', [None])[0], indent=2)
                    if command == 'install-policy' and status == self.FAILED:
                        # FIXME: what about partial success and warnings
                        msgs = []
                        for msg in task[
                                'task-details'][0]['stagesInfo'][0][
                                    'messages']:
                            msgs.append('%s: %s' % (
                                msg['type'], msg['message']))
                        details = '\n'.join(msgs)
                    raise Exception(
                        '%s: %s :\n%s' % (command, status, details))

            if self.auto_publish and (
                    command.startswith('set-') or
                    command.startswith('add-') or
                    command.startswith('delete-')):
                self('publish', {})
            if command == 'logout':
                self.sid = None
            if not aggregate:
                return payload
            objects += payload[aggregate]
            if payload['total'] == 0 or payload['total'] <= payload['to']:
                return objects
            offset = payload['to']

    def in_domain(self, obj):
        domain = 'SMC User' if self.domain is None else self.domain
        return obj['domain']['name'] == domain

    def __enter__(self):
        # FIXME: if the polling period is longer than the session timeout
        #        we need to request a longer session or add keepalive
        try:
            if not self.user:
                progress('+')
                login_args = ['mgmt_cli', '--root', 'true', '--format', 'json',
                              'login']
                if self.domain:
                    login_args += ['domain', self.domain]
                resp = json.loads(subprocess.check_output(login_args))
            else:
                login_data = {'user': self.user, 'password': self.password}
                if self.domain:
                    login_data['domain'] = self.domain
                resp = self('login', login_data)
            self.sid = resp['sid']
            debug('\nnew session:  %s' % resp['uid'])
            for session in self('show-sessions', {'details-level': 'full'},
                                aggregate='objects'):
                if session['uid'] == resp['uid'] or (
                        not self.in_domain(session) or
                        session['application'] != 'WEB_API'):
                    continue
                log('\ndiscarding session: %s' % session['uid'])
                self('discard', {'uid': session['uid']})
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
            log('\n%s' % traceback.format_exc())

    def get_gateway(self, name):
        try:
            gw = self('show-simple-gateway', {'name': name}, silent=True)
        except Exception:
            # FIXME: remove when all gateways are able to show
            if str(sys.exc_info()[1]).endswith(
                    'Runtime error: Unmarshalling Error: Unable to ' +
                    'create an instance of com.checkpoint.management.' +
                    'dlecommon.ngm_api.CpmiOwned '):
                return None
            else:
                raise
        if TAG not in self.get_object_tags(gw):
            return None
        return gw

    def get_gateways(self):
        objects = self('show-simple-gateways', {}, aggregate='objects')
        gateways = {}
        for name in (o['name'] for o in objects):
            gw = self.get_gateway(name)
            if gw:
                gateways[gw['name']] = gw
        return gateways

    def get_object_tags(self, obj, in_comments=True):
        if not in_comments:
            return obj['tags']
        tags = []
        comments = obj.get('comments', '')
        match = re.match(r'.*\{tags=([^}]*)\}.*$', comments)
        if match and match.group(1):
            tags = match.group(1).split('|')
        return tags

    def put_object_tags(self, obj, tags, in_comments=True):
        if not in_comments:
            obj['tags'] = tags
            return
        comments = obj.get('comments', '')
        match = re.match(r'([^{]*)(\{tags=[^}]*\})?(.*)$', comments)
        obj['comments'] = match.group(1) + (
            '{tags=%s}' % '|'.join(tags)) + match.group(3)

    def get_object_tag_value(self, obj, prefix, default=None,
                             in_comments=True):
        for tag in self.get_object_tags(obj, in_comments=in_comments):
            if tag.startswith(prefix):
                return tag[len(prefix):]
        return default

    def put_object_tag_value(self, obj, prefix, value, in_comments=True,
                             silent=False):
        if not silent:
            log('\n%s tag: %s' % (
                'putting' if value else 'removing',
                prefix + value if value else prefix))
        old_tags = self.get_object_tags(obj, in_comments=in_comments)
        new_tags = []
        for t in old_tags:
            if not t.startswith(prefix):
                new_tags.append(t)
                continue
        if value:
            new_tags.append(prefix + value)
        self.put_object_tags(obj, new_tags, in_comments=in_comments)

    def set_object_tag_value(self, uid, prefix, value, in_comments=True):
        obj = self('show-generic-object', {'uid': uid})
        self.put_object_tag_value(obj, prefix, value, in_comments=in_comments)
        payload = {'uid': uid}
        if in_comments:
            payload['comments'] = obj['comments']
        else:
            payload['tags'] = obj['tags']
        self('set-generic-object', payload)

    def gw2str(self, gw):
        return ' '.join([gw['name'],
                         '|'.join(self.get_object_tags(gw)),
                         '|'.join(self.targets.get(gw['name'], ['-'])),
                         str(self.domain)])

    def get_uid(self, name):
        objects = self('show-generic-objects', {'name': name},
                       aggregate='objects')
        by_name = [o for o in objects if o['name'] == name]
        if len(by_name) == 1:
            return by_name[0]['uid']
        if not len(by_name):
            return None
        by_domain = [o for o in by_name if self.in_domain(o)]
        if len(by_domain) == 1:
            return by_domain[0]['uid']
        raise Exception('more than one object named "%s"' % name)

    def set_proxy(self, gw, proxy_ports):
        log('\n%s: %s' % ('setting proxy', json.dumps(proxy_ports)))
        uid = gw['uid']
        if not proxy_ports:
            self('set-generic-object', {'uid': uid, 'proxyOnGwEnabled': False})
            return

        ports = self('show-generic-object', {'uid': uid})[
            'proxyOnGwSettings']['ports']
        # FIXME: would not be needed when we can assign to an empty value
        if not ports:
            ports = {'add': proxy_ports}
        else:
            ports = proxy_ports
        self('set-generic-object', {
            'uid': uid,
            'proxyOnGwEnabled': True,
            'proxyOnGwSettings': {
                'interfacesType': 'ALL_INTERFACES',
                'ports': ports,
                'tarnsparentMode': False}})

    def set_ips_profile(self, gw, ips_profile):
        IPS_LAYER = 'IPS'
        log('\n%s: %s' % ('setting ips profile', ips_profile))
        profile = self('show-threat-profile', {'name': ips_profile})
        layer = self.get_uid(IPS_LAYER)
        for rule in self(
                'show-threat-rulebase', {'uid': layer})['rulebase']:
            if gw['uid'] in rule['install-on']:
                break
        else:
            raise Exception('could not find IPS rule for gateway')
        self('set-threat-rule', {
            'uid': rule['uid'], 'layer': layer, 'action': profile['uid']})

    def set_identity_awareness(self, gw, enabled):
        if gw['version'] != 'R77.30':
            log('\nidentity awarness setup is not supported for "%s"' % (
                gw['version']))
            return False
        uid = gw['uid']
        gw_gen = self('show-generic-object', {'uid': uid})
        was_installed = gw_gen.get('identityAwareBlade', {}).get(
            'identityAwareBladeInstalled') == 'INSTALLED'
        log('\nsetting identity awareness: %s -> %s' % (
            was_installed, enabled))
        if enabled and was_installed or not enabled and not was_installed:
            return False
        if not enabled:
            self('set-generic-object', {
                'uid': uid,
                'identityAwareBlade': {
                    'identityAwareBladeInstalled': 'NOT_MINUS_INSTALLED',
                    'isCollectingIdentities': False}})
            return False
        has_portal = 'IAMUAgent' in {
            p.get('portalName') for p in gw_gen.get('portals', [])}
        has_realm = 'identity_portal' in {
            p.get('ownedName') for p in gw_gen.get('realmsForBlades', [])}
        with open('/dev/urandom') as f:
            psk = base64.b64encode(f.read(12))
        gw_obj = {
            'uid': uid,
            'cdmModule': 'NOT_MINUS_INSTALLED',
            'identityAwareBlade': {
                'create': self.CPMI_IDENTITY_AWARE_BLADE,
                'owned-object': {
                    'idaApiSettings': {
                        'idaApiClientVerificationSettings': []},
                    'enableCitrix': True,
                    'citrixSettings': {
                        'preSharedSecret': psk},
                    'idcSettings': [],
                    'isCollectingIdentities': True,
                    'identityAwareBladeInstalled': 'INSTALLED'}}}
        if not has_portal:
            gw_obj.update({
                'portals': {
                    'add': {
                        'create': self.CPMI_PORTAL_SETTINGS,
                        'owned-object': {
                            'internalPort': 8886,
                            'portalName': 'IAMUAgent',
                            'portalAccess': 'ALL_INTERFACES',
                            'mainUrl': 'https://0.0.0.0/_IA_MU_Agent',
                            'ipAddress': '0.0.0.0'}}}})
        if not has_realm:
            gw_obj.update({
                'realmsForBlades': {
                    'add': {
                        'create': self.CPMI_REALM_BLADE_ENTRY,
                        'owned-object': {
                            'ownedName': 'identity_portal',
                            'displayString': 'Identity Portal Realm',
                            'requirePasswordInFirstChallenge': True,
                            'directory': {
                                'fetchOptions': {
                                    'create': self.CPMI_REALM_FETCH_OPTIONS}},
                            'authentication': {
                                'create': self.CPMI_REALM_AUTHENTICATION,
                                'owned-object': {
                                    'authSchemes': {
                                        'add': {
                                            'create':
                                                self.CPMI_REALM_AUTH_SCHEME,
                                            'owned-object': {
                                                'authScheme': 'USER_PASS',
                                            }}}}}}}}})
        self('set-generic-object', gw_obj)
        return True

    def get_targets(self):
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
                targets.setdefault(target['name'], []).append(policy_name)
        self.targets = targets

    def load_balancer_tag(self, instance):
        load_balancers = getattr(instance, 'load_balancers', {})
        if not load_balancers:
            return None
        parts = []
        for dns_name in load_balancers:
            protocol_ports = load_balancers[dns_name]
            for protocol_port in protocol_ports:
                parts.append('-'.join(
                    [protocol_port] + sorted(
                        protocol_ports[protocol_port])))
        return ':'.join(sorted(parts))

    def get_flat_rules(self, command, body):
        body['limit'] = 1
        body['offset'] = 0
        last_section = None
        while True:
            response = self(command, body)
            top_rules = response['rulebase']
            if not top_rules:
                return
            for top_rule in top_rules:
                if top_rule['type'].endswith('-section'):
                    sub_rules = top_rule.pop('rulebase')
                    if top_rule['uid'] != last_section:
                        last_section = top_rule['uid']
                        yield top_rule
                    for sub_rule in sub_rules:
                        yield sub_rule
                else:
                    yield top_rule
            if body['offset'] + body['limit'] > response['total']:
                return
            body['offset'] = response['to']

    def get_rulebase(self, rulebase, nat=False, sections=False):
        if nat:
            command = 'show-nat-rulebase'
            body = {'package': rulebase}
        else:
            command = 'show-access-rulebase'
            body = {'uid': rulebase}
        rules = []
        for rule in self.get_flat_rules(command, body):
            if rule['type'].endswith('-rule'):
                if not sections:
                    rules.append(rule)
                continue
            if rule['type'].endswith('-section'):
                if sections:
                    rules.append(rule)
                continue
        return rules

    def get_dummy_group(self):
        if hasattr(self, 'dummy_group'):
            return self.dummy_group
        self.dummy_group = self.get_uid(self.DUMMY_PREFIX + 'group')
        if not self.dummy_group:
            dummy_host = self.get_uid(self.DUMMY_PREFIX + 'host')
            if not dummy_host:
                dummy_host = self('add-host', {
                    'ignore-warnings': True,  # re-use of IP address
                    'name': self.DUMMY_PREFIX + 'host',
                    'ip-address': '169.254.1.1'})['uid']
            self.dummy_group = self('add-group', {
                'name': self.DUMMY_PREFIX + 'group',
                'members': dummy_host})['uid']
        return self.dummy_group

    def get_protocol_type(self, protocol):
        if not hasattr(self, 'protocol_map'):
            self.protocol_map = {
                'HTTP': self('show-generic-object', {
                    'uid': self.get_uid('http')})['protoType'],
                'HTTPS': self('show-generic-object', {
                    'uid': self.get_uid('https')})['protoType']}
        return self.protocol_map.get(protocol)

    def add_load_balancer(self, gw, policy, dns_name, protocol_ports):
        debug('\nadding %s: %s\n' % (
            dns_name, json.dumps(protocol_ports, indent=2)))
        private_address = gw['interfaces'][0]['ipv4-address']
        private_name = private_address + '_' + gw['name']
        if not self.get_uid(private_name):
            log('\nadding %s' % private_name)
            self('add-host', {
                'ignore-warnings': True,  # re-use of IP address
                'name': private_name, 'ip-address': private_address})
        if len(gw['interfaces']) > 1:
            nat_address = gw['interfaces'][1]['ipv4-address']
            nat_name = nat_address + '_' + gw['name']
            if not self.get_uid(nat_name):
                log('\nadding %s' % nat_name)
                self('add-host', {
                    'ignore-warnings': True,  # re-use of IP address
                    'name': nat_name, 'ip-address': nat_address})
        else:
            nat_address = private_address
            nat_name = private_name
        # create logical server
        logical_server = None
        for i in xrange(100):
            extension = ''.join([random.choice('0123456789' +
                                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                                               'abcdefghijklmnopqrstuvwxyz')
                                 for j in xrange(6)])
            candidate = '%s_%s' % (dns_name, extension)
            if self.get_uid(candidate):
                continue
            logical_server = candidate
            break
        if not logical_server:
            raise Exception('Failed to find a name for a logical server')
        if self.get_uid(logical_server):
            return
        log('\nadding %s' % logical_server)
        ls_obj = {
            'ignore-warnings': True,  # re-use of IP address
            'create': self.CPMI_LOGICAL_SERVER,
            'name': logical_server,
            'ipaddr': private_address,
            'serversType': 'OTHER',
            'method': 'DOMAIN',
            'servers': self.get_dummy_group()}
        self.put_object_tag_value(ls_obj, self.GATEWAY_PREFIX, gw['name'])
        self('add-generic-object', ls_obj)
        layers = []
        for layer in self('show-package', {'name': policy})['access-layers']:
            if not self.in_domain(layer):
                continue
            if self('show-generic-object',
                    {'uid': layer['uid']})['firewallOn']:
                layers.append(layer)
        if not layers:
            raise Exception('failed to find a firwall layer in "%s"' % layer)
        for layer in layers:
            for section in self.get_rulebase(layer['uid'], sections=True):
                if section.get('name') == self.SECTION:
                    debug('\nusing access layer "%s\n"' % layer['name'])
                    position = {'below': section['uid']}
                    break
            else:
                continue
            break
        else:
            layer = layers[0]
            position = 'top'
        for section in self.get_rulebase(policy, nat=True, sections=True):
            if section.get('name') == self.SECTION:
                nat_position = {'below': section['uid']}
                break
        else:
            nat_position = 'top'
        for protocol_port in protocol_ports:
            lb_protocol, dash, port = protocol_port.partition('-')
            # add a service
            service_name = '%s_%s' % (protocol_port, gw['name'])
            log('\nadding %s' % service_name)
            self('add-service-tcp', {
                'name': service_name, 'port': port, 'match-for-any': False})
            protocol = self.get_protocol_type(lb_protocol)
            if protocol:
                self('set-generic-object', {
                    'uid': self.get_uid(service_name),
                    'protoType': protocol})
            # add subnets
            net_uids = []
            for subnet in protocol_ports[protocol_port]:
                net, slash, mask = subnet.partition('/')
                net_name = '%s-%s_%s' % (net, mask, service_name)
                log('\nadding %s' % net_name)
                net_uids.append(self('add-network', {
                    'ignore-warnings': True,  # re-use of subnet/mask
                    'name': net_name, 'subnet': net,
                    'mask-length': int(mask)})['uid'])
            source = 'Any'
            original_source = 'All_Internet'
            if net_uids:
                group_name = 'net-group_%s' % service_name
                log('\nadding %s' % group_name)
                group_uid = self('add-group', {
                    'name': group_name, 'members': net_uids})['uid']
                source = group_uid
                original_source = group_uid
            # add access rule
            log('\nadding access rule for %s' % service_name)
            short_service_name = service_name
            if len(short_service_name) > 38:
                short_service_name = short_service_name[:35] + '___'
            self('add-access-rule', {
                'name': short_service_name,
                'comments': 'access_%s' % service_name,
                'layer': layer['uid'],
                'position': position,
                'source': source,
                'destination': logical_server,
                'service': service_name,
                'action': 'Accept',
                'track': 'Log',
                'install-on': gw['name']})
            # add nat rule
            log('\nadding nat rule for %s' % service_name)
            self('add-nat-rule', {
                'comments': 'nat_%s' % service_name,
                'package': policy,
                'position': nat_position,
                'original-source': original_source,
                'original-destination': private_name,
                'original-service': service_name,
                'translated-source': nat_name,
                'method': 'hide',
                'install-on': gw['name']})

    def set_policy(self, gw, policy):
        name = gw['name']
        log('\nsetting policy "%s" on %s' % (policy, name))
        for old_policy in self.targets.pop(name, []):
            self('set-package', {
                'name': old_policy,
                'installation-targets': {'remove': name}})
        if not policy:
            return

        self('set-package', {
            'name': policy,
            'installation-targets': {'add': name}})
        self.targets.setdefault(name, []).append(policy)

        self('install-policy', {
            'policy-package': policy, 'targets': name})

    def customize(self, name, parameters=None):
        if not self.custom_script:
            return True
        if parameters is None:
            cmd = [self.custom_script, 'delete', name]
        else:
            if isinstance(parameters, basestring):
                parameters = re.split(r'\s+', parameters)
            cmd = [self.custom_script, 'add', name] + parameters
        log('\ncustomizing %s\n' % cmd)
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, err = proc.communicate()
        log(err)
        log(out)
        return not proc.wait()

    def reset_gateway(self, name, delete=False):
        log('\n%s: %s' % ('deleting' if delete else 'resetting', name))
        self.customize(name)
        gw = self.get_gateway(name)
        self.set_policy(gw, None)
        policies = [p['name']
                    for p in self('show-packages', {}, aggregate='packages')]
        for policy in policies:
            # remove nat rules installed on the deleted gateway
            rules = self.get_rulebase(policy, nat=True)
            for rule in rules:
                if gw['uid'] in rule['install-on']:
                    log('\ndeleting %s in "%s"' % (rule['comments'], policy))
                    self('delete-nat-rule', {
                        'uid': rule['uid'], 'package': policy})
            # remove access rules installed on the deleted gateway
            layers = self(
                'show-package', {'name': policy})['access-layers']
            for layer in layers:
                rules = self.get_rulebase(layer['uid'])
                for rule in rules:
                    if gw['uid'] in rule['install-on']:
                        log('\ndeleting %s in "%s"' % (
                            rule.get('comments', rule.get('name')),
                            layer['name']))
                        self('delete-access-rule',
                             {'uid': rule['uid'], 'layer': layer['uid']})
        # remove groups defined for the gateway
        for group in self('show-groups', {}, aggregate='objects'):
            if group['name'].endswith('_' + name):
                log('\ndeleting %s' % group['name'])
                self('delete-group', {'name': group['name']})
        # remove networks defined for the gateway
        for net in self('show-networks', {}, aggregate='objects'):
            if net['name'].endswith('_' + name):
                log('\ndeleting %s' % net['name'])
                self('delete-network', {'name': net['name']})
        # remove services defined for the gateway
        for service in self('show-services-tcp', {}, aggregate='objects'):
            if service['name'].endswith('_' + name):
                log('\ndeleting %s' % service['name'])
                self('delete-service-tcp', {'name': service['name']})
        # remove logical servers defined for the gateway
        logical_servers = self(
            'show-generic-objects', {'class-name': self.CPMI_LOGICAL_SERVER},
            aggregate='objects')
        for logical_server in logical_servers:
            logical_server = self('show-generic-object', {
                'uid': logical_server['uid']})
            if self.get_object_tag_value(
                    logical_server, self.GATEWAY_PREFIX) == name:
                log('\ndeleting %s' % logical_server['name'])
                self('delete-generic-object', {'uid': logical_server['uid']})
        # remove the hosts defined for the gateway
        for host in self('show-hosts', {}, aggregate='objects'):
            if host['name'].endswith('_' + name):
                log('\ndeleting %s' % host['name'])
                self('delete-host', {'name': host['name']})
        if delete:
            log('\ndeleting %s' % name)
            self('delete-simple-gateway', {'name': name})

    def is_up_to_date(self, instance, gw, generation):
        if not gw:
            return False
        if (instance.template !=
                self.get_object_tag_value(gw, self.TEMPLATE_PREFIX, '')):
            log('\nconfiguration was not complete')
            return False
        if (generation !=
                self.get_object_tag_value(gw, self.GENERATION_PREFIX, '')):
            log('\nnew template generation')
            return False
        if (self.load_balancer_tag(instance) !=
                self.get_object_tag_value(gw, self.LOAD_BALANCER_PREFIX)):
            log('\nnew load balancer configuration')
            return False
        return True

    def set_topology(self, interfaces, specific_network):
        if len(interfaces) == 1:
            interfaces[0]['anti-spoofing'] = False
            return
        this_net = {
            'ip-address-behind-this-interface':
                'network defined by the interface ip and net mask'}
        for interface in interfaces:
            if interface.get('topology-settings'):
                continue
            topology = interface['topology']
            if topology == 'internal':
                interface['topology-settings'] = this_net
                continue
            if topology.startswith('specific'):
                spec, colon, spec_net = topology.partition(':')
                if spec != 'specific':
                    raise Exception('bad topology: %s: "%s"' % (
                        interface['name'], topology))
                if spec_net:
                    specific_network = spec_net
                if not specific_network:
                    raise Exception(
                        'no specific-network for topology: %s' %
                        interface['name'])
                interface['topology'] = 'internal'
                interface['topology-settings'] = {
                    'ip-address-behind-this-interface': 'specific',
                    'specific-network': specific_network}

    def set_gateway(self, instance, gw):
        log('\n%s: %s' % ('updating' if gw else 'creating', instance.name))
        simple_gateway = Template.get_dict(instance.template)
        generation = str(simple_gateway.pop('generation', ''))
        if self.is_up_to_date(instance, gw, generation):
            return

        proxy_ports = simple_gateway.pop('proxy-ports', None)
        https_inspection = simple_gateway.pop('https-inspection', False)
        identity_awareness = simple_gateway.pop('identity-awareness', False)
        ips_profile = simple_gateway.pop('ips-profile', None)
        specific_network = simple_gateway.pop('specific-network', None)
        policy = simple_gateway.pop('policy')
        otp = simple_gateway.pop('one-time-password')
        custom_parameters = simple_gateway.pop('custom-parameters', [])
        # FIXME: network info is not updated once the gateway exists
        if not gw:
            self.set_state(instance.name, 'ADDING')
            gw = {
                'name': instance.name,
                'ip-address': instance.ip_address,
                'interfaces': instance.interfaces,
                'one-time-password': otp}
            self.set_topology(gw['interfaces'], specific_network)
            version = simple_gateway.pop('version')
            if version:
                gw['version'] = version
            self.put_object_tags(gw, [TAG])
            self('add-simple-gateway', gw)
        else:
            self.set_state(instance.name, 'UPDATING')
        success = False
        published = False
        try:
            self.auto_publish = False
            self.reset_gateway(instance.name)
            simple_gateway['name'] = instance.name
            tags = simple_gateway.pop('tags', [])
            self.put_object_tags(simple_gateway, tags + [TAG])
            self('set-simple-gateway', simple_gateway)
            gw = self.get_gateway(instance.name)
            self.set_proxy(gw, proxy_ports)
            self('set-generic-object', {
                'uid': gw['uid'],
                'sslInspectionEnabled': https_inspection})
            identity_awareness = self.set_identity_awareness(
                gw, identity_awareness)
            if gw.get('ips'):
                self('set-generic-object', {
                    'uid': gw['uid'], 'protectInternalInterfacesOnly': False})
                if ips_profile:
                    self.set_ips_profile(gw, ips_profile)
            load_balancers = getattr(instance, 'load_balancers', {})
            if load_balancers:
                for dns_name in load_balancers:
                    self.add_load_balancer(
                        gw, policy, dns_name, load_balancers[dns_name])
            self.set_object_tag_value(gw['uid'],
                                      self.LOAD_BALANCER_PREFIX,
                                      self.load_balancer_tag(instance))
            self('publish', {})
            published = True
            self.auto_publish = True
            self.set_policy(gw, policy)
            if identity_awareness:
                cmd = 'pdp api enable'
                log('\nrunning: "%s" on %s' % (cmd, instance.name))
                response = self('run-script', {
                    'script-name': cmd,
                    'script': cmd,
                    'targets': [instance.name]
                    }).get('task-details', [{}])[0]
                log('\n%s' % base64.b64decode(response.get('responseMessage')))
                if response.get('statusCode') != self.SUCCEEDED:
                    log('\nfailed to enable pdp api on the gateway\n%s', (
                        base64.b64decode(response.get('responseError'))))
            if not self.customize(instance.name, custom_parameters):
                raise Exception('customization has failed')
            self.set_object_tag_value(gw['uid'],
                                      self.GENERATION_PREFIX, generation)
            self.set_object_tag_value(gw['uid'],
                                      self.TEMPLATE_PREFIX, instance.template)
            success = True
        finally:
            self.auto_publish = True
            if not success:
                if not published:
                    try:
                        log('\ndiscarding changes for %s' % instance.name)
                        self('discard', {})
                    except Exception:
                        log('\n%s' % traceback.format_exc())
                else:
                    try:
                        self.reset_gateway(instance.name)
                    except Exception:
                        log('\n%s' % traceback.format_exc())

    def set_state(self, name, status):
        if not hasattr(self, 'state'):
            self.state = {}
        if name:
            log('\n%s: %s' % (name, status))
        if status:
            self.state[name] = status
        elif name in self.state:
            del self.state[name]

    @staticmethod
    @contextlib.contextmanager
    def init(domains, **config):
        managements = collections.OrderedDict()
        options = config['management'].copy()
        default_domain = options.pop('domain', None)
        try:
            for domain in domains:
                actual_domain = default_domain if domain is None else domain
                if domain not in managements:
                    managements[domain] = Management(
                        domain=actual_domain, **options)
            yield managements
        finally:
            for management in reversed(managements.values()):
                try:
                    management.__exit__(*sys.exc_info())
                except Exception:
                    log('\n%s' % traceback.format_exc())


def is_SIC_open(instance):
    with contextlib.closing(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(3)
        if s.connect_ex((instance.ip_address, 18211)):
            return False
        time.sleep(5)
        return True


def signal_handler(signum, frame):
    log('\ncaught signal %d...\n' % signum)
    raise KeyboardInterrupt('signal %d' % signum)


def sync(controller, management, gateways):
    log('\n' + controller.name)
    if not conf.get('debug'):
        log('\n')
    instances = {}
    for instance in controller.filter_instances():
        instances[instance.name] = instance
    if conf.get('debug'):
        log('\n')
    log('\n'.join([str(instances[i]) for i in instances] + ['']))
    filtered_gateways = set(name for name in gateways
                            if name.startswith(
                                controller.name + controller.SEPARATOR))
    for name in filtered_gateways - set(instances):
        try:
            management.set_state(name, 'DELETING')
            management.reset_gateway(name, delete=True)
        except Exception:
            log('\n%s' % traceback.format_exc())
        finally:
            management.set_state(name, None)

    for name in set(instances):
        gw = gateways.get(name)

        if not gw:
            if not is_SIC_open(instances[name]):
                management.set_state(name, 'INITIALIZING')
                continue
        try:
            management.set_gateway(instances[name], gw)
            management.set_state(name, 'COMPLETE')
        except Exception:
            log('\n%s' % traceback.format_exc())


def loop(managements, controllers, delay):
    while True:
        for domain in controllers.keys():
            try:
                management = managements[domain]
                if management.domain:
                    log('\n%s' % management.domain)
                management.get_targets()
                gateways = management.get_gateways()
                log('\ngateways (before):\n')
                log('\n'.join(
                    [management.gw2str(gateways[gw]) for gw in gateways] +
                    ['']))
                for c in controllers[domain]:
                    try:
                        sync(c, management, gateways)
                    except Exception:
                        log('\n%s' % traceback.format_exc())
                log('\n')
                gateways = management.get_gateways()
                log('\ngateways (after):\n')
                log('\n'.join(
                    [management.gw2str(gateways[gw]) for gw in gateways] +
                    ['']))
                log('\n')
            except Exception:
                log('\n%s' % traceback.format_exc())
        time.sleep(delay)


def start(config):
    for t in config['templates']:
        Template(t, **config['templates'][t])
    controllers = collections.OrderedDict()
    for c in config['controllers']:
        controller = config['controllers'][c]
        controllers.setdefault(controller.get('domain'), []).append(
            globals()[controller['class']](
                name=c, management=config['management']['name'], **controller))
    with Management.init(controllers.keys(), **config) as managements:
        loop(managements, controllers, config['delay'])


def test(config_file):
    log('\nTesting if the configuration file exists...\n')
    if not os.path.isfile(config_file):
        raise Exception('Cannot find "%s"\n' % config_file)

    log('\nTesting if the configuration file is a valid JSON object...\n')
    try:
        with open(config_file) as f:
            config = json.load(f, object_pairs_hook=collections.OrderedDict)
    except ValueError:
        raise Exception('%s is not a valid JSON file\n' % config_file)

    log('\nTesting basic configuration structure...\n')
    for key in ['delay', 'management', 'templates', 'controllers']:
        if key not in config or not config[key]:
            raise Exception('"%s" section is missing or empty\n' % key)

    if not isinstance(config['delay'], int):
        raise Exception('The parameter "delay" must be an integer\n')

    log('\nTesting templates...\n')
    protos = set([t.get('proto') for t in config['templates'].values()])
    for name in config['templates']:
        Template(name, **config['templates'][name])
    templates = set(config['templates']) - protos
    for name, controller in config['controllers'].items():
        if 'templates' not in controller:
            continue
        if not isinstance(controller['templates'], list):
            raise Exception(
                'The parameter "templates" in controller %s should be an array'
                % name)
        templates.update(controller['templates'])
    for name in templates:
        log('\nTesting %s...\n' % name)
        for key in ['version', 'one-time-password', 'policy']:
            if not Template.get(name, key, None):
                raise Exception('The parameter "%s" is missing' % key)

    log('\nTesting controllers...\n')
    domains = set()
    for name, c in config['controllers'].items():
        log('\nTesting %s...\n' % name)
        for key in ['class']:
            if key not in c:
                raise Exception('The parameter "%s" is missing' % key)

        cls = globals().get(c['class'], object)
        if not issubclass(cls, Controller):
            raise Exception('Unknown controller class "%s"' % c['class'])
        if cls.SEPARATOR in name:
            raise Exception('The controller name contains "%s"' %
                            cls.SEPARATOR)

        cls.test(cls, name=name, management=config['management']['name'], **c)
        domains.add(c.get('domain'))
    if domains and None in domains and domains - {None} and (
            not config['management'].get('domain')):
        raise Exception('Some controllers do not have a "domain"')

    log('\nTesting management configuration...\n')
    for key in ['name', 'host']:
        if key not in config['management']:
            raise Exception(
                'The parameter "%s" is missing in management section\n' % key)

    log('\nTesting management connectivity...\n')
    with Management.init(domains, **config) as managements:
        for management in managements.values():
            management.get_gateways()

    log('\nAll Tests passed successfully\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog=argv[0] if argv else None)
    parser.add_argument('config', metavar='CONFIG',
                        help='JSON-FILE or a literal json expression')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    parser.add_argument('-l', '--logfile', metavar='LOGFILE',
                        help='Path to log file')
    parser.add_argument('-t', '--test', dest='test', action='store_true')
    args = parser.parse_args(argv[1:] if argv else None)

    logfile = getattr(args, 'logfile', None)
    if logfile:
        handler = logging.handlers.RotatingFileHandler(args.logfile,
                                                       maxBytes=1000000,
                                                       backupCount=3)
        logger = logging.getLogger('MONITOR')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s-%(name)s-%(levelname)s- %(message)s'))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        conf['logger'] = logger
        os.environ['AWS_NO_DOT'] = 'true'
        os.environ['AZURE_NO_DOT'] = 'true'
        os.environ['GCP_NO_DOT'] = 'true'

    debug_func = None
    if args.debug:
        conf['debug'] = True
        debug_func = debug
        if conf.get('logger'):
            conf.get('logger').setLevel(logging.DEBUG)
    aws.set_logger(log=log, debug=debug_func)
    azure.set_logger(log=log, debug=debug_func)
    gcp.set_logger(log=log, debug=debug_func)

    if args.test:
        test(args.config)
        sys.exit(0)

    if args.config[0] == '@':
        args.config = args.config[1:]

    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            with open(args.config) as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except:
                    raise Exception('Another process is already running')
                config = json.load(
                    f, object_pairs_hook=collections.OrderedDict)
                start(config)
        except Exception:
            log('\n%s' % traceback.format_exc())
        log('\n')
        time.sleep(300)
    return 0


if __name__ == '__main__':
    try:
        rc = main(sys.argv)
    except SystemExit:
        raise
    except:
        log('\n%s' % traceback.format_exc())
        rc = 1
    sys.exit(rc)
