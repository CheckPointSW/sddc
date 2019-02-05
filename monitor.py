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
CIDRS_REGEX = (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
               r'([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
               r'(\/([0-9]|[1-2][0-9]|3[0-2]))$')

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
def redact(active, log, redact_patterns):
    line = []
    if active:
        stdout = sys.stdout
        redact_patterns = [(re.compile(p), r) for p, r in redact_patterns]

        def write(buf):
            while buf:
                end, newline, start = buf.partition('\n')
                line.append(end)
                if not newline:
                    return
                buf = ''.join(line) + '\n'
                for pattern, replacement in redact_patterns:
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
    templates = collections.OrderedDict([(None, None)])

    def __init__(self, name, **options):
        self.name = name
        self.proto = options.get('proto')
        self.self = self
        self.options = {
            k: v for k, v in options.items() if k not in self.EXCLUDED}
        self.templates[self.name] = self

    def __getattr__(self, attr):
        if attr in self.options:
            return self.options[attr]
        proto = Template.templates[self.proto]
        if proto:
            return getattr(proto, attr)
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
    def __init__(
            self, name, ip_address, interfaces, template, load_balancers=None):
        self.name = name
        self.ip_address = ip_address
        self.interfaces = interfaces
        self.template = template
        self.load_balancers = load_balancers

    def __str__(self):
        return ' '.join([
            self.name, self.ip_address, json.dumps(self.interfaces),
            self.template, json.dumps(self.load_balancers)])


class VPNConn(object):
    def __init__(self, name, controller, short_name, tag, gateway,
                 peer, local, remote, asn, pre_shared_key, cidr):
        self.name = name
        self.controller = controller
        self.short_name = short_name
        self.tag = tag
        self.gateway = gateway
        self.peer = peer
        self.local = local
        self.remote = remote
        self.asn = asn
        self.pre_shared_key = pre_shared_key
        self.cidr = cidr

    def __str__(self):
        name = self.name
        if self.tag:
            name = '%s(%s)' % (name, self.tag)
        gw = self.gateway
        return ' '.join([name, gw, self.peer, self.local, self.remote,
                         self.asn, self.cidr])


class Controller(object):
    SEPARATOR = '--'

    def __init__(self, **options):
        self.name = options['name']
        self.management = options['management']
        self.templates = options.get('templates', [])
        self.communities = options.get('communities', [])
        self.sync = options.get('sync', {'gateway': True, 'lb': True}).copy()

    def get_instances(self):
        raise Exception('not implemented')

    def get_vpn_conns(self, vpn_env=None, test=False):
        return []

    def filter_instances(self):
        instances = []
        for i in self.get_instances():
            if self.templates and i.template not in self.templates:
                continue
            i.controller = self
            instances.append(i)
        return instances

    @staticmethod
    @contextlib.contextmanager
    def Tester(cls, **options):
        controller = cls(**options)
        yield controller
        if controller.sync.get('gateway', False):
            instances = controller.filter_instances()
            log('\n'.join([''] + [str(i) for i in instances] + ['']))
        if controller.sync.get('vpn', False):
            vpn_conns = controller.get_vpn_conns(test=True)
            log('\n'.join([''] + [str(v) for v in vpn_conns] + ['']))

    @staticmethod
    def test(cls, **options):
        with Controller.Tester(cls, **options) as controller:
            controller  # do nothing but keep pyflakes happy


class AWS(Controller):
    BASE_CRED_OPTS = ['access-key', 'secret-key', 'cred-file']
    OPT_TO_ARG = {
        'access-key': 'key', 'secret-key': 'secret', 'cred-file': 'key_file',
        'sts-role': 'sts_role', 'sts-external-id':  'sts_ext_id'}
    ARG_TO_ENV = {
        'key': 'AWS_ACCESS_KEY_ID', 'secret': 'AWS_SECRET_ACCESS_KEY',
        'key_file': 'AWS_KEY_FILE', 'sts_role': 'AWS_STS_ROLE',
        'sts_ext_id': 'AWS_STS_EXTERNAL_ID', 'sts_session': 'AWS_STS_SESSION'}
    CREDENTIAL = '__credential__'
    VPC = '__vpc__'
    VGW = '__vgw__'
    RTB = '__rtb__'
    NUM_CIDRS = 65536 // 4
    FREE_CIDRS = {
        '%s.%s' % (k * 4 // 256, k * 4 % 256) for k in xrange(NUM_CIDRS)} - {
            '0.0', '1.0', '2.0', '3.0', '4.0', '5.0', '169.252'}
    PORT_REGEX = (r'[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}'
                  r'|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]')

    def __init__(self, **options):
        super(AWS, self).__init__(**options)
        self.regions = options['regions']
        sts_session = 'autoprovision-%s' % (
            datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
        kwargs = {a: options.get(o) for o, a in self.OPT_TO_ARG.items()}
        kwargs['sts_session'] = sts_session if 'sts-role' in options else None
        self.aws = aws.AWS(**kwargs)
        self.env_creds = {None: {
            e: kwargs[a] for a, e in self.ARG_TO_ENV.items() if kwargs[a]}}
        self.sub_creds = {}
        if 'sub-creds' in options:
            for sub_cred in options['sub-creds']:
                val = options['sub-creds'][sub_cred]
                if 'sts-role' in val:
                    if all(k not in val for k in self.BASE_CRED_OPTS):
                        val.update({k: options[k]
                                    for k in self.BASE_CRED_OPTS
                                    if k in options})
                kwargs = {
                    a: val.get(o) for o, a in self.OPT_TO_ARG.items()}
                kwargs['sts_session'] = (
                    sts_session if 'sts-role' in val else None)
                self.sub_creds[sub_cred] = aws.AWS(**kwargs)
                self.env_creds = {sub_cred: {
                    e: kwargs[a]
                    for a, e in self.ARG_TO_ENV.items() if kwargs[a]}}

    def request(self, service, *args, **kwargs):
        aws_obj = self.aws
        sub_cred = kwargs.pop('sub_cred', None)
        if sub_cred is not None:
            aws_obj = self.sub_creds[sub_cred]
        delays = [.5, 1., 2., 5.]
        while True:
            headers, body = aws_obj.request(service, *args, **kwargs)
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
                msg = 'UnparsedError: %s (%s)' % (
                    headers.get('_reason', '-'), headers.get('_code', '-'))
            else:
                msg = '%s: %s' % (code, error.get('Message', '-'))
            retry = (headers.get('_code', ' ')[0] == '5' or
                     code.lower() == 'throttling')
            if not delays or not retry:
                raise Exception(msg)
            log('\n%s request failed: %s [%s]' % (service, msg, len(delays)))
            time.sleep(delays.pop(0))

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

    def register_internal_lb(self, lb, by_template):
        tags = lb['Tags']
        if tags.get('x-chkp-management') != self.management:
            return
        ignore_ports = tags.get('x-chkp-ignore-ports', [])
        if ignore_ports:
            ignore_ports = set(ignore_ports.split(':'))
        http_ports = tags.get('x-chkp-http-ports', [])
        if http_ports:
            http_ports = set(http_ports.split(':'))
        https_ports = tags.get('x-chkp-https-ports', [])
        if https_ports:
            https_ports = set(https_ports.split(':'))
        ssl_ports = tags.get('x-chkp-ssl-ports', [])
        if ssl_ports:
            ssl_ports = set(ssl_ports.split(':'))
        bad_ports = ', '.join({p[1:] for p in set(
            http_ports) | set(https_ports) if p.startswith('@')})
        if bad_ports:
            raise Exception(
                'the "@" annotation is deprecated in x-chkp-http-ports and '
                'x-chkp-https-ports, and is used with ports %s, consider using'
                ' x-chkp-forwarding instead' % bad_ports)
        if set(http_ports) & set(ssl_ports):
            raise Exception(
                'overlapping ports in x-chkp-http-ports and '
                'x-chkp-ssl-ports with ports: %s'
                % list(http_ports & ssl_ports))
        if set(https_ports) & set(ssl_ports):
            raise Exception(
                'overlapping ports in x-chkp-https-ports and '
                'x-chkp-ssl-ports with ports: %s'
                % list(https_ports & ssl_ports))

        source_cidrs = tags.get('x-chkp-source-cidrs', '') or set()
        if source_cidrs:
            source_cidrs = set(source_cidrs.split())
            bad_cidrs = {s for s in source_cidrs if not re.compile(
                CIDRS_REGEX).match(s)}
            if '0.0.0.0/0' in source_cidrs:
                source_cidrs = set()
            if bad_cidrs:
                raise Exception(
                    'malformed CIDRs: %s in tag x-chkp-source-cidrs' %
                    ', '.join(bad_cidrs))
        source_object = tags.get('x-chkp-source-object', '') or set()
        if source_object:
            source_object = {source_object}
        forwarding_rules = tags.get('x-chkp-forwarding', '') or set()
        if forwarding_rules:
            forwarding_rules = set(forwarding_rules.split())
            bad_rules = {r for r in forwarding_rules if not re.compile(
                r'(TCP|HTTP|HTTPS|SSL)(-(%s)){2}$' % self.PORT_REGEX).match(r)}
            if bad_rules:
                raise Exception(
                    'malformed forwarding rules: %s in tag x-chkp-forwarding' %
                    ', '.join(bad_rules))
        protocol_ports = []

        for pp in [p1 for p1 in lb['Front'] if p1.split('-')[1] not in [
                p2.split('-')[2] for p2 in forwarding_rules]] + list(
                forwarding_rules):
            protocol, port, translated = (pp.split('-') + [None])[:3]
            if port in ignore_ports:
                continue
            if port in ['444', '8082', '8880']:
                raise Exception(
                    'Port %s cannot be used for internal LB listener'
                    % port)
            if port in {'80', '443'} and not translated:
                protocol = 'HTTP' if port == '80' else 'HTTPS'
                port, translated = (str(int(port) + 9000), port)
            if port in http_ports:
                protocol = 'HTTP'
            if port in https_ports:
                protocol = 'HTTPS'
            if port in ssl_ports:
                protocol = 'SSL'
            protocol_ports.append('%s-%s-%s' % (protocol, port,
                                                translated or port))
        template = tags.get('x-chkp-template')
        by_template.setdefault(template, {})
        by_template[template][lb['DNSName']] = (protocol_ports, source_cidrs
                                                | source_object)

    def retrieve_all_elbs(self, region, sub_cred=None):
        elb_list = self.retrieve_all(
            'elasticloadbalancing', region, '/?Action=DescribeLoadBalancers',
            'DescribeLoadBalancersResult', 'LoadBalancerDescriptions',
            sub_cred=sub_cred)
        for elb in elb_list:
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?Action=DescribeTags&LoadBalancerNames.member.1=' +
                elb['LoadBalancerName'], '', sub_cred=sub_cred)
            elb['Tags'] = self.get_tags(aws.listify(
                body['DescribeTagsResult']['TagDescriptions'],
                'member')[0].get('Tags'))
            protocol_ports = []
            for listener in elb['ListenerDescriptions']:
                protocol_ports.append('%s-%s' % (
                    listener['Listener']['Protocol'],
                    listener['Listener']['LoadBalancerPort']))
            elb['Front'] = protocol_ports

        v2lb_dict = {
            v2lb['DNSName']: v2lb
            for v2lb in self.retrieve_all(
                'elasticloadbalancing', region,
                '/?Version=2015-12-01&Action=DescribeLoadBalancers',
                'DescribeLoadBalancersResult', 'LoadBalancers',
                sub_cred=sub_cred)}
        for v2lb in v2lb_dict.values():
            headers, body = self.request(
                'elasticloadbalancing', region, 'GET',
                '/?' + urllib.urlencode({
                    'Version': '2015-12-01',
                    'Action': 'DescribeTags',
                    'ResourceArns.member.1': v2lb['LoadBalancerArn']}), '',
                sub_cred=sub_cred)
            v2lb['Tags'] = self.get_tags(aws.listify(
                body['DescribeTagsResult']['TagDescriptions'],
                'member')[0].get('Tags'))
            v2lb['Listeners'] = self.retrieve_all(
                'elasticloadbalancing', region,
                '/?' + urllib.urlencode({
                    'Version': '2015-12-01',
                    'Action': 'DescribeListeners',
                    'LoadBalancerArn': v2lb['LoadBalancerArn']}),
                'DescribeListenersResult', 'Listeners', sub_cred=sub_cred)
            protocol_ports = []
            for listener in v2lb['Listeners']:
                protocol_ports.append('%s-%s' % (
                    listener['Protocol'], listener['Port']))
            v2lb['Front'] = protocol_ports

        return elb_list, v2lb_dict

    def retrieve_classic_lbs(self, subnets, auto_scaling_groups,
                             elb_list, by_template, by_instance):
        i2lb_names = {}
        lb_name2cidrs = {}
        for elb in elb_list:
            cidrs = [subnets[s]['cidrBlock'] for s in elb['Subnets']]
            back_ports = []
            for listener in elb['ListenerDescriptions']:
                back_ports.append('%s' % listener['Listener']['InstancePort'])
            self.register_internal_lb(elb, by_template)
            lb_name = elb['LoadBalancerName']
            for i in elb['Instances']:
                i2lb_names.setdefault(i['InstanceId'], set()).add(
                    elb['LoadBalancerName'])
            lb_name2cidrs.setdefault(lb_name, {})
            for port in back_ports:
                lb_name2cidrs[lb_name][port] = cidrs

        for group in auto_scaling_groups:
            for i in group['Instances']:
                i2lb_names.setdefault(i['InstanceId'], set()).update(
                    group['LoadBalancerNames'])

        for i in i2lb_names:
            by_instance.setdefault(i, {})
            for lb_name in i2lb_names[i]:
                for port in lb_name2cidrs.get(lb_name, {}):
                    by_instance[i].setdefault(port, []).append(
                        ((lb_name2cidrs[lb_name].get(port, [])), False))

    def retrieve_v2_lbs(self, region, subnets, auto_scaling_groups, v2lb_dict,
                        by_template, by_instance):
        i2target_groups = {}
        for auto_scale_group in auto_scaling_groups:
            for i in auto_scale_group['Instances']:
                for target in auto_scale_group['TargetGroupARNs']:
                    i2target_groups.setdefault(i['InstanceId'], {}).setdefault(
                        target, set())

        target_groups = self.retrieve_all(
            'elasticloadbalancing', region,
            '/?Version=2015-12-01&Action=DescribeTargetGroups',
            'DescribeTargetGroupsResult', 'TargetGroups')
        for target_group in target_groups:
            default_port = target_group['Port']
            for i in i2target_groups:
                if target_group['TargetGroupArn'] in i2target_groups[i]:
                    i2target_groups[i][target_group['TargetGroupArn']].add(
                        default_port)
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
                            target['Target']['Port'])

        dns_name2cidrs = {}
        target_group2dns_names = {}
        for v2lb in v2lb_dict.values():
            dns_name = v2lb['DNSName']
            cidrs = [
                subnets[az['SubnetId']]['cidrBlock']
                for az in v2lb['AvailabilityZones']]
            dns_name2cidrs.setdefault(dns_name, []).extend(cidrs)
            for listener in v2lb['Listeners']:
                rules = self.retrieve_all(
                    'elasticloadbalancing', region,
                    '/?' + urllib.urlencode({
                        'Version': '2015-12-01',
                        'Action': 'DescribeRules',
                        'ListenerArn': listener['ListenerArn']}),
                    'DescribeRulesResult', 'Rules')
                for rule in rules:
                    for action in rule['Actions']:
                        if 'TargetGroupArn' not in action:
                            continue
                        target_group2dns_names.setdefault(
                            action['TargetGroupArn'], set()).add(dns_name)
            self.register_internal_lb(v2lb, by_template)

        for i in i2target_groups:
            by_instance.setdefault(i, {})
            for target_group in i2target_groups[i]:
                for port in i2target_groups[i][target_group]:
                    for dns_name in target_group2dns_names.get(
                            target_group, []):
                        by_instance[i].setdefault(port, []).append(
                            (dns_name2cidrs[dns_name],
                             v2lb_dict[dns_name]['Type'] == 'network'))

    def retrieve_foreign_internal_lbs(self, region, by_template):
        for sub_cred in self.sub_creds:
            elb_list, v2lb_dict = self.retrieve_all_elbs(
                region, sub_cred=sub_cred)
            for elb in elb_list:
                self.register_internal_lb(elb, by_template)
            for v2lb in v2lb_dict.values():
                self.register_internal_lb(v2lb, by_template)

    def validate_port_overlap(self, by_template):
        used_ports = {}
        for template in by_template:
            used_ports[template] = {}
            for dns_name, (protocol_ports, cidrs) in by_template[
                    template].iteritems():
                for port in [protocol_port.split('-')[1]
                             for protocol_port in protocol_ports]:
                    used_ports[template].setdefault(port, []).append(dns_name)
        exception_msg = []
        for port, DNS_name in [(port, used_ports[template][port]) for template
                               in used_ports for port in used_ports[template]
                               if 1 < len(used_ports[template][port])]:
            exception_msg.append('Multiple listeners on port %s: %s' %
                                 (port, ', '.join(DNS_name)))
        if exception_msg:
            raise Exception('\n' + '\n'.join(exception_msg))

    def retrieve_elbs(self, subnets):
        by_template = {}
        by_instance = {}
        result = {'by-template': by_template, 'by-instance': by_instance}
        if not self.sync.get('lb', False):
            return result
        for region in self.regions:
            by_template[region] = {}
            by_instance[region] = {}
            auto_scaling_groups = self.retrieve_all(
                'autoscaling', region, '/?Action=DescribeAutoScalingGroups',
                'DescribeAutoScalingGroupsResult', 'AutoScalingGroups')
            elb_list, v2lb_dict = self.retrieve_all_elbs(region)
            self.retrieve_classic_lbs(
                subnets[region], auto_scaling_groups, elb_list,
                by_template[region], by_instance[region])
            self.retrieve_v2_lbs(
                region, subnets[region], auto_scaling_groups, v2lb_dict,
                by_template[region], by_instance[region])
            self.retrieve_foreign_internal_lbs(region, by_template[region])
            self.validate_port_overlap(by_template[region])
        return result

    def retrieve_all(self, service, region, path, top_set, collect_set,
                     sub_cred=None):
        MEMBER = {'ec2': 'item'}.get(service, 'member')
        MARKER = {
            'autoscaling': 'NextToken',
            'cloudformation': 'NextToken',
            'ec2': 'NextToken',
            'elasticloadbalancing': 'Marker'}[service]
        NEXT_MARKER = {
            'autoscaling': 'NextToken',
            'cloudformation': 'NextToken',
            'ec2': 'nextToken',
            'elasticloadbalancing': 'NextMarker'}[service]
        objects = []
        marker = None
        while True:
            extra_params = ''
            if marker:
                extra_params += '&' + urllib.urlencode({MARKER: marker})
            headers, body = self.request(
                service, region, 'GET', path + extra_params, '',
                sub_cred=sub_cred)
            obj = aws.listify(body, MEMBER)
            top = obj[top_set]
            if top and not isinstance(top, list):
                marker = top.get(NEXT_MARKER)
                top = [top]
            else:
                marker = obj.get(NEXT_MARKER)
            for r in top:
                objects += r[collect_set]
            if not marker:
                break
        return objects

    def retrieve_instances(self):
        instances = {}
        for region in self.regions:
            instances[region] = self.retrieve_all(
                'ec2',
                region,
                '/?Action=DescribeInstances',
                'reservationSet', 'instancesSet')
            instances[region] = [
                i for i in instances[region]
                if self.get_tags(i.get('tagSet')).get(
                    'x-chkp-management') == self.management]
        return instances

    def get_tags(self, tag_list):
        if not tag_list:
            tag_list = []
        tags = collections.OrderedDict()
        joined = []
        for t in tag_list:
            k = t.get('key', t.get('Key'))
            v = t.get('value', t.get('Value', ''))
            if k.startswith('x-chkp-tags'):
                joined.append((k[len('x-chkp-tags'):], v))
            else:
                tags[k] = v
        for sep, joined_tags in sorted(joined):
            if not sep:
                sep = ':'
            for part in joined_tags.split(sep):
                key, es, value = part.partition('=')
                tags.setdefault('x-chkp-' + key, value)
        return tags

    def get_topology(self, eni, subnets):
        tags = self.get_tags(eni.get('tagSet'))
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

                tags = self.get_tags(instance.get('tagSet'))
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

                template = tags['x-chkp-template']
                load_balancers = {}
                internal_elbs = elbs['by-template'].get(
                    region, {}).get(template, {})
                external_elbs = elbs['by-instance'].get(region, {}).get(
                    instance['instanceId'], {})
                for dns_name in internal_elbs:
                    protocol_ports, tag_sources = internal_elbs[dns_name]
                    for protocol_port in protocol_ports:
                        cidrs_type = external_elbs.get(
                            protocol_port.split('-')[1], set())
                        transparent_cidrs = set(sum(
                            [ct[0] for ct in cidrs_type if ct[1]], []))
                        non_transparent_cidrs = set(sum(
                            [ct[0] for ct in cidrs_type if not ct[1]], []))
                        if tag_sources:
                            if non_transparent_cidrs:
                                raise Exception(
                                    '\nexternal non NLB with cidr or object '
                                    'tag on the internal LB %s' % dns_name)
                            sources = set(tag_sources) | transparent_cidrs
                        else:
                            if transparent_cidrs:
                                sources = set()
                            else:
                                sources = non_transparent_cidrs
                        load_balancers.setdefault(
                            dns_name, {})[protocol_port] = list(sources)
                instances.append(Instance(
                    instance_name, ip_address, interfaces, template,
                    load_balancers))
        return instances

    def retrieve_vpcs(self, vpcs, sub_cred):
        for region in self.regions:
            headers, body = self.request(
                'ec2', region, 'GET',
                '/?Action=DescribeVpcs&Version=2016-11-15', '',
                sub_cred=sub_cred)
            vpcs.setdefault(region, {})
            for v in aws.listify(body, 'item')['vpcSet']:
                v[self.CREDENTIAL] = sub_cred
                vpcs[region][v['vpcId']] = v

    def retrieve_vgws(self, vgws, sub_cred):
        for region in self.regions:
            headers, body = self.request(
                'ec2', region, 'GET', '/?Action=DescribeVpnGateways', '',
                sub_cred=sub_cred)
            vgws.setdefault(region, {})
            for v in aws.listify(body, 'item')['vpnGatewaySet']:
                vgws[region][v['vpnGatewayId']] = v
        return vgws

    def retrieve_vconns(self, vconns, sub_cred):
        for region in self.regions:
            headers, body = self.request(
                'ec2', region, 'GET', '/?Action=DescribeVpnConnections', '',
                sub_cred=sub_cred)
            vconns.setdefault(region, {})
            for s in aws.listify(body, 'item')['vpnConnectionSet']:
                if 'customerGatewayConfiguration' not in s:
                    continue
                if 'vpnGatewayId' not in s:
                    continue
                vconns[region][s['vpnConnectionId']] = s
                s['customerGatewayConfiguration'] = aws.parse_element(
                    aws.xml.dom.minidom.parseString(
                        s['customerGatewayConfiguration']))['vpn_connection']

    def retrieve_cgws(self, cgws, sub_cred):
        for region in self.regions:
            headers, body = self.request(
                'ec2', region, 'GET', '/?Action=DescribeCustomerGateways', '',
                sub_cred=sub_cred)
            cgws.setdefault(region, {})
            for c in aws.listify(body, 'item')['customerGatewaySet']:
                if c['state'] == 'deleted':
                    continue
                c[self.CREDENTIAL] = sub_cred
                cgws[region][c['customerGatewayId']] = c

    def retrieve_rtbs(self, rtbs, sub_cred):
        for region in self.regions:
            headers, body = self.request(
                'ec2', region, 'GET', '/?Action=DescribeRouteTables', '',
                sub_cred=sub_cred)
            rtbs.setdefault(region,  {})
            for rtb in aws.listify(body, 'item')['routeTableSet']:
                rtbs[region][rtb['routeTableId']] = rtb

    def retrieve_stacks(self, stacks, cred, test=False):
        for region in self.regions:
            stacks.setdefault(region, {})
            for stack in self.retrieve_all(
                    'cloudformation', region, '/?Action=DescribeStacks',
                    'DescribeStacksResult', 'Stacks', sub_cred=cred):
                match = re.match(r'stack/vpn-by-tag--(vpc-[0-9a-z]+)/.*$',
                                 stack['StackId'].split(':')[-1])
                if not match:
                    continue
                vpc_id = match.group(1)
                stacks[region][vpc_id] = stack
                log('\n%s: %s' % (stack['StackName'], stack['StackStatus']))
                if '_FAILED' not in stack['StackStatus']:
                    stack[self.CREDENTIAL] = cred
                    continue
                try:
                    reason = stack.get('StackStatusReason')
                    if reason:
                        log(': %s' % reason)
                    resources = self.retrieve_all(
                        'cloudformation', region,
                        '/?Action=DescribeStackResources&StackName=' +
                        stack['StackName'],
                        'DescribeStackResourcesResult', 'StackResources',
                        sub_cred=cred)
                    for resource in resources:
                        status = resource['ResourceStatus']
                        if '_PROGRESS' in status or '_COMPLETE' in status:
                            continue
                        log('\n  %s: %s' % (
                            resource['LogicalResourceId'], status))
                        reason = resource.get('ResourceStatusReason')
                        if reason:
                            log(': %s' % reason)
                finally:
                    if not test:
                        self.request(
                            'cloudformation', region, 'GET',
                            '/?Action=DeleteStack&StackName=' +
                            stack['StackName'], '', sub_cred=cred)

    def get_parameter(self, stack, key, split=None):
        for p in stack.get('Parameters'):
            if p['ParameterKey'] == key:
                value = p['ParameterValue']
                if split:
                    return value.split(split)
                return value
        if split:
            return []
        return None

    def get_sub_cidr(self, cidr):
        octets = cidr.partition('/')[0].split('.')
        return '%s.%s' % (octets[2], int(octets[3]) // 4 * 4)

    def update_used_cgws_cidrs(self, vgws, cgws, vconns, stacks, used_cgws,
                               sub_cidrs_by_vpc_id, sub_cidrs_by_cgw_addr):
        for vconn_id, vconn in vconns.items():
            used_cgws.add(vconn['customerGatewayId'])
            vgw_id = vconn['vpnGatewayId']
            vpc_id = vgws[vgw_id].get(self.VPC)
            vconn_tunnels = vconn[
                'customerGatewayConfiguration']['ipsec_tunnel']
            for tunnel in vconn_tunnels:
                addr = tunnel['customer_gateway'][
                    'tunnel_outside_address']['ip_address']
                sub_cidr = self.get_sub_cidr(tunnel['customer_gateway'][
                    'tunnel_inside_address']['ip_address'])
                if sub_cidr in sub_cidrs_by_cgw_addr.get(addr, set()):
                    log('\nWARNING: 169.254.%s/30 already used by %s' % (
                        sub_cidr, addr))
                sub_cidrs_by_cgw_addr.setdefault(addr, set()).add(sub_cidr)
                if vpc_id:
                    sub_cidrs_by_vpc_id.setdefault(vpc_id, set()).add(sub_cidr)
        for vpc_id, stack in stacks.items():
            cgw_ids = self.get_parameter(stack, 'cgws', ',')
            cidrs = self.get_parameter(stack, 'cidrs', ',')
            for i, cgw_id in enumerate(cgw_ids):
                used_cgws.add(cgw_id)
                for j in xrange(2):
                    sub_cidr = self.get_sub_cidr(cidrs[2 * i + j])
                    sub_cidrs_by_vpc_id.setdefault(vpc_id, set()).add(sub_cidr)
                    sub_cidrs_by_cgw_addr.setdefault(
                        cgws[cgw_id]['ipAddress'], set()).add(sub_cidr)

    def resolve_tag(self, prefix, vpn_tags, vpc):
        tag = self.get_tags(vpc.get('tagSet')).get('x-chkp-vpn')
        if not tag:
            return None, None
        log('\n%s: "%s"' % (vpc['vpcId'], tag))
        if ':' not in tag and '/' not in tag:
            return tag, tag
        if prefix is None:  # test
            prefixes = {'/'.join(t.split('/')[:-1] + [''])
                        for t in tag.split(':')}
            if len(prefixes) != 1:
                log(': no common prefix ["%s"]' % '" "'.join(prefixes))
            return tag, tag
        hub_tags = []
        for hub_tag in tag.split(':'):
            if not hub_tag.startswith(prefix):
                log(': "%s" must start with "%s"' % (hub_tag, prefix))
                return None, None
            new_tag = vpn_tags.get(hub_tag)
            if new_tag is None:
                log(': could not resolve "%s"' % hub_tag)
                return None, None
            hub_tags.append(new_tag)
        log(' -> (%s)' % '):('.join(hub_tags))
        return ' '.join(hub_tags), tag

    def get_cgw_ids(self, region, tag, orig_tag, vpc, cgws, cgw_by_cred_addr):
        cred = vpc[self.CREDENTIAL]
        cgw_by_addr = cgw_by_cred_addr.get(cred, {})
        cgw_ids = []
        for val in tag.split():
            cgw_ids.append(None)
            match_cgw = re.match(r'(cgw-[0-9a-f]{8})', val)
            if match_cgw:
                cgw_id = match_cgw.group(1)
                if cgw_id in cgws[region]:
                    cgw_ids[-1] = cgw_id
                else:
                    log('\nunknown customer gateway: "%s"' % cgw_id)
                continue
            match_addr = re.match(r'((\d{1,3}\.){3}\d{1,3})(@(\d+))?', val)
            if match_addr:
                addr = match_addr.group(1)
                asn = match_addr.group(4)
                cgw = cgw_by_addr.get(addr)
                if cgw and cgw['state'] == 'available':
                    cgw_id = cgw['customerGatewayId']
                    cgw_ids[-1] = cgw_id
                elif asn:
                    log('\ncreating customer gateway: %s %s' % (addr, asn))
                    cgw = self.request(
                        'ec2', region, 'GET', '/?' + urllib.urlencode({
                            'Action': 'CreateCustomerGateway',
                            'IpAddress': addr,
                            'Type': 'ipsec.1',
                            'BgpAsn': asn}), '', sub_cred=cred)[1][
                                'customerGateway']
                    cgw_id = cgw['customerGatewayId']
                    cgw_ids[-1] = cgw_id
                    cgw[self.CREDENTIAL] = cred
                    cgws[region][cgw_id] = cgw
                    cgw_by_addr[cgw['ipAddress']] = cgw
                    cgw_by_cred_addr[cred] = cgw_by_addr
                else:
                    log('\nmissing asn for customer gateway for "%s"' % addr)
                continue
            log('\nignoring unrecognized tag: "%s" in "%s" ("%s")' % (
                val, tag, orig_tag))
            cgw_ids.pop()
        return cgw_ids

    def get_free_cidr(self, vpc_id, addr,
                      sub_cidrs_by_vpc_id, sub_cidrs_by_cgw_addr):
        free = (self.FREE_CIDRS -
                sub_cidrs_by_vpc_id.setdefault(vpc_id, set()) -
                sub_cidrs_by_cgw_addr.setdefault(addr, set()))
        start = random.randrange(self.NUM_CIDRS)
        for i in xrange(self.NUM_CIDRS):
            j = (i + start) % self.NUM_CIDRS * 4
            sub_cidr = '%s.%s' % (j // 256, j % 256)
            if sub_cidr not in free:
                continue
            break
        else:
            raise Exception('no more CIDRs available')
        sub_cidrs_by_vpc_id[vpc_id].add(sub_cidr)
        sub_cidrs_by_cgw_addr[addr].add(sub_cidr)
        return '169.254.%s/30' % sub_cidr

    def provision(self, region, prefix, tag, vpc, cgw_ids, cidrs):
        def cf_resource(typ, props, deps=None):
            obj = {'Type': typ, 'Properties': props}
            if deps:
                obj['DependsOn'] = deps
            return obj

        resources = {}
        vpc_id = vpc['vpcId']
        vgw_ref = vpc.get(self.VGW)
        vgw_id = vgw_ref
        deps = None
        if not vgw_ref:
            resources['vgw'] = cf_resource(
                'AWS::EC2::VPNGateway', {'Type': 'ipsec.1'})
            vgw_ref = {'Ref': 'vgw'}
            resources['attachment'] = cf_resource(
                'AWS::EC2::VPCGatewayAttachment', {
                    'VpcId': vpc_id, 'VpnGatewayId': vgw_ref})
            deps = ['attachment']
            resources['propagation'] = cf_resource(
                'AWS::EC2::VPNGatewayRoutePropagation', {
                    'RouteTableIds': [vpc[self.RTB]],
                    'VpnGatewayId': vgw_ref},
                deps=deps)

        for i, cgw_id in enumerate(cgw_ids):
            resources['conn%d' % i] = cf_resource(
                'AWS::EC2::VPNConnection', {
                    'Type': 'ipsec.1',
                    'CustomerGatewayId': cgw_id,
                    'VpnGatewayId': vgw_ref,
                    'VpnTunnelOptionsSpecifications': [
                        {'TunnelInsideCidr': cidrs[2 * i]},
                        {'TunnelInsideCidr': cidrs[2 * i + 1]}]},
                deps=deps)

        log('\nprovisioning: %s [%s] "%s" (%s) (%s) (%s) (%s)' % (
            vpc_id, prefix, tag[0], tag[1], vgw_id,
            ' '.join(cgw_ids), ' '.join(cidrs)))

        self.request('cloudformation', region, 'GET', '/?' + urllib.urlencode({
            'Action': 'CreateStack',
            'StackName': 'vpn-by-tag' + '--' + vpc_id,
            'Parameters.member.1.ParameterKey': 'cgws',
            'Parameters.member.1.ParameterValue': ','.join(cgw_ids),
            'Parameters.member.2.ParameterKey': 'cidrs',
            'Parameters.member.2.ParameterValue': ','.join(cidrs),
            'Parameters.member.3.ParameterKey': 'prefix',
            'Parameters.member.3.ParameterValue': prefix,
            'TemplateBody': json.dumps({
                'Parameters': {
                    'cgws': {'Type': 'String'}, 'cidrs': {'Type': 'String'},
                    'prefix': {'Type': 'String'}},
                'Resources': resources}, separators=(',', ':')),
            'OnFailure': 'DO_NOTHING'}), '', sub_cred=vpc[self.CREDENTIAL])

    def vpn_by_tag(self, vpn_env, vpcs, vgws, vconns, test=False):
        if test and vpn_env is None:
            vpn_env = None, {}, {}
        prefix, vpn_tags, gw_tun_addrs = vpn_env
        cgws = {}
        rtbs = {}
        stacks = {}
        for cred in [None] + self.sub_creds.keys():
            self.retrieve_cgws(cgws, cred)
            self.retrieve_rtbs(rtbs, cred)
            self.retrieve_stacks(stacks, cred, test)

        sub_cidrs_by_vpc_id = {}
        sub_cidrs_by_cgw_addr = {}
        used_cgws = {}
        for region in self.regions:
            self.update_used_cgws_cidrs(
                vgws[region], cgws[region], vconns[region], stacks[region],
                used_cgws.setdefault(region, set()), sub_cidrs_by_vpc_id,
                sub_cidrs_by_cgw_addr)

        if test:
            log('\nUsed tunnel CIDRs by vpc ID and gateway address:')
            for d in [sub_cidrs_by_vpc_id, sub_cidrs_by_cgw_addr]:
                for k in sorted(d):
                    log('\n  %s' % k)
                    for c in sorted(d[k]):
                        log('\n    169.254.%s/30' % c)

        for gw_addr, tun_addrs in gw_tun_addrs.items():
            if not tun_addrs:
                continue
            for tun_addr in tun_addrs.split(':'):
                if not tun_addr.startswith('169.254.'):
                    continue
                sub_cidrs = sub_cidrs_by_cgw_addr.setdefault(gw_addr, set())
                sub_cidr = self.get_sub_cidr(tun_addr)
                if sub_cidr not in sub_cidrs:
                    log('\nGateway %s uses 169.254.%s/30' % (
                        gw_addr, sub_cidr))
                    sub_cidrs.add(sub_cidr)

        for region in self.regions:
            log('\n%s' % region)
            cgw_by_cred_addr = {}
            for cgw in cgws[region].values():
                cgw_by_cred_addr.setdefault(cgw[self.CREDENTIAL], {})[
                    cgw['ipAddress']] = cgw
            for rtb in rtbs[region].values():
                if rtb['vpcId'] not in vpcs[region]:
                    continue
                if any(a['main'] == 'true' for a in rtb['associationSet']):
                    assert self.RTB not in vpcs[region][rtb['vpcId']]  # FIXME
                    vpcs[region][rtb['vpcId']][self.RTB] = rtb['routeTableId']
            tagged_vpcs = set()
            updated_vpcs = set()
            for vpc_id in vpcs[region]:
                vpc = vpcs[region][vpc_id]
                tag, orig_tag = self.resolve_tag(prefix, vpn_tags, vpc)
                if not tag:
                    continue
                tagged_vpcs.add(vpc_id)
                if test:
                    log('\nwould synchronize: %s' % vpc_id)
                    continue
                cgw_ids = self.get_cgw_ids(
                    region, tag, orig_tag, vpc, cgws, cgw_by_cred_addr)
                if None in cgw_ids:
                    log('\nskipping: %s "%s" (%s)' % (vpc_id, tag, orig_tag))
                    continue

                stack = stacks[region].get(vpc_id)
                if stack:
                    old_cgws = set(self.get_parameter(stack, 'cgws', ','))
                    new_cgws = set(cgw_ids)
                    if old_cgws != new_cgws:
                        log('\nneed to reprovision: %s "%s" (%s) (%s->%s)' % (
                            vpc_id, tag, orig_tag,
                            sorted([str(c) for c in old_cgws]),
                            sorted([str(c) for c in new_cgws])))
                        updated_vpcs.add(vpc_id)
                    continue

                if not cgw_ids:
                    continue

                cidrs = []
                for cgw_id in cgw_ids:
                    used_cgws[region].add(cgw_id)
                    addr = cgws[region][cgw_id]['ipAddress']
                    for _ in xrange(2):
                        cidrs.append(self.get_free_cidr(
                            vpc_id, addr,
                            sub_cidrs_by_vpc_id, sub_cidrs_by_cgw_addr))
                self.provision(
                    region, prefix, (tag, orig_tag), vpc, cgw_ids, cidrs)

            for vpc_id in (
                    set(stacks[region]) - set(tagged_vpcs)) | updated_vpcs:
                stack = stacks[region][vpc_id]
                stack_prefix = self.get_parameter(stack, 'prefix')
                if stack_prefix is None:
                    log('\n%s has no prefix parameter' %
                        stack['StackName'])
                elif stack_prefix != prefix:
                    continue
                if stack['StackStatus'] == 'DELETE_IN_PROGRESS':
                    continue
                if test:
                    log('\nwould deprovision: %s' % stack['StackName'])
                    continue
                log('\ndeprovisioning: %s' % stack['StackName'])
                self.request(
                    'cloudformation', region, 'GET',
                    '/?Action=DeleteStack&StackName=' + stack['StackName'], '',
                    sub_cred=stack[self.CREDENTIAL])

            for cgw_id in set(cgws[region]) - used_cgws[region]:
                cgw = cgws[region][cgw_id]
                if cgw.get('tagSet', []):
                    continue
                if test:
                    log('\nwould delete: %s' % cgw_id)
                    continue
                log('\ndeleting customer gateway %s (%s %s)' % (
                    cgw_id, cgw['ipAddress'], cgw['bgpAsn']))
                self.request(
                    'ec2', region, 'GET',
                    '/?Action=DeleteCustomerGateway&CustomerGatewayId=' +
                    cgw_id, '', sub_cred=cgw[self.CREDENTIAL])
        log('\n')

    def get_vpn_conns(self, vpn_env=None, test=False):
        vpcs = {}
        vgws = {}
        vconns = {}
        for cred in [None] + self.sub_creds.keys():
            self.retrieve_vpcs(vpcs, cred)
            self.retrieve_vgws(vgws, cred)
            self.retrieve_vconns(vconns, cred)
        for region in self.regions:
            for vgw_id in vgws[region]:
                vgw = vgws[region][vgw_id]
                for attachment in vgw.get('attachments', []):
                    if attachment['state'] != 'attached':
                        continue
                    vpc = vpcs[region].get(attachment['vpcId'])
                    if vpc:
                        assert self.VGW not in vpc
                        vpc[self.VGW] = vgw_id
                        assert self.VPC not in vgw
                        vgw[self.VPC] = vpc['vpcId']

        self.vpn_by_tag(vpn_env, vpcs, vgws, vconns, test=test)

        vpn_conns = []
        for region in self.regions:
            for vconn in vconns.get(region, {}).values():
                short_name = vconn['vpnConnectionId']
                base_name = self.SEPARATOR.join([
                    self.name, short_name, region])
                tag = self.get_tags(vconn.get('tagSet')).get('x-chkp-vpn')
                vpc_id = vgws[region].get(vconn['vpnGatewayId'], {}).get(
                    self.VPC)
                vpc = None
                if vpc_id:
                    vpc = vpcs[region].get(vpc_id)
                if not vpc:
                    log('\nskipping %s - no vpc' % short_name)
                    continue
                cidr_set = set()
                for assoc in vpc['cidrBlockAssociationSet']:
                    if assoc['cidrBlockState']['state'] != 'associated':
                        continue
                    cidr_set.add(assoc['cidrBlock'])
                cidr_set.discard(vpc['cidrBlock'])
                cidrs = ','.join([vpc['cidrBlock']] + sorted(cidr_set))
                vconn_tunnels = vconn[
                    'customerGatewayConfiguration']['ipsec_tunnel']
                if any('bgp' not in t['vpn_gateway'] for t in vconn_tunnels):
                    log('\nat least one non-BGP tunnel for %s' % short_name)
                    continue
                for tunnel in vconn_tunnels:
                    peer = tunnel['vpn_gateway'][
                        'tunnel_outside_address']['ip_address']
                    remote = tunnel['vpn_gateway'][
                        'tunnel_inside_address']['ip_address']
                    gateway = tunnel['customer_gateway'][
                        'tunnel_outside_address']['ip_address']
                    local = tunnel['customer_gateway'][
                        'tunnel_inside_address']['ip_address']
                    asn = tunnel['vpn_gateway']['bgp']['asn']
                    pre_shared_key = tunnel['ike']['pre_shared_key']
                    name = self.SEPARATOR.join([base_name, peer])
                    vpn_conns.append(
                        VPNConn(name, self.name, short_name, tag, gateway,
                                peer, local, remote, asn, pre_shared_key,
                                cidrs))
        return vpn_conns

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

    def get_vmss_address(self, address_type, config, vmss_pips):
        if address_type == 'private':
            return config.get('privateIPAddress')
        elif address_type == 'public':
            id = config.get('publicIPAddress', {}).get('id')
            if not id:
                log('no public address for interface\n')
                return None
            pip = vmss_pips.get(id)
            if not pip:
                log('no public address with id %s\n' % id)
                return None
            return pip['properties'].get('ipAddress')
        else:
            log('unsupported address type %s\n' % address_type)
            return None

    def get_vmss(self, subnets):
        instances = []

        vmsss = self.azure.arm(
            'GET',
            '%s/providers/Microsoft.Compute/virtualMachineScaleSets' %
            self.sub)[1]['value']
        for vmss in vmsss:
            tags = vmss.get('tags', {})
            if tags.get('x-chkp-management') != self.management:
                continue

            address_type = tags.get('x-chkp-ip-address', 'private')
            mgmt_nic = tags.get('x-chkp-management-interface')
            if mgmt_nic != 'eth0' and address_type == 'public':
                raise Exception('can\'t use %s to manage with public IP '
                                'address. Adjust VMSS tags.' % mgmt_nic)
            anti_spoofing = {}
            for s in tags.get('x-chkp-anti-spoofing', '').split(','):
                if not s:
                    continue
                ifname, _, val = s.partition(':')
                if val.lower() == 'false':
                    anti_spoofing[ifname] = False
                else:
                    anti_spoofing[ifname] = True

            topology = {}
            for t in tags.get('x-chkp-topology', '').split(','):
                if not t:
                    continue
                ifname, _, val = t.partition(':')
                topology[ifname] = val

            vms = self.azure.arm(
                'GET', vmss['id'] + '/virtualMachines')[1]['value']

            if self.azure.environment.name == 'AzureCloud':
                api = '?api-version=2017-03-30'
                vmss_pips = self.azure.arm(
                    'GET', vmss['id'] + '/publicipaddresses' + api)[1]['value']
                vmss_pips = {pip['id']: pip for pip in vmss_pips}
            else:
                api = ''
                vmss_pips = {}

            vmss_nics = self.azure.arm(
                'GET', vmss['id'] + '/networkInterfaces' + api)[1]['value']
            vmss_nics = {nic['id']: nic for nic in vmss_nics}

            for vm in vms:
                name = self.SEPARATOR.join([
                    self.name, vm['name'], vm['id'].split('/')[4]])
                interfaces = []
                ip_address = None
                vm_nics = vm['properties']['networkProfile'][
                    'networkInterfaces']
                for nic in vm_nics:
                    interface = vmss_nics.get(nic['id'])
                    if not interface:
                        log('no interface %s for %s\n' % (
                            nic['id'], vm['name']))
                        break
                    ifname = interface['name']
                    config = self.get_primary_configuration(interface)
                    if not config:
                        log('no primary interface config for %s\n' % vm[
                            'name'])
                        break
                    interfaces.append({
                        'name': ifname,
                        'ipv4-address': config['privateIPAddress'],
                        'ipv4-mask-length':
                            int(subnets[config['subnet']['id']]['properties'][
                                'addressPrefix'].partition('/')[2]),
                        'anti-spoofing': anti_spoofing.get(ifname, True),
                        'topology': topology.get(ifname, 'external')
                    })
                    if len(vm_nics) == 1 or ifname == mgmt_nic or (
                            mgmt_nic is None
                            and nic['properties'].get('primary')):
                        ip_address = self.get_vmss_address(
                            address_type, config, vmss_pips)
                        if not ip_address:
                            log('no address for %s\n' % vm['name'])
                            break
                else:
                    instances.append(Instance(
                        name, ip_address, interfaces, tags['x-chkp-template']))

        return instances

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

        instances += self.get_vmss(subnets)
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
        proxy = os.environ.get('https_proxy')
        if proxy:
            no_proxy = os.environ.get('no_proxy', set())
            if no_proxy:
                no_proxy = set(no_proxy.split(','))
            if self.host not in no_proxy:
                self.set_tunnel(self.host, self.port)
                self.host, _, self.port = urlparse.urlsplit(
                    proxy).netloc.partition(':')
                if self.port:
                    self.port = int(self.port)
                else:
                    self.port = 8080
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


def http(method, url, fingerprint, headers, body, redact_patterns=None):
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
        with redact(debuglevel > 0, debug,
                    redact_patterns if redact_patterns else []):
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
                print 'body: %s' % repr(body)
    return headers, body


def run_local(cmd, data=None, env=None):
    if isinstance(cmd, basestring):
        shell = True
    else:
        shell = False
        if cmd[0].startswith('./'):
            cmd = [
                os.path.join(os.path.dirname(__file__), cmd[0][2:])] + cmd[1:]
    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=shell, env=proc_env)
    out, err = proc.communicate(data)
    status = proc.wait()
    return out, err, status


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
    RESTRICTIVE_POLICY = MONITOR_PREFIX + 'restrictive-policy'
    ONCE_PREFIX = '__once__'
    GATEWAY_PREFIX = '__gateway__'
    VSEC_DUMMY_HOST = DUMMY_PREFIX + 'vsec_internal_host'
    CONTROLLER_PREFIX = '__controller__'
    CIDR_PREFIX = '__cidr__'
    VPN_PREFIX = '__vpn__'
    COMMUNITY_PREFIX = '__community__'
    SPOKE_ROUTES = 'spoke-routes'
    EXPORT_ROUTES = 'export-routes'

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
    CPMI_INTERFACE = (
        'com.checkpoint.objects.classes.dummy.CpmiInterface')
    CPMI_INTERFACE_SECURITY = (
        'com.checkpoint.objects.classes.dummy.CpmiInterfaceSecurity')
    CPMI_NETACCESS = 'com.checkpoint.objects.classes.dummy.CpmiNetaccess'
    CPMI_GATEWAY_PLAIN = (
        'com.checkpoint.objects.classes.dummy.CpmiGatewayPlain')

    BAD_SESSION_PATTERNS = [
        re.compile(r'.*Wrong session id'),
        re.compile(r'.* locked[: ]'),
        re.compile(r'.* has no permission '),
        re.compile(r'.*Operation is not allowed in read only mode'),
        re.compile(r'.*Work session was not found'),
        # FIXME: this is a normal failure for management HA
        re.compile(r'.*This domain is in standby mode on this machine'),
        re.compile(r'.*Management server failed to execute command')]

    GET_INTERFACES = [
        ('get-interfaces-sync', 'v1.3'), ('get-interfaces', 'v1.1'),
    ]

    IDA_API_MAIN_URI = 'https://0.0.0.0/_IA_API'
    IDA_API_MAIN_URI_R77_30 = 'https://0.0.0.0/_IA_MU_Agent'

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
        self.last_action_time = 0
        self.local_host_uid = None
        self.targets = {}
        self.get_interfaces_command_version = None

        if 'proxy' in options:
            os.environ['https_proxy'] = options['proxy']

        no_proxy = set(os.environ.get('no_proxy', '').split(','))
        no_proxy -= {''}
        no_proxy |= {'127.0.0.1', 'localhost'}
        os.environ['no_proxy'] = ','.join(no_proxy)

    def __call__(self, command, body, aggregate=None,
                 silent=False, version='v1'):
        redact_patterns = [(r'send: .*x-chkp-sid\s*:\s*([^\\]*)\\.*$', '***')]
        if command == 'login':
            redact_patterns = [
                (r'send: .*"password"\s*:\s*"([^"]*)".*$', '***'),
                (r'body: .*"sid"\s*:\s*"([^"]*)".*$', '***')]
            c = '+'
        elif command == 'logout':
            if not self.sid:
                return None
            c = '-'
        elif command == 'publish':
            if not self.sid:
                raise Exception('cannot publish with no sid')
            c = '|'
        else:
            if not self.sid or (
                    (time.time() - self.last_action_time) >
                    self.session_timeout):
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
                'POST', 'https://%s/web_api/%s/%s' % (
                    self.host, version, command),
                self.fingerprint, headers, json.dumps(body), redact_patterns)
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
                    log('\nresetting session id')
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
                    command.startswith('get-interfaces') or
                    command.startswith('delete-')):
                self('publish', {})
            if command == 'logout':
                self.sid = None
            if not aggregate:
                self.last_action_time = time.time()
                return payload
            objects += payload[aggregate]
            if payload['total'] == 0 or payload['total'] <= payload['to']:
                self.last_action_time = time.time()
                return objects
            offset = payload['to']

    def in_domain(self, obj):
        domain = 'SMC User' if self.domain is None else self.domain
        return obj['domain']['name'] == domain

    def command_available(self, command, version='v1.1'):
        try:
            self(command, {
                '__no_such_parameter__': None}, version=version, silent=True)
        except Exception as e:
            if 'Unrecognized parameter [__no_such_parameter__]' in str(e):
                return True
            elif 'Unknown API version' in str(e):
                return False
            elif 'command: [%s] not found' % command in str(e):
                return False
            raise

    def __enter__(self):
        try:
            self.last_action_time = time.time()
            if not self.user:
                progress('+')
                login_args = ['mgmt_cli', '--root', 'true', '--format', 'json',
                              'login']
                if self.domain:
                    login_args += ['domain', self.domain]
                out, err, rc = run_local(login_args)
                if rc:
                    raise Exception('\nfailed to run %s: %s\n%s\n%s' % (
                        login_args, rc, err, out))
                resp = json.loads(out)
            else:
                login_data = {'user': self.user, 'password': self.password}
                if self.domain:
                    login_data['domain'] = self.domain
                resp = self('login', login_data)
            self.sid = resp['sid']
            self.session_timeout = resp['session-timeout']
            self.session_timeout = max(
                self.session_timeout // 2, self.session_timeout - 50)

            log('\nnew session:  %s' % resp['uid'])
            with_take_over = self.command_available(
                'take-over-session', version='v1.2')
            for session in self('show-sessions', {'details-level': 'full'},
                                aggregate='objects'):
                if session['uid'] == resp['uid'] or (
                        not self.in_domain(session) or
                        session['application'] != 'WEB_API'):
                    continue
                log('\ndiscarding session: %s' % session['uid'])
                try:
                    if with_take_over:
                        self('take-over-session', {
                            'uid': session['uid'],
                            'disconnect-active-session': True},
                            silent=True,
                            version='v1.2')
                        self('discard', {}, silent=True)
                    else:
                        self('discard', {'uid': session['uid']}, silent=True)
                except Exception:
                    debug('\n%s' % traceback.format_exc())
                    log('\ndiscard uid %s: failed' % session['uid'])
                    if not self.sid:
                        log('\nrestoring sid')
                        self.sid = resp['sid']

            if self.get_interfaces_command_version is None:
                self.get_interfaces_command_version = (None, None)
                for (command, version) in self.GET_INTERFACES:
                    if self.command_available(command, version):
                        self.get_interfaces_command_version = (
                            command, version)
                        break

            return self
        except:
            self.__exit__(*sys.exc_info())
            raise

    def __exit__(self, type, value, tb):
        try:
            if self.sid:
                self('discard', {})
                self('logout', {})
            else:
                log('\ncalled __exit__ with no sid')
        except Exception:
            log('\n%s' % traceback.format_exc())

    def run_script(self, target, script, name=None):
        if not name:
            name = script[:100]
            if name != script:
                name += '...'
        log('\nrunning: %s on %s' % (json.dumps(script), target))
        run_script_x = os.path.join(os.path.dirname(__file__), 'run-script')
        if os.path.exists(run_script_x):
            addr = self('show-simple-gateway',
                        {'name': target})['ipv4-address']
            out, err, status = run_local([run_script_x, addr, script])
            if status:
                raise Exception('run-script failed\n%s\n%s' % (out, err))
            return out
        response = self('run-script', {
            'script-name': name,
            'script': script,
            'targets': [target]}).get('task-details', [{}])[0]
        if response.get('statusCode') != self.SUCCEEDED:
            raise Exception('run-script failed\n%s' % (
                base64.b64decode(response.get('responseError'))))
        return base64.b64decode(response.get('responseMessage'))

    def get_gateway(self, name, filtered=True, version='v1'):
        try:
            gw = self('show-simple-gateway', {'name': name}, silent=True,
                      version=version)
        except Exception:
            # FIXME: remove when all gateways are able to show
            if str(sys.exc_info()[1]).endswith(
                    'Runtime error: Unmarshalling Error: Unable to ' +
                    'create an instance of com.checkpoint.management.' +
                    'dlecommon.ngm_api.CpmiOwned '):
                return None
            elif 'Operations with SMB gateways are unsupported' in str(
                    sys.exc_info()[1]):
                return None
            else:
                raise
        if filtered and TAG not in self.get_object_tags(gw):
            return None
        return gw

    def get_gateways(self, filtered=True, version='v1'):
        objects = self('show-simple-gateways', {}, aggregate='objects')
        gateways = {}
        for name in (o['name'] for o in objects):
            gw = self.get_gateway(name, filtered=filtered, version=version)
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
        if value is not None:
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

    def get_uid(self, name, obj_type=None):
        objects = self('show-generic-objects', {'name': name},
                       aggregate='objects')
        if obj_type:
            objects = [o for o in objects if o['type'] == obj_type]
        by_name = [o for o in objects if o['name'] == name]
        if len(by_name) == 1:
            return by_name[0]['uid']
        if not len(by_name):
            return None
        by_domain = [o for o in by_name if self.in_domain(o)]
        if len(by_domain) == 1:
            return by_domain[0]['uid']
        if not len(by_domain):
            by_domain = [o for o in by_name if o['domain']['name'] == 'Global']
            if len(by_domain) == 1:
                return by_domain[0]['uid']
        raise Exception('more than one object named "%s"' % name)

    def set_proxy(self, gw, proxy_ports):
        log('\n%s: %s' % ('setting proxy', json.dumps(proxy_ports)))
        uid = gw['uid']
        if not proxy_ports:
            self('set-generic-object', {'uid': uid, 'proxyOnGwEnabled': False})
            return

        gw_gen = self('show-generic-object', {'uid': uid})

        body = None
        ports = gw_gen['proxyOnGwSettings']['ports']
        # FIXME: would not be needed when we can assign to an empty value.
        if not ports:
            ports = {'add': proxy_ports}
        else:
            ports = proxy_ports

        if gw['version'] == 'R77.30':
            body = {
                'uid': uid,
                'proxyOnGwEnabled': True,
                'proxyOnGwSettings': {
                    'interfacesType': 'ALL_INTERFACES',
                    'ports': ports,
                    'tarnsparentMode': False}}
        else:
            body = {
                'uid': uid,
                'proxyOnGwEnabled': True,
                'proxyOnGwSettings': {
                    'interfacesType': 'INTERNAL_INTERFACES',
                    'ports': ports,
                    'tarnsparentMode': False}}
            if len(gw['interfaces']) == 1:
                body['proxyOnGwSettings'][
                    'interfacesType'] = 'SPECIFIC_INTERFACES'
                body['proxyOnGwSettings'][
                    'interfacesList'] = [
                        self.build_proxy_interface(gw_gen['interfaces'][0])]

        self('set-generic-object', body)

    def build_proxy_interface(self, gw_interface):
        interface = {'create': self.CPMI_INTERFACE, 'owned-object': {}}

        attributes_to_ignore = ('folder', 'domainId', 'folderPath', 'objId',
                                'text', 'checkPointObjId', 'domainsPreset')
        for field in gw_interface:
            if field in attributes_to_ignore:
                continue
            elif field == 'security':
                security = {
                    'create': self.CPMI_INTERFACE_SECURITY, 'owned-object': {}}
                gw_security = gw_interface['security']
                for field in gw_security:
                    if field in attributes_to_ignore:
                        continue
                    elif field == 'netaccess':
                        net_access = {
                            'create': self.CPMI_NETACCESS, 'owned-object': {}}
                        gw_net_access = gw_security['netaccess']
                        for field in gw_net_access:
                            if field in attributes_to_ignore:
                                continue
                            else:
                                net_access['owned-object'][
                                    field] = gw_net_access[field]
                        security['owned-object'][
                            'netaccess'] = net_access
                    else:
                        security[field] = gw_security[field]
                interface['owned-object']['security'] = security
            else:
                interface['owned-object'][field] = gw_interface[field]
        return interface

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

    def init_identity_awareness_r77_30(self, gw):
        uid = gw['uid']
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
                    'isCollectingIdentities': False,
                    'identityAwareBladeInstalled': 'NOT_MINUS_INSTALLED'}}}

        gw_obj.update(
            self.get_ida_portal(
                'IAMUAgent', self.IDA_API_MAIN_URI_R77_30))

        gw_obj.update(self.get_ida_realm())
        self('set-generic-object', gw_obj)

    def get_ida_realm(self):
        return {'realmsForBlades': {
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
                                    }}}}}}}}}

    def get_ida_portal(self, portal_name, main_uri):
        return {'portals': {
            'add': {
                'create': self.CPMI_PORTAL_SETTINGS,
                'owned-object': {
                    'internalPort': 8886,
                    'portalName': portal_name,
                    'portalAccess': 'ALL_INTERFACES',
                    'mainUrl': main_uri,
                    'ipAddress': '0.0.0.0'}}}}

    def set_identity_awareness(self, gw_uid, enable):
        self('set-generic-object', {
            'uid': gw_uid,
            'identityAwareBlade': {
                'identityAwareBladeInstalled':
                    'INSTALLED' if enable else 'NOT_MINUS_INSTALLED',
                'isCollectingIdentities':
                    True if enable else False,
                'enableAppiProxyUsersDetection':
                    True if enable else False}})

    def init_identity_awareness(self, gw):
        uid = gw['uid']

        gw_obj = {
            'uid': uid,
            'identityAwareBlade': {
                'create': self.CPMI_IDENTITY_AWARE_BLADE,
                'owned-object': {
                    'enableIdaApi': True,
                    'idcSettings': [],
                    'isCollectingIdentities': False,
                    'identityAwareBladeInstalled': 'NOT_MINUS_INSTALLED'}}}

        gw_obj.update(
            self.get_ida_portal(
                'IAAPI', self.IDA_API_MAIN_URI))

        gw_obj.update(self.get_ida_realm())

        self('set-generic-object', gw_obj)

        with open('/dev/urandom') as f:
            psk = base64.b64encode(f.read(12))

        if not self.local_host_uid:
            self.local_host_uid = self.get_uid(self.VSEC_DUMMY_HOST)
            if not self.local_host_uid:
                host_body = self('add-host', {
                    'name': self.VSEC_DUMMY_HOST,
                    'ip-address': '127.0.0.1',
                    'ignore-warnings': True})
                self.local_host_uid = host_body.get('uid')

        debug('\nCreating new IDA owned object')
        client_obj = {
            'uid': uid,
            'identityAwareBlade': {
                'idaApiSettings': {
                    'idaApiClientVerificationSettings': {
                        'add': {
                            'create':
                                'com.checkpoint.objects.'
                                'identity_awareness_classes.dummy.'
                                'CpmiIdentityAwareClientVerificationEntry',
                            'owned-object': {
                                'preSharedSecret': psk,
                                'whiteListClient': self.local_host_uid
                            }
                        }
                    }
                }
            }
        }

        self('set-generic-object', client_obj)

    def set_vpn_community_star_as_center(self, gw, communities):
        if isinstance(communities, basestring):
            communities = [communities]
        for community in communities:
            log('\nadding %s to community %s' % (gw['name'], community))
            self(
                'set-vpn-community-star', {
                    'name': community, 'center-gateways': {'add': gw['uid']}},
                version='v1.1')

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
        load_balancers = instance.load_balancers
        if load_balancers is None:
            return [None, None]
        parts = []
        old_parts = []
        for dns_name in load_balancers:
            protocol_ports = load_balancers[dns_name]
            for protocol_port in protocol_ports:
                old_protocol_port_parts = protocol_port.split('-')
                if old_protocol_port_parts[1] == old_protocol_port_parts[2]:
                    old_protocol_port_parts.pop(2)
                parts.append('-'.join(
                    [protocol_port] + sorted(
                        protocol_ports[protocol_port])))
                old_parts.append('-'.join(
                    ['-'.join(old_protocol_port_parts)] + sorted(
                        protocol_ports[protocol_port])))
        return [':'.join(sorted(parts)), ':'.join(sorted(old_parts))]

    def get_unique_name(self, base, ext_len=6, retries=100):
        for i in xrange(retries):
            extension = ''.join([random.choice('0123456789' +
                                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                                               'abcdefghijklmnopqrstuvwxyz')
                                 for j in xrange(ext_len)])
            candidate = '%s_%s' % (base, extension)
            if self.get_uid(candidate):
                continue
            return candidate
        raise Exception('Failed to find a unique name for "%s"' % base)

    def get_flat_rules(self, command, body):
        body['limit'] = 100
        body['offset'] = 0
        rules = collections.OrderedDict()
        while True:
            response = self(command, body)
            top_rules = response['rulebase']
            if not top_rules:
                break
            for top_rule in top_rules:
                sub_rules = top_rule.pop('rulebase', [])
                rules[top_rule['uid']] = top_rule
                for sub_rule in sub_rules:
                    rules[sub_rule['uid']] = sub_rule
            if body['offset'] + body['limit'] > response['total']:
                break
            body['offset'] = response['to'] - 1
        return rules.values()

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

    def add_load_balancer(self, gw, policy, section_name, dns_name,
                          protocol_ports):
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
        logical_server = self.get_unique_name(dns_name)
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
            raise Exception('failed to find a firewall layer in "%s"' % layer)
        for layer in layers:
            for section in self.get_rulebase(layer['uid'], sections=True):
                if section.get('name') == section_name:
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
            if section.get('name') == section_name:
                nat_position = {'below': section['uid']}
                break
        else:
            nat_position = 'top'
        for protocol_port in protocol_ports:
            lb_protocol, port, translated = protocol_port.split('-')
            services = []
            # add a service
            for p in [port, translated]:
                service = '%s-%s_%s' % (lb_protocol, p, gw['name'])
                services.append(service)
                if self.get_uid(service, obj_type='service-tcp'):
                    continue
                protocol = {'HTTP': 'HTTP', 'HTTPS': 'ENC-HTTP',
                            'SSL': 'TLS12', 'TCP': None}[lb_protocol]
                log('\nadding %s' % service)
                self('add-service-tcp', {
                    'name': service, 'port': p, 'match-for-any': False,
                    'ignore-warnings': True, 'protocol': protocol},
                    version='v1.1')
            service_name = services[0]
            # add subnets
            sources = []
            for source_item in protocol_ports[protocol_port]:
                if re.compile(CIDRS_REGEX).match(source_item):
                    net, slash, mask = source_item.partition('/')
                    net_name = '%s-%s_%s' % (net, mask, service_name)
                    log('\nadding %s' % net_name)
                    sources.append(self('add-network', {
                        'ignore-warnings': True,  # re-use of subnet/mask
                        'name': net_name, 'subnet': net,
                        'mask-length': int(mask)})['uid'])
                else:
                    if not self.get_uid(source_item):
                        raise Exception(
                            'object %s was not found' % source_item)
                    sources.append(source_item)
            source = 'Any'
            original_source = 'All_Internet'
            if sources:
                group_name = 'net-group_%s' % service_name
                log('\nadding %s' % group_name)
                group_uid = self('add-group', {
                    'name': group_name, 'members': sources})['uid']
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
            nat_rule_body = {
                'comments': 'nat_%s' % service_name,
                'package': policy,
                'position': nat_position,
                'original-source': original_source,
                'original-destination': private_name,
                'original-service': service_name,
                'translated-source': nat_name,
                'method': 'hide',
                'install-on': gw['name']}
            if 2 == len(set(services)):
                nat_rule_body['translated-service'] = services[-1]
            self('add-nat-rule', nat_rule_body)

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
        env = {}
        if self.domain:
            env['AUTOPROVISION_DOMAIN'] = self.domain
        if parameters is None:
            cmd = [self.custom_script, 'delete', name]
        else:
            if isinstance(parameters, basestring):
                parameters = re.split(r'\s+', parameters)
            cmd = [self.custom_script, 'add', name] + parameters
        log('\ncustomizing %s\n' % cmd)
        out, err, status = run_local(cmd, env=env)
        log(err)
        log(out)
        return not status

    def delete_objects_for_gw(self, gw):
        name = gw['name']
        log('\n%s: %s' % ('deleting objects for', name))
        policies = [p['name']
                    for p in self('show-packages', {}, aggregate='packages')]
        for policy in policies:
            try:
                # remove nat rules installed on the deleted gateway
                rules = self.get_rulebase(policy, nat=True)
                for rule in rules:
                    if gw['uid'] in rule['install-on']:
                        log('\ndeleting %s in "%s"' % (
                            rule['comments'], policy))
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
            except Exception:
                log('\n%s' % traceback.format_exc())
                log('\nskipping policy "%s"' % policy)
        # remove from communities
        for comm_name, centers, satellites in self.get_star_communities():
            if gw['name'] in satellites:
                log('\nremoving from %s satellites' % comm_name)
                self(
                    'set-vpn-community-star', {
                        'name': comm_name,
                        'satellite-gateways': {'remove': gw['name']},
                        'ignore-warnings': True},
                    version='v1.1')
            if gw['name'] in centers:
                log('\nremoving from %s centers' % comm_name)
                self(
                    'set-vpn-community-star', {
                        'name': comm_name,
                        'center-gateways': {'remove': gw['name']},
                        'ignore-warnings': True},
                    version='v1.1')
        for community in self(
                'show-vpn-communities-meshed', {'details-level': 'full'},
                aggregate='objects', version='v1.1'):
            if gw['name'] in community['gateways']:
                log('\nremoving from %s' % community['name'])
                self(
                    'set-vpn-community-meshed', {
                        'name': community['name'],
                        'gateways': {'remove': gw['name']},
                        'ignore-warnings': True},
                    version='v1.1')
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

    def reset_gateway(self, name, delete_gw=False, delete_objects=False):
        log('\n%s: %s' % ('deleting' if delete_gw else 'resetting', name))
        self.customize(name)
        gw = self.get_gateway(name)
        self.set_policy(gw, None)
        if delete_objects or delete_gw and self.get_object_tag_value(
                gw, self.LOAD_BALANCER_PREFIX) is not None:
            self.delete_objects_for_gw(gw)
        if delete_gw:
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
        if self.get_object_tag_value(gw, self.LOAD_BALANCER_PREFIX) not in (
                self.load_balancer_tag(instance)):
            log('\nnew load balancer configuration')
            if os.path.exists(os.path.join(os.path.dirname(__file__),
                                           'x-no-lb-reprovisioning')):
                log('\nskipping lb reprovisioning')
            else:
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

        tags = simple_gateway.pop('tags', [])
        proxy_ports = simple_gateway.pop('proxy-ports', None)
        https_inspection = simple_gateway.pop('https-inspection', False)
        identity_awareness = simple_gateway.pop('identity-awareness', False)
        ips_profile = simple_gateway.pop('ips-profile', None)
        vpn_community_star_as_center = simple_gateway.pop(
            'vpn-community-star-as-center', None)
        vpn_domain = simple_gateway.pop('vpn-domain', None)
        specific_network = simple_gateway.pop('specific-network', None)
        policy = simple_gateway.pop('policy')
        otp = simple_gateway.pop('one-time-password')
        custom_parameters = simple_gateway.pop('custom-parameters', [])
        restrictive_policy = simple_gateway.pop('restrictive-policy',
                                                self.RESTRICTIVE_POLICY)
        section_name = simple_gateway.pop('section-name', self.SECTION)

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
            gw = self.get_gateway(instance.name)
        else:
            self.set_state(instance.name, 'UPDATING')

        if gw['sic-state'] != 'communicating':
            log('\nfailed to initialize SIC to %s (sic-state=%s)'
                % (gw['name'], gw['sic-state']))
            log('\ninitializing SIC')
            gw = self('set-simple-gateway', {
                'name': instance.name,
                'one-time-password': otp
            })
            if gw['sic-state'] != 'communicating':
                log('\nSIC still not communicating (sic-state=%s),'
                    ' will try again later' % gw['sic-state'])
                return

        if identity_awareness and gw.get('identityAwareBlade') is None:
            if gw['version'] == 'R77.30':
                self.init_identity_awareness_r77_30(gw)
            else:
                self.init_identity_awareness(gw)

        if self.ONCE_PREFIX not in self.get_object_tags(gw):
            if restrictive_policy not in (None, 'none'):
                self.set_restrictive_policy(gw, restrictive_policy)
        tags += [TAG, self.ONCE_PREFIX]

        success = False
        published = False
        try:
            self.auto_publish = False
            self.reset_gateway(instance.name, delete_objects=(
                instance.load_balancers is not None))
            simple_gateway['name'] = instance.name
            self.put_object_tags(simple_gateway, tags)
            self('set-simple-gateway', simple_gateway)
            gw = self.get_gateway(instance.name)
            self.set_proxy(gw, proxy_ports)
            self('set-generic-object', {
                'uid': gw['uid'],
                'sslInspectionEnabled': https_inspection})
            if identity_awareness:
                self.set_identity_awareness(gw['uid'], True)
            if gw.get('ips'):
                self('set-generic-object', {
                    'uid': gw['uid'], 'protectInternalInterfacesOnly': False})
                if ips_profile:
                    self.set_ips_profile(gw, ips_profile)
            if vpn_community_star_as_center:
                self.set_vpn_community_star_as_center(
                    gw, vpn_community_star_as_center)
                enc_domain_type = 'ADDRESSES_BEHIND_GW'
                enc_domain_uid = None
                if vpn_domain is not None:
                    enc_domain_type = 'MANUAL'
                    if vpn_domain == '':
                        enc_domain_uid = self.get_empty_encryption_domain()
                        log('\nsetting encryption domain to "%s"' % 'EMPTY')
                    else:
                        enc_domain_uid = self.get_uid(vpn_domain)
                        log('\nsetting encryption domain to "%s"' % vpn_domain)
                self('set-generic-object', {
                    'uid': gw['uid'],
                    'encdomain': enc_domain_type,
                    'manualEncdomain': enc_domain_uid,
                    'vpn': {
                        'singleVpnIp': instance.ip_address,
                        'ipResolutionMechanismGw': 'SINGLENATIPVPN'}})
            load_balancers = instance.load_balancers
            if load_balancers is not None:
                for dns_name in load_balancers:
                    self.add_load_balancer(gw, policy, section_name, dns_name,
                                           load_balancers[dns_name])
            self.set_object_tag_value(gw['uid'],
                                      self.LOAD_BALANCER_PREFIX,
                                      self.load_balancer_tag(instance)[0])
            self('publish', {})
            published = True
            self.auto_publish = True
            self.set_policy(gw, policy)

            if gw['version'] == 'R77.30' and identity_awareness:
                cmd = 'pdp api enable'
                try:
                    out = self.run_script(instance.name, cmd)
                    log('\n%s' % out)
                except Exception:
                    log('\n%s' % traceback.format_exc())
                    log('\nfailed to enable pdp api on the gateway')
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
                        self.reset_gateway(instance.name, delete_objects=(
                            instance.load_balancers is not None))
                    except Exception:
                        log('\n%s' % traceback.format_exc())

    def set_restrictive_policy(self, gw, restrictive_policy):
        default_policy = restrictive_policy == self.RESTRICTIVE_POLICY

        log('\nsetting autoprovision restrictive policy name "%s" on gw.'
            % restrictive_policy)

        policies = self('show-packages', {}, aggregate='packages')
        if not any(p['name'] == restrictive_policy for p in policies):
            if default_policy:
                self('add-package', {'name': restrictive_policy})
            else:
                raise Exception(
                    'Cannot find policy name "%s".' %
                    restrictive_policy +
                    ' restricitive policy should be manually configured \n')

        self('install-policy', {
            'policy-package': restrictive_policy,
            'targets': gw['name']})

    def set_state(self, name, status):
        if not hasattr(self, 'state'):
            self.state = {}
        if name:
            log('\n%s: %s' % (name, status))
        if status:
            self.state[name] = status
        elif name in self.state:
            del self.state[name]

    def get_star_communities(self):
        communities = []
        for comm in self('show-vpn-communities-star', {
                'details-level': 'full'}, aggregate='objects', version='v1.1'):
            centers = sorted([gw['name'] for gw in comm['center-gateways']])
            gateways = {n: i for i, n in enumerate(centers)}
            satellites = sorted([gw['name']
                                 for gw in comm['satellite-gateways']])
            communities.append((comm['name'], gateways, satellites))
        return communities

    def show_interoperable_device(self, i):
        result = ['%s:' % i['name']]
        for prefix in [self.GATEWAY_PREFIX, self.CIDR_PREFIX,
                       self.CONTROLLER_PREFIX, self.VPN_PREFIX,
                       self.COMMUNITY_PREFIX]:
            result.append('%s=%s' % (
                prefix.split('__')[1], self.get_object_tag_value(i, prefix)))
        return ' '.join(result)

    def get_interoperable_devices(self, controller):
        interop_devices = self(
            'show-generic-objects', {'class-name': self.CPMI_GATEWAY_PLAIN,
                                     'details-level': 'full'},
            aggregate='objects')
        iods = {}
        for i in interop_devices:
            c = self.get_object_tag_value(i, self.CONTROLLER_PREFIX)
            if controller.name != c:
                continue
            vconn = self.get_object_tag_value(i, self.VPN_PREFIX)
            if vconn in iods:
                raise Exception(
                    'duplicate interoperable devices: %s\n%s\n%s' % (
                        vconn, self.show_interoperable_device(iods[vconn]),
                        self.show_interoperable_device(i)))
            iods[vconn] = i
        for vconn in iods:
            log('\n%s' % self.show_interoperable_device(iods[vconn]))
        log('\n')
        return iods

    def reinstall_policy(self, gw_name):
        policies = self.targets.get(gw_name, [])
        if len(policies) != 1:
            raise Exception(
                'Cannot select policy for gateway "%s" (%s)' % (
                    gw_name, policies))
        if os.path.exists(os.path.join(os.path.dirname(__file__),
                                       'x-no-vpn-policy-install')):
            log('\nskipping policy "%s" for "%s"' % (policies[0], gw_name))
            return
        log('\ninstalling policy "%s" on "%s"' % (policies[0], gw_name))
        self('install-policy', {
            'policy-package': policies[0], 'targets': gw_name})

    def add_vpn(self, iod, vpn_conn, gw_name, index, community):
        if iod:
            reason = None
            if community != self.get_object_tag_value(
                    iod, self.COMMUNITY_PREFIX, ''):
                reason = 'incomplete'
            elif vpn_conn.cidr != self.get_object_tag_value(
                    iod, self.CIDR_PREFIX, ''):
                reason = 'cidr mismatch'
            if not reason:
                return
            log('\nDeleting (%s): %s' % (
                reason, self.show_interoperable_device(iod)))
            self.delete_vpn(iod)
            iod_name = iod['name']
        else:
            iod_name = self.get_unique_name(vpn_conn.short_name)
        uid = self.create_interoperable_device(iod_name, gw_name, vpn_conn)

        log('\ngoing to provision "%s":' % gw_name)
        tags = self('show-vpn-community-star',
                    {'name': community}, version='v1.1')['tags']
        tags_dict = dict([tag['name'].partition('=')[::2] for tag in tags])
        tags_dict = {key: value for (key, value) in tags_dict.iteritems() if
                     key in {self.SPOKE_ROUTES, self.EXPORT_ROUTES}}
        tag_params = []
        if self.SPOKE_ROUTES in tags_dict:
            tag_params.append(tags_dict[self.SPOKE_ROUTES])
            if self.EXPORT_ROUTES in tags_dict:
                tag_params.extend(tags_dict[self.EXPORT_ROUTES].split(','))
        out = self.run_script(gw_name, 'config-vpn add \'%s\'' % (
            '\' \''.join([
                str(index), vpn_conn.local, vpn_conn.asn, vpn_conn.remote,
                iod_name, vpn_conn.cidr] + tag_params)))
        log('\n%s' % out)

        log('\ngetting interfaces')
        self(self.get_interfaces_command_version[0], {'target-name': gw_name},
             version=self.get_interfaces_command_version[1])

        log('\nadding interoperable device to community "%s"' % community)
        self(
            'set-vpn-community-star',
            {
                'name': community,
                'satellite-gateways': {'add': uid},
                'shared-secrets': {'add': {
                    'external-gateway': iod_name,
                    'shared-secret': vpn_conn.pre_shared_key}}},
            version='v1.1')

        self.reinstall_policy(gw_name)

        self.set_object_tag_value(uid, self.COMMUNITY_PREFIX, community)

    def delete_vpn(self, iod):
        iod_name = iod['name']
        gw_name = self.get_object_tag_value(iod, self.GATEWAY_PREFIX)
        cidr = self.get_object_tag_value(iod, self.CIDR_PREFIX)
        log('\ndeleting vpn for: %s (%s %s)' % (iod_name, gw_name, cidr))
        for comm, _, satellites in self.get_star_communities():
            if iod_name not in satellites:
                continue
            log('\nremove interoperable from community: "%s"' % comm)
            self('set-vpn-community-star', {
                'name': comm, 'satellite-gateways': {
                    'remove': iod_name},
                'ignore-warnings': True}, version='v1.1')
        gw_uid = self.get_uid(gw_name, obj_type='simple-gateway')
        if gw_uid:
            log('\ngoing to deprovision "%s":' % gw_name)
            out = self.run_script(
                gw_name, 'config-vpn delete \'%s\' \'%s\'' % (
                    iod_name, cidr))
            log('\n%s' % out)
            log('\ngetting interfaces')
            self(self.get_interfaces_command_version[0],
                 {'target-name': gw_name},
                 version=self.get_interfaces_command_version[1])
            self.reinstall_policy(gw_name)

        log('\ndeleting interoperable device')
        self('delete-generic-object', {
            "uid": iod['uid'], 'ignore-warnings': True})

    def create_interoperable_device(self, name, gw_name, vpn_conn):
        log('\ncreate interoperable device: %s %s %s' % (
            name, gw_name, vpn_conn))

        enc_domain_uid = self.get_empty_encryption_domain()

        obj = {
            'create': self.CPMI_GATEWAY_PLAIN,
            'name': name,
            'ipaddr': vpn_conn.peer,
            'thirdPartyEncryption': True,
            'osInfo': {
                'osName': 'Gaia'
            },
            'vpn': {
                'create': 'com.checkpoint.objects.classes.dummy.CpmiVpn',
                'owned-object': {
                    'vpnClientsSettingsForGateway': {
                        'create':
                            'com.checkpoint.objects.classes.dummy.'
                            'CpmiVpnClientsSettingsForGateway',
                        'owned-object': {
                            'endpointVpnClientSettings': {
                                'create':
                                    'com.checkpoint.objects.classes.dummy.'
                                    'CpmiEndpointVpnClientSettingsForGateway',
                                'owned-object': {
                                    'endpointVpnEnable': True
                                }
                            }
                        }
                    },
                    'ike': {
                        'create':
                            'com.checkpoint.objects.classes.dummy.CpmiIke'
                    },
                    'sslNe': {
                        'create': 'com.checkpoint.objects.classes.dummy.'
                            'CpmiSslNetworkExtender',
                        'owned-object': {
                            'sslEnable': False,
                            'gwCertificate': 'defaultCert'
                        }
                    }
                }
            },
            'dataSourceSettings': None,
            'nat': None,
            'manualEncdomain': enc_domain_uid,
            'encdomain': 'MANUAL',
            'ignore-warnings': True}

        self.put_object_tag_value(obj, self.GATEWAY_PREFIX, gw_name)
        self.put_object_tag_value(obj, self.CIDR_PREFIX, vpn_conn.cidr)
        self.put_object_tag_value(obj, self.CONTROLLER_PREFIX,
                                  vpn_conn.controller)
        self.put_object_tag_value(obj, self.VPN_PREFIX, vpn_conn.name)

        obj = self('add-generic-object', obj)

        self(
            'set-generic-object',
            {'uid': obj['uid'], 'vpn': {'isakmpIpcompSupport': True}})
        return obj['uid']

    def get_empty_encryption_domain(self):
        name = self.MONITOR_PREFIX + 'empty_encryption_domain'
        uid = self.get_uid(name)
        if uid:
            return uid
        return self('add-group', {'name': name})['uid']

    @staticmethod
    @contextlib.contextmanager
    def init(domains, **config):
        managements = collections.OrderedDict()
        options = config['management'].copy()
        default_domain = options.pop('domain', None)
        try:
            for domain in set(domains) | {None}:
                actual_domain = default_domain if domain is None else domain
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


def sync_vpn(controller, management):
    log('\n%s: vpn sync' % controller.name)
    if not conf.get('debug'):
        log('\n')
    gateways = management.get_gateways(filtered=False, version='v1.1')
    communities = management.get_star_communities()
    vpn_conns = controller.get_vpn_conns(
        get_vpn_env(controller, management, communities, gateways))
    addr_to_gw_comm = {}
    for community, centers, _ in communities:
        if controller.communities and (
                community not in controller.communities):
            continue
        for gw_name in centers:
            vpn_tag = management.get_object_tag_value(
                gateways[gw_name], management.VPN_PREFIX)
            addr = None
            if vpn_tag:
                addr = vpn_tag.partition('@')[0]
                debug('\ngot "%s" for %s by vpn tag' % (addr, gw_name))
            if not addr:
                addr = gateways[gw_name]['ipv4-address']
            name_index_comm = (gw_name, centers[gw_name], community)
            addr_to_gw_comm.setdefault(addr, []).append(name_index_comm)
    vpn_conn_to_gw_comm = {}
    filtered_vpn_conns = {}
    for vconn in vpn_conns:
        if vconn.tag == 'ignore':
            continue
        if vconn.gateway in addr_to_gw_comm:
            if len(addr_to_gw_comm[vconn.gateway]) != 1:
                raise Exception(
                    'ambiguous gateway by address %s for %s (%s)' % (
                        vconn.gateway, vconn.name, json.dumps(
                            addr_to_gw_comm[vconn.gateway])))
            vpn_conn_to_gw_comm[vconn.name] = addr_to_gw_comm[vconn.gateway][0]
        else:
            continue
        filtered_vpn_conns[vconn.name] = vconn
        log('\n%s' % vconn)
    log('\n')
    filtered_iods = management.get_interoperable_devices(controller)

    deleting_iod_cidrs = {}
    for name in set(filtered_iods) - set(filtered_vpn_conns):
        try:
            management.set_state(name, 'DELETING')
            management.delete_vpn(filtered_iods[name])
        except Exception:
            log('\n%s' % traceback.format_exc())
            cidr = management.get_object_tag_value(
                filtered_iods[name], management.CIDR_PREFIX)
            gw_name = management.get_object_tag_value(
                filtered_iods[name], management.GATEWAY_PREFIX)
            log('\nblocking provisioning of %s for %s' % (gw_name, cidr))
            deleting_iod_cidrs.setdefault((gw_name, cidr), []).append(name)
        finally:
            management.set_state(name, None)
    for name in set(filtered_vpn_conns):
        iod = filtered_iods.get(name)
        try:
            gw_name, gw_index, comm_name = vpn_conn_to_gw_comm[name]
            log('\nsynchronizing: %s %s %s %s' % (
                filtered_vpn_conns[name].name, gw_name, gw_index, comm_name))
            if not management.get_object_tag_value(
                    gateways[gw_name], management.TEMPLATE_PREFIX):
                log('\nskipping incompletely configured gateway: %s' % gw_name)
                continue
            other_iod_names = deleting_iod_cidrs.get(
                (gw_name, filtered_vpn_conns[name].cidr))
            if other_iod_names:
                log('\nskipping %s because cidr is used by: %s' % (
                    name, other_iod_names))
                continue
            if not iod and any(
                    i['ipv4-address'] == filtered_vpn_conns[name].local
                    for i in gateways[gw_name]['interfaces']):
                log('\nskipping %s: %s already has an interface with %s' % (
                    name, gw_name, filtered_vpn_conns[name].remote))
                continue
            management.add_vpn(
                iod, filtered_vpn_conns[name], gw_name, gw_index, comm_name)
            management.set_state(name, 'COMPLETE')
        except Exception:
            log('\n%s' % traceback.format_exc())


def sync(controller, management, gateways):
    log('\n%s: gateway sync' % controller.name)
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
            management.reset_gateway(name, delete_gw=True)
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


def get_vpn_env(controller, management, communities, gateways):
    prefix = controller.management + '/'
    if management.domain is not None:
        prefix += management.domain + '/'
    vpn_tags = {}
    tun_addrs = {}
    for community, centers, _ in communities:
        try:
            if controller.communities and (
                    community not in controller.communities):
                continue
            t = prefix + community
            vpn_tag_list = []
            for gw in centers:
                vpn_tag = management.get_object_tag_value(
                    gateways[gw], management.VPN_PREFIX)
                if not vpn_tag:
                    vpn_tag = management.run_script(
                        gateways[gw]['name'],
                        'config-vpn show').strip()
                    management.set_object_tag_value(
                        gateways[gw]['uid'],
                        management.VPN_PREFIX, vpn_tag)
                vpn_tag_list.append(vpn_tag)
                gw_addr = vpn_tag.partition('@')[0]
                tun_addrs[gw_addr] = ':'.join([
                    i['ipv4-address']
                    for i in gateways[gw].get('interfaces', [])
                    if i.get('name', '').startswith('vpnt')])
                log('\n%s: %s' % (vpn_tag, tun_addrs[gw_addr]))
            v = ' '.join(vpn_tag_list)
            log('\n%s: %s' % (t, v))
            vpn_tags[t] = v
        except Exception:
            log('\n%s' % traceback.format_exc())
    return prefix, vpn_tags, tun_addrs


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
                        if c.sync.get('gateway', False):
                            sync(c, management, gateways)
                    except Exception:
                        log('\n%s' % traceback.format_exc())
                    try:
                        if c.sync.get('vpn', False):
                            sync_vpn(c, management)
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


def test():
    log('\nTesting the configuration file loads...\n')
    config = load_configuration()
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
    for name, template in Template.templates.items():
        if name is None:
            continue
        log('\nTesting %s...\n' % name)
        if template.proto and template.proto not in Template.templates:
            raise Exception('The proto "%s" does not exist' % template.proto)
        if name not in templates:
            continue
        for key in ['version', 'one-time-password', 'policy']:
            if not Template.get(name, key, None):
                raise Exception('The parameter "%s" is missing' % key)

    log('\nTesting controllers...\n')
    domains = set()
    need_get_interfaces = False
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
        if c.get('sync', {}).get('vpn', False):
            need_get_interfaces = True

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
            is_mds = domains - {None}
            if management.domain:
                log('\nTesting domain: %s\n' % management.domain)
            elif is_mds:
                continue
            try:
                management('discard', {})
            except Exception:
                log('\n%s' % traceback.format_exc())
                msg = 'Failed'
                if management.user:
                    msg += '\nPlease check the user/password credentials'
                if management.domain:
                    msg += ('\nPlease verify that domain "%s" exists' %
                            management.domain)
                raise Exception(msg + '\n')
            management.get_gateways()

            if need_get_interfaces:
                if not management.get_interfaces_command_version[0]:
                    raise Exception(
                        'Your management version does not support '
                        '"get-interfaces"')

    log('\nAll Tests passed successfully\n')


def load_configuration():
    out, err, status = run_local(['./conf-cli.py', '--dump'])
    if status:
        raise Exception(
            'Failed to load configuration (%s)\n%s' % (status, err))
    return json.loads(out, object_pairs_hook=collections.OrderedDict)


def main(argv=None):
    parser = argparse.ArgumentParser(prog=argv[0] if argv else None)
    parser.add_argument('-d', '--debug', dest='debug', action='store_true')
    parser.add_argument('-l', '--logfile', metavar='LOGFILE',
                        help='Path to log file')
    parser.add_argument('-t', '--test', dest='test', action='store_true')
    args = parser.parse_args(argv[1:] if argv else None)

    logfile = getattr(args, 'logfile', None)
    if logfile:
        handler = logging.handlers.RotatingFileHandler(args.logfile,
                                                       maxBytes=20000000,
                                                       backupCount=10)
        logger = logging.getLogger('MONITOR')
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s'))
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

    run_local(['./conf-cli.py', '--upgrade'])
    if args.test:
        test()
        sys.exit(0)

    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            with open(__file__) as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except:
                    raise Exception('Another process is already running')
                config = load_configuration()
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
