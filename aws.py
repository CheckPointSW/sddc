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

import base64
import collections
import datetime
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib
import urlparse
import xml.dom.minidom

META_DATA = 'http://169.254.169.254/2014-02-25/meta-data'


def logger(msg):
    sys.stderr.write(msg)

logger.log = logger
logger.debug = logger if os.environ.get('AWS_API_DEBUG') == 'true' else None


def log(msg):
    logger.log(msg)


def debug(msg):
    if logger.debug:
        logger.debug(msg)


def set_logger(log, debug=None):
    logger.log = log
    logger.debug = debug

ALGORITHM = 'AWS4-HMAC-SHA256'

API_VERSIONS = {
    'autoscaling': '2011-01-01',
    'cloudformation': '2010-05-15',
    'ec2': '2015-04-15',
    'elasticloadbalancing': '2012-06-01',
    'iam': '2010-05-08',
    'monitoring': '2010-08-01',
    's3': '2006-03-01',
    'sns': '2010-03-31',
}

API_TARGETS = {
    'dynamodb': ('DynamoDB_20120810', '1.0'),
    'marketplacecommerceanalytics':
        ('MarketplaceCommerceAnalytics20150701', '1.1'),
    'logs': ('Logs_20140328', '1.1'),
    'events': ('AWSEvents', '1.1'),
}


class AWSException(Exception):
    pass


class EnvException(AWSException):
    pass


class CurlException(AWSException):
    def __init__(self, err, cmd):
        super(AWSException, self).__init__(err)
        self.cmd = cmd


class RoleException(AWSException):
    pass


class PayloadException(AWSException):
    pass


class VersionException(AWSException):
    pass

if os.path.isfile('/etc/cp-release'):
    os.environ.setdefault('AWS_CURL', 'curl_cli')
    if 'CURL_CA_BUNDLE' not in os.environ:
        if 'CPDIR' not in os.environ:
            raise EnvException(
                'Please define CPDIR in env for the CA bundle')
        ca_bundle = os.environ['CPDIR'] + '/conf/ca-bundle.crt'
        os.environ['CURL_CA_BUNDLE'] = ca_bundle

    if 'https_proxy' not in os.environ:
        host, err = subprocess.Popen(
            ['dbget', 'proxy:ip-address'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        host = host.strip()
        port, err = subprocess.Popen(
            ['dbget', 'proxy:port'], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        port = port.strip()
        if host and port:
            os.environ['https_proxy'] = 'http://%s:%s' % (host, port)

    no_proxy = set(os.environ.get('no_proxy', '').split(','))
    no_proxy -= {''}
    no_proxy |= {'169.254.169.254'}
    os.environ['no_proxy'] = ','.join(no_proxy)


def truncate(buf, max_len):
    first_truncated = repr(buf[:max_len * 4])
    second_truncated = first_truncated[:max_len]
    was_truncated = len(buf) > max_len * 4 or len(first_truncated) > max_len
    return second_truncated + ('...' if was_truncated else '')


def http(method, url, body, req_headers=None, max_time=None):
    curl = os.environ.get('AWS_CURL', 'curl')
    if 'AWS_NO_DOT' not in os.environ or os.environ[
            'AWS_NO_DOT'].lower() != 'true':
        log('.')
    cmd = [curl, '--silent', '--show-error', '--globoff',
           '--dump-header', '/dev/fd/2']
    if max_time:
        cmd += ['--max-time', str(max_time)]
    if method == 'HEAD':
        cmd += ['--head']
    else:
        cmd += ['--request', method]
    if url.startswith('https:') and os.environ.get('AWS_CA_BUNDLE'):
        cmd += ['--cacert', os.environ['AWS_CA_BUNDLE']]
    if body:
        cmd += ['--data-binary', '@-']
    has_content_type = False
    has_content_length = False
    if req_headers:
        for h in req_headers:
            if h.lower().startswith('content-type:'):
                has_content_type = True
            if h.lower().startswith('content-length:'):
                has_content_length = True
            cmd += ['--header', h]
    if not has_content_type:
        cmd += ['--header', 'Content-Type:']
    if not body and not has_content_length and method in set(['PUT', 'POST']):
        cmd += ['--header', 'Content-Length: 0']
    stdin = subprocess.PIPE
    if isinstance(body, file):
        stdin = body
        body = None
    cmd.append(url)
    debug(repr(cmd) + '\n')
    max_debug = 2048
    if body and not isinstance(body, file):
        debug(truncate(body, max_debug) + '\n')
    p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate(body)
    debug(err + '\n')
    debug(truncate(out, max_debug) + '\n')
    rc = p.wait()
    if rc:
        raise CurlException(err, cmd)
    # use only the last set of headers
    lines = [h.strip() for h in err.strip().split('\n')]
    ends = [i for i, line in enumerate(lines) if line == '']
    if len(ends) > 0:
        lines = lines[ends[-1] + 1:]
    proto, code, reason = lines[0].split(' ', 2)
    headers = {'_proto': proto, '_code': code, '_reason': reason}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        headers[key.strip().lower()] = value.strip()
    return headers, out


def sign(key, msg, hex=False):
    sig = hmac.new(key, msg.encode('utf-8'), hashlib.sha256)
    if hex:
        return sig.hexdigest()
    return sig.digest()


def calculate_key(key, date, region, service):
    k = sign(('AWS4' + key).encode('utf-8'), date)
    k = sign(k, region)
    k = sign(k, service)
    k = sign(k, 'aws4_request')
    return k


def parse_element(e):
    if not e.childNodes:
        return ''
    if len(e.childNodes) == 1 and e.firstChild.nodeType == e.TEXT_NODE:
        return e.firstChild.nodeValue
    result = collections.OrderedDict()
    for child in e.childNodes:
        if child.nodeType == child.ELEMENT_NODE:
            name = child.nodeName
            parsed_child = parse_element(child)
            if name in result:
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(parsed_child)
            else:
                result[name] = parsed_child
    return result


def as_list(obj, key):
    if obj == '':
        return []
    if isinstance(obj, list):
        return obj
    value = obj.get(key, [])
    if isinstance(value, list):
        return value
    return [value]


def listify(obj, key):
    if not isinstance(obj, dict):
        return obj
    listified = collections.OrderedDict()
    for k, v in obj.items():
        if k == key:
            if not isinstance(v, list):
                v = [v]
            return [listify(i, key) for i in v]
        else:
            v = listify(v, key)
        listified[k] = v
    return listified


class AWS(object):
    def __init__(self, key=None, secret=None, token=None, key_file=None,
                 max_time=None):
        self.max_time = max_time

        def read_file(f_name):
            f_key, f_secret = None, None
            with open(f_name) as f:
                for line in f:
                    k, v = line.strip().split('=', 1)
                    if k == 'AWSAccessKeyId':
                        f_key = v
                    elif k == 'AWSSecretKey':
                        f_secret = v
            return f_key, f_secret

        self.creds = {}

        if key_file == 'IAM':
            try:
                http('GET', META_DATA + '/ami-id', '', max_time=15)
            except:
                raise RoleException('not in AWS')
            url = META_DATA + '/iam/security-credentials/'
            h, b = http('GET', url, '')
            if h.get('_code') != '200':
                raise RoleException('no role in meta-data')
            self.creds['role'] = b
            return

        if key_file:
            key, secret = read_file(key_file)

        if not key or not secret:
            raise EnvException("""
Please specify a source for credentials in env:

AWS_KEY_FILE - text file with AWSAccessKeyId=..., AWSSecretKey=...,
    and optionally AWSSessionToken=...,
    or, the value IAM instead of a path to a text file to indicate the
    usage of temporary credentials via a IAM instance profile
AWS_ACCESS_KEY_ID or AWS_ACCESS_KEY
AWS_SECRET_ACCESS_KEY or AWS_SECRET_KEY
AWS_SESSION_TOKEN - (optional)
""")
        self.creds['access_key'] = key
        self.creds['secret_key'] = secret
        if token:
            self.creds['token'] = token

    def refresh_credentials(self):
        if not self.creds.get('role'):
            return

        tstamp = self.creds.get('tstamp', 0.0)
        if tstamp <= time.time() < tstamp + 300:
            return

        url = META_DATA + '/iam/security-credentials/' + self.creds.get('role')
        headers, body = http('GET', url, '')
        cred = json.loads(body)
        self.creds['access_key'] = cred['AccessKeyId']
        self.creds['secret_key'] = cred['SecretAccessKey']
        self.creds['token'] = cred['Token']
        self.creds['tstamp'] = time.time()

    def get_url(self, service, region, method, url, payload, expiration=30,
                header_list=None):

        self.refresh_credentials()

        url_parts = urlparse.urlsplit(url)
        query = {}
        if url_parts.query:
            query = urlparse.parse_qs(url_parts.query, keep_blank_values=True,
                                      strict_parsing=True)
            query = {k: query[k][0] for k in query}
        now = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        if service == 'iam':
            host = service
        elif service.endswith('s3') and not region.startswith('cn-'):
            if region == 'us-east-1':
                host = service
            else:
                host = service + '-' + region
            service = 's3'
        else:
            host = service + '.' + region
        signing_name = os.environ.get(
            'AWS_SIGNING_NAME_' + service.replace('.', '_'), service)
        suffix = '.amazonaws.com'
        if region.startswith('cn-'):
            suffix += '.cn'
        host += suffix
        url = 'https://' + host + url_parts.path

        scope = '/'.join([now[:8], region, signing_name, 'aws4_request'])

        if service.endswith('s3') and (
                method == 'PUT' or header_list is None):
            hashed_payload = 'UNSIGNED-PAYLOAD'
        else:
            if isinstance(payload, file):
                raise PayloadException('cannot sign streaming payload')
            hashed_payload = hashlib.sha256(payload).hexdigest()

        headers = collections.OrderedDict()
        if header_list:
            for h in header_list:
                name, colon, value = h.partition(':')
                headers[name.strip()] = value.strip()
        headers['Host'] = host
        query = query.copy()
        content_type = query.pop('Content-Type', None)
        if 'Version' not in query and service in API_VERSIONS:
            query['Version'] = API_VERSIONS[service]
        if 'Version' not in query:
            target = query.pop('X-Amz-Target', None)
            if target is None and 'Action' in query:
                if service not in API_TARGETS:
                    raise VersionException(
                        'cannot find version or target prefix for "%s"' % (
                            service))
                target_prefix, json_version = API_TARGETS[service]
                target = '%s.%s' % (target_prefix, query.pop('Action'))
                if content_type is None:
                    content_type = 'application/x-amz-json-%s' % json_version
            if target is not None:
                headers['X-Amz-Target'] = target
        if content_type is not None:
            headers['Content-Type'] = content_type
        credential = self.creds['access_key'] + '/' + scope
        if header_list is None:
            query['X-Amz-Algorithm'] = ALGORITHM
            query['X-Amz-Credential'] = credential
            query['X-Amz-Date'] = now
            query['X-Amz-Expires'] = str(expiration)
            query['X-Amz-SignedHeaders'] = 'host'
            if 'token' in self.creds:
                query['X-Amz-Security-Token'] = self.creds['token']
        else:
            headers['X-Amz-Date'] = now
            if 'token' in self.creds:
                headers['X-Amz-Security-Token'] = self.creds['token']
            if service.endswith('s3'):
                headers['X-Amz-Content-Sha256'] = hashed_payload
        canonical_header_name_pairs = sorted([(n.lower(), n) for n in headers])
        canonical_headers = '\n'.join([
            '%s:%s' % (l, headers[n])
            for l, n in canonical_header_name_pairs]) + '\n'
        signed_headers = ';'.join([l for l, n in canonical_header_name_pairs])

        parts = []
        for k, v in sorted(query.items()):
            parts += [urllib.quote(k, '~') + '=' + urllib.quote(v, '~')]
        query_string = '&'.join(parts)

        req = '\n'.join([method, url_parts.path, query_string,
                         canonical_headers, signed_headers, hashed_payload])
        signature = sign(
            calculate_key(self.creds['secret_key'], now[:8], region,
                          signing_name),
            '\n'.join([ALGORITHM, now, scope,
                       hashlib.sha256(req).hexdigest()]),
            hex=True)
        if header_list is None:
            query_string += '&X-Amz-Signature=' + signature
        else:
            del header_list[:]
            header_list += ['%s: %s' % (k, v) for k, v in headers.items()]
            header_list += [
                'Authorization: %s %s' % (ALGORITHM, ', '.join([
                    'Credential=%s' % credential,
                    'SignedHeaders=%s' % signed_headers,
                    'Signature=%s' % signature]))]
        if query_string:
            query_string = '?' + query_string
        return url + query_string

    def request(self, service, region, method, url, payload,
                user_headers=None, max_time=None):
        req_headers = None
        if method in {'GET', 'POST'}:
            req_headers = []
        elif method == 'PUT' and service.endswith('s3') and not isinstance(
                payload, file):
            req_headers = ['Content-MD5: %s' %
                           base64.b64encode(hashlib.md5(payload).digest())]
        if req_headers is not None or user_headers is not None:
            if req_headers is None:
                req_headers = []
            if user_headers is not None:
                req_headers += user_headers[:]
        url = self.get_url(service, region, method, url, payload,
                           header_list=req_headers)
        if not max_time:
            max_time = self.max_time
        headers, body = http(method, url, payload, req_headers, max_time)
        ct = headers.get('content-type')
        if method == 'HEAD':
            body = None
            headers['_parsed'] = True
        elif ct is None or ct == 'application/xml' or ct.startswith(
                'text/xml'):
            try:
                body = parse_element(
                    xml.dom.minidom.parseString(body).documentElement)
                headers['_parsed'] = True
            except:
                if ct is not None:
                    raise
        elif body and ct in {'application/x-amz-json-1.0',
                             'application/x-amz-json-1.1',
                             'application/json'}:
            try:
                body = json.loads(
                    body, object_pairs_hook=collections.OrderedDict)
                headers['_parsed'] = True
            except:
                raise
        return headers, body


def init(*args, **kwargs):
    """Create a singleton instance with module level functions"""
    if '_once' in globals():
        return
    globals()['_once'] = True

    def set_from_env(arg_name, env_names):
        val = kwargs.get(arg_name)
        if not val:
            for name in env_names:
                val = os.environ.get(name)
                if val:
                    break
            if val:
                kwargs[arg_name] = val

    set_from_env('key', ['AWS_ACCESS_KEY_ID', 'AWS_ACCESS_KEY'])
    set_from_env('secret', ['AWS_SECRET_ACCESS_KEY', 'AWS_SECRET_KEY'])
    set_from_env('token', ['AWS_SESSION_TOKEN'])
    set_from_env('key_file', ['AWS_KEY_FILE'])
    set_from_env('max_time', ['AWS_MAX_TIME'])

    aws = AWS(*args, **kwargs)

    import inspect
    for m in inspect.getmembers(aws, inspect.ismethod):
        if m[0] == '__init__':
            continue
        globals()[m[0]] = m[1]


def main(argv):
    global request  # for pyflakes
    if len(argv) < 4 or argv[1] == '-h' or (
            argv[2] != '--' and len(argv) > 5) or (
            argv[2] == '--' and len(argv) % 2 != 1):
        log("""Usage: %s

SERVICE[@REGION][:LIST-MEMBER] METHOD URL [BODY]

SERVICE[@REGION][:LIST-MEMBER] -- KEY VALUE ...
""" % argv[0])
        sys.exit(1)
    os.environ['AWS_NO_DOT'] = 'true'
    init()
    user_headers = []
    for var in os.environ:
        if var.startswith('AWS_HTTP_'):
            name = var[len('AWS_HTTP_'):].lower().replace('_', '-')
            user_headers.append('%s: %s' % (name, os.environ[var]))
    if not user_headers:
        user_headers = None
    service_region_member = argv[1]
    service, region, member = re.match(
        r'([^@:]+)(@[^:]*)?(:.*)?$', service_region_member).groups()
    if region:
        region = region[1:]
    if not region:
        region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
    if member:
        member = member[1:]
    method = argv[2]
    if method == '--':
        query = []
        if service in API_TARGETS:
            method = 'POST'
            payload = collections.OrderedDict()
            for i in xrange(3, len(argv), 2):
                val = argv[i + 1]
                if argv[i] == 'Action':
                    query.append((argv[i], val))
                else:
                    if val.startswith('json:'):
                        val = json.loads(val[5:])
                    payload[argv[i]] = val
            payload = json.dumps(payload)
        else:
            method = 'GET'
            for i in xrange(3, len(argv), 2):
                query.append((argv[i], argv[i + 1]))
            payload = ''
        headers, body = request(service, region, method,
                                '/?' + urllib.urlencode(query), payload,
                                user_headers)
    else:
        url = argv[3]
        data = ''
        if len(argv) > 4:
            data = argv[4]
        file_name = os.devnull
        if data.startswith('@'):
            if data[1:] == '-':
                data = sys.stdin
            else:
                file_name = data[1:]
                data = None
        with open(file_name, 'rb') as f:
            if data is None:
                data = f
            headers, body = request(service, region, method, url, data,
                                    user_headers)
    try:
        if headers.get('_parsed'):
            if member:
                body = listify(body, member)
            body = json.dumps(body, indent=2) + '\n'
    except:
        log(repr(headers) + '\n')
        log(repr(body) + '\n')
        raise
    log(json.dumps(headers, indent=2) + '\n')
    sys.stdout.write(body)


if __name__ == '__main__':
    main(sys.argv)
