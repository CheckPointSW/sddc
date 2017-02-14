#!/usr/bin/env python

#   Copyright 2016 Check Point Software Technologies LTD
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
import base64
import collections
import contextlib
import inspect
import json
import os
import subprocess
import sys
import time
import urllib


def logger(msg):
    sys.stderr.write(msg)

logger.log = logger
logger.debug = logger if os.environ.get('GCP_DEBUG') == 'true' else None


def log(msg):
    logger.log(msg)


def debug(msg):
    if logger.debug:
        logger.debug(msg)


def set_logger(log, debug=None):
    logger.log = log
    logger.debug = debug


class GCPException(Exception):
    pass


class EnvException(GCPException):
    pass


class CurlException(GCPException):
    def __init__(self, msg, cmd):
        super(GCPException, self).__init__(msg)
        self.cmd = cmd


class HTTPException(GCPException):
    def __init__(self, msg, headers, body):
        super(GCPException, self).__init__(msg)
        self.headers = headers
        self.body = body


if os.path.isfile('/etc/cp-release'):
    os.environ.setdefault('GCP_OPENSSL', 'cpopenssl')
    os.environ.setdefault('GCP_CURL', 'curl_cli')
    cpdir = os.environ.get('MDS_CPDIR', os.environ.get('CPDIR'))
    if not cpdir:
        raise EnvException('Please define CPDIR in env for the CA bundle')
    bundle_dir = cpdir + '/conf/'
    if os.path.exists(bundle_dir + 'public-cloud.crt'):
        cloud_bundle = bundle_dir + 'ca-bundle-public-cloud.crt'
        if 'CURL_CA_BUNDLE' not in os.environ or (
                os.environ['CURL_CA_BUNDLE'] == bundle_dir + 'ca-bundle.crt'):
            os.environ['CURL_CA_BUNDLE'] = cloud_bundle


def truncate(buf, max_len):
    first_truncated = repr(buf[:max_len * 4])
    second_truncated = first_truncated[:max_len]
    was_truncated = len(buf) > max_len * 4 or len(first_truncated) > max_len
    return second_truncated + ('...' if was_truncated else '')


def http(method, url, body=None, headers=None, auth=None, max_time=None,
         proxy=None, sensitive=False):
    curl = os.environ.get('GCP_CURL', 'curl')
    if 'GCP_NO_DOT' not in os.environ or os.environ[
            'GCP_NO_DOT'].lower() != 'true':
        log('.')
    cmd = [curl, '--silent', '--show-error', '--globoff',
           '--dump-header', '/dev/fd/2']
    if max_time:
        cmd += ['--max-time', str(max_time)]
    if proxy is not None:
        cmd += ['--proxy', proxy]
    cmd += ['--noproxy', '169.254.169.254']
    if method == 'HEAD':
        cmd += ['--head']
    else:
        cmd += ['--request', method]
    if body:
        cmd += ['--data-binary', '@-']
    has_content_type = False
    has_content_length = False
    if headers:
        for h in headers:
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
    cmd += ['--url', url]
    debug(repr(cmd) + '\n')

    if auth:
        cmd += ['--header', auth]

    max_debug = 2048
    if body and not sensitive and not isinstance(body, file):
        debug(truncate(body, max_debug) + '\n')
    p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate(body)
    debug(err + '\n')
    if not sensitive:
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
    headers = {'_proto': proto, '_code': int(code), '_reason': reason}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        headers[key.strip().lower()] = value.strip()

    if not (200 <= headers['_code'] < 300):
        raise HTTPException('Unexpected HTTP code: %s' % (
            headers['_code']), headers, out)

    if not headers['content-type'].startswith('application/json'):
        raise HTTPException('Unexpected content-type: %s' % (
            headers['content-type']), headers, out)

    resp = json.loads(out, object_pairs_hook=collections.OrderedDict)
    return headers, resp


def sign(data, key):
    rfd, wfd = None, None
    try:
        rfd, wfd = os.pipe()
        os.write(wfd, key)
        os.close(wfd)
        wfd = None
        return subprocess.Popen([
            os.environ.get('GCP_OPENSSL', 'openssl'), 'dgst', '-sha256',
            '-sign', '/dev/fd/%d' % rfd], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate(
                data)[0]
    finally:
        if wfd is not None:
            os.close(wfd)
        if rfd is not None:
            os.close(rfd)


class GCP(object):
    def __init__(self, credentials, max_time=None, proxy=None,
                 project=None, region=None, zone=None):
        self.max_time = max_time
        self.proxy = proxy
        self.token = {
            'expires_in': 0
        }
        if isinstance(credentials, basestring):
            if credentials.startswith('{'):
                credentials = json.loads(credentials)
            elif credentials != 'IAM':
                with open(credentials) as f:
                    credentials = json.load(f)
        self.credentials = credentials
        if project is None:
            if self.credentials == 'IAM':
                self.project = self.metadata()[0]['project']['projectId']
            else:
                self.project = self.credentials['project_id']
        else:
            self.project = project
        if zone:
            self.zone = zone
        if region:
            self.region = region
        elif zone:
            self.region = '-'.join(self.zone.split('-')[:2])

    @contextlib.contextmanager
    def get_authorization(self):
        now = int(time.time())
        if self.token['expires_in'] < now:
            debug('get_authorization: no cache\n')
            if self.credentials == 'IAM':
                h, self.token = http(
                    'GET', 'http://169.254.169.254/computeMetadata/' +
                    'v1/instance/service-accounts/default/token',
                    headers=['Metadata-Flavor: Google'],
                    max_time=self.max_time,
                    sensitive=True)
            else:
                jwt = [base64.urlsafe_b64encode(json.dumps({
                    'alg': 'RS256',
                    'typ': 'JWT',
                    'kid': self.credentials['private_key_id']})).replace(
                        '=', '')]
                jwt += [base64.urlsafe_b64encode(json.dumps({
                    'iss': self.credentials['client_email'],
                    'scope': 'https://www.googleapis.com/auth/cloud-platform',
                    'aud': self.credentials['token_uri'],
                    'exp': now + 60,
                    'iat': now - 60})).replace('=', '')]
                jwt += [base64.urlsafe_b64encode(sign(
                    '.'.join(jwt),
                    self.credentials['private_key'])).replace('=', '')]
                h, self.token = http(
                    'POST', self.credentials['token_uri'],
                    body=urllib.urlencode([
                        ('grant_type',
                            'urn:ietf:params:oauth:grant-type:jwt-bearer'),
                        ('assertion', '.'.join(jwt))]),
                    headers=[
                        'Content-type: application/x-www-form-urlencoded'],
                    max_time=self.max_time,
                    proxy=self.proxy,
                    sensitive=True)
            self.token['expires_in'] += now - 120
        try:
            yield 'Authorization: {token_type} {access_token}'.format(
                **self.token)
        except HTTPException as e:
            if e.headers['_code'] in {401, 403}:
                debug('get_authorization: delete from cache\n')
                self.token = {'expires_in': 0}
            raise

    def metadata(self, recursive=True, wait_for_change=False, timeout_sec=0,
                 etag=None):
        query = {}
        if recursive:
            query['recursive'] = 'true'
        if wait_for_change:
            query['wait_for_change'] = 'true'
        if timeout_sec:
            query['timeout_sec'] = timeout_sec
            max_time = timeout_sec + 2
        else:
            max_time = self.max_time
        if etag:
            query['last_etag'] = etag
        url = 'http://169.254.169.254/computeMetadata/v1/?%s' % (
            urllib.urlencode(query))
        h, b = http(
            'GET', url, headers=['Metadata-Flavor: Google'], max_time=max_time)
        return b, h['etag']

    GLOBAL = {'images', 'networks', 'routes', 'deployments'}
    REGIONAL = {'subnetworks'}
    ZONAL = {'disks', 'instances'}

    def rest(self, method, path, query={}, service=None, body=None,
             headers=None, aggregate=False):
        result = None
        page_token = None

        while True:
            if page_token:
                query['pageToken'] = page_token

            url = ''
            if not path.startswith('https://'):
                if service is None:
                    service = 'compute/v1'
                url = 'https://www.googleapis.com/%s' % service
                if not path.startswith('/projects/'):
                    url += '/projects/%s' % self.project
                    parts = path.split('/')
                    if parts[1] not in {'global', 'regions', 'zones'}:
                        if parts[1] in self.GLOBAL:
                            url += '/global'
                        elif parts[1] in self.REGIONAL:
                            url += '/regions/' + self.region
                        elif parts[1] in self.ZONAL:
                            url += '/zones/' + self.zone
            url += path

            if query:
                _, _, query_string = url.partition('?')
                url += '&' if query_string else '?'
                url += urllib.urlencode(query)

            with self.get_authorization() as auth:
                h, resp = http(
                    method, url, body=body, headers=headers, auth=auth,
                    max_time=self.max_time, proxy=self.proxy)

            if not aggregate:
                return h, resp
            elif resp.get('kind', '').endswith('AggregatedList'):
                if not result:
                    result = collections.OrderedDict()
                items = resp.get('items', {})
                for key, value in items.items():
                    result.setdefault(key, collections.OrderedDict())
                    for k, v in value.items():
                        if k == 'warning' and v.get(
                                'code') == 'NO_RESULTS_ON_PAGE':
                            continue
                        result[key].setdefault(k, [])
                        if isinstance(v, list):
                            result[key][k].extend(v)
                        else:
                            result[key][k].append(v)
            else:
                if not result:
                    result = []
                items = resp.get('items', [])
                result.extend(items)
            page_token = resp.get('nextPageToken')
            if not page_token:
                return {}, result


def init(*args, **kwargs):
    if '_once' not in globals():
        globals()['_once'] = True
        for m in inspect.getmembers(GCP, inspect.ismethod):
            if m[0] in globals():
                raise Exception('symbol collision for "%s"' % m[0])

    credentials = kwargs.get('credentials')
    if not credentials:
        credentials = os.environ.get('GCP_CREDENTIALS')
        if credentials:
            kwargs['credentials'] = credentials

    max_time = kwargs.get('max_time')
    if not max_time:
        max_time = os.environ.get('GCP_MAX_TIME')
        if max_time:
            kwargs['max_time'] = max_time

    proxy = kwargs.get('proxy')
    if not proxy:
        proxy = os.environ.get('https_proxy')
        if not proxy:
            host, err = subprocess.Popen(
                ['dbget', 'proxy:ip-address'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            host = host.strip()
            port, err = subprocess.Popen(
                ['dbget', 'proxy:port'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
            port = port.strip()
            if host and port:
                proxy = 'http://%s:%s' % (host, port)
        if proxy:
            kwargs['proxy'] = proxy

    project = kwargs.get('project')
    if not project:
        project = os.environ.get('CLOUDSDK_CORE_PROJECT')
        if project:
            kwargs['project'] = project

    region = kwargs.get('region')
    if not region:
        region = os.environ.get('CLOUDSDK_COMPUTE_REGION')
        if region:
            kwargs['region'] = region

    zone = kwargs.get('zone')
    if not zone:
        zone = os.environ.get('CLOUDSDK_COMPUTE_ZONE')
        if zone:
            kwargs['zone'] = zone

    gcp = GCP(*args, **kwargs)

    for m in inspect.getmembers(gcp, inspect.ismethod):
        if m[0].startswith('_'):
            continue
        globals()[m[0]] = m[1]


def main(argv):
    global rest  # appease pyflakes
    parser = argparse.ArgumentParser()

    parser.add_argument('method', metavar='METHOD',
                        choices=['GET', 'PUT', 'POST', 'DELETE', 'PATCH'])
    parser.add_argument('path', metavar='PATH')
    parser.add_argument('-a', '--aggregate', action='store_true')
    parser.add_argument(
        '-b', '--body', metavar='BODY', default='',
        help='DATA-AS-STRING or @FILE-NAME or @- (from stdin)')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument(
        '-H', '--header', metavar='HEADER', action='append',
        help='NAME:\\ VALUE')
    parser.add_argument('-p', '--project', metavar='PROJECT')
    parser.add_argument('-r', '--region', metavar='REGION')
    parser.add_argument('-s', '--service', metavar='SERVICE')
    parser.add_argument('-z', '--zone', metavar='ZONE')

    args = parser.parse_args()
    if args.debug:
        logger.debug = logger

    os.environ.setdefault('GCP_NO_DOT', 'true')

    os.environ.setdefault('GCP_CREDENTIALS', 'IAM')

    init(project=args.project, region=args.region, zone=args.zone)

    file_name = os.devnull
    data = args.body
    if data.startswith('@'):
        if data[1:] == '-':
            data = sys.stdin
        else:
            file_name = data[1:]
            data = None
    try:
        with open(file_name, 'rb') as f:
            if data is None:
                data = f
            headers, resp = rest(
                args.method, args.path, body=data, headers=args.header,
                service=args.service, aggregate=args.aggregate)
        body = json.dumps(resp, indent=2) + '\n'
    except HTTPException as e:
        headers = e.headers
        body = e.body
    sys.stderr.write(json.dumps(headers, indent=2) + '\n')
    sys.stdout.write(body)


if __name__ == '__main__':
    main(sys.argv)
