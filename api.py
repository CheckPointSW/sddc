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

import collections
import datetime
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import urllib
import urlparse
import xml.dom.minidom

DEBUG = os.environ.get('AWS_API_DEBUG') == 'true'
META_DATA = 'http://169.254.169.254/2014-02-25/meta-data'


def log(msg):
    sys.stderr.write(msg)


def debug(msg):
    if DEBUG:
        log(msg)


ALGORITHM = 'AWS4-HMAC-SHA256'

API_VERSIONS = {
    'autoscaling': '2011-01-01',
    'cloudformation': '2010-05-15',
    'ec2': '2015-04-15',
    'elasticloadbalancing': '2012-06-01',
    'iam': '2010-05-08',
    'monitoring': '2010-08-01',
    's3': '2006-03-01',
}


def http(method, url, body, req_headers=None):
    curl = 'curl'
    if 'AWS_CURL' in os.environ:
        curl = os.environ['AWS_CURL']
    if 'AWS_NO_DOT' not in os.environ or os.environ[
            'AWS_NO_DOT'].lower() != 'true':
        log('.')
    cmd = [curl, '-s', '-S', '-g', '-L', '-D', '/dev/fd/2', '-X', method]
    if DEBUG:
        cmd += ['-v']
    if method == 'HEAD':
        cmd += ['-I']
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
            cmd += ['-H', h]
    if not has_content_type:
        cmd += ['-H', 'Content-Type:']
    if not body and not has_content_length and method in set(['PUT', 'POST']):
        cmd += ['-H', 'Content-Length: 0']
    stdin = subprocess.PIPE
    if isinstance(body, file):
        stdin = body
        body = None
    cmd.append(url)
    debug(repr(cmd) + '\n')
    p = subprocess.Popen(cmd, stdin=stdin, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate(body)
    debug(err + '\n')
    debug(repr(out[:65536]) + ('...' if len(out) > 65536 else '') + '\n')
    rc = p.wait()
    if rc:
        raise Exception('%s\n%s' % (cmd, err))
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


def get_ec2_tags(obj):
    tags = {}
    for t in as_list(obj['tagSet'], 'item'):
        tags[t['key']] = t['value']
    return tags


def listify(obj, key):
    if not isinstance(obj, dict):
        return obj
    listified = {}
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
    def __init__(self, key=None, secret=None, token=None, key_file=None):
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
            url = META_DATA + '/iam/security-credentials/'
            self.creds['role'] = http('GET', url, '')[1]
            return

        if key_file:
            key, secret = read_file(key_file)
        if not key:
            key = os.environ.get(
                'AWS_ACCESS_KEY_ID', os.environ.get('AWS_ACCESS_KEY'))
        if not secret:
            secret = os.environ.get(
                'AWS_SECRET_ACCESS_KEY', os.environ.get('AWS_SECRET_KEY'))
        if not token:
            token = os.environ.get('AWS_SESSION_TOKEN')

        if not key and not secret and not token:
            if 'AWS_KEY_FILE' in os.environ:
                key, secret = read_file(os.environ['AWS_KEY_FILE'])

        if not key or not secret:
            raise Exception("""Please specify a source for credentials in env:

AWS_KEY_FILE - text file with AWSAccessKeyId=..., AWSSecretKey=..., and
    optionally AWSSessionToken=...
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
                auth_headers=None):

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
        suffix = '.amazonaws.com'
        if region.startswith('cn-'):
            suffix += '.cn'
        host += suffix
        url = 'https://' + host + url_parts.path

        scope = '/'.join([now[:8], region, service, 'aws4_request'])

        if service.endswith('s3') and (
                method != 'GET' or auth_headers is None):
            hashed_payload = 'UNSIGNED-PAYLOAD'
        else:
            if isinstance(payload, file):
                raise Exception('cannot sign streaming payload')
            hashed_payload = hashlib.sha256(payload).hexdigest()

        query = query.copy()
        if 'Version' not in query:
            query['Version'] = API_VERSIONS[service]
        headers = {'Host': host}
        credential = self.creds['access_key'] + '/' + scope
        if auth_headers is None:
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
        canonical_headers = '\n'.join(sorted(
            ['%s:%s' % (k.lower(), v) for k, v in headers.items()])) + '\n'
        signed_headers = ';'.join(sorted([k.lower() for k in headers]))

        parts = []
        for k, v in sorted(query.items()):
            parts += [urllib.quote(k, '~') + '=' + urllib.quote(v, '~')]
        query_string = '&'.join(parts)

        req = '\n'.join([method, url_parts.path, query_string,
                         canonical_headers, signed_headers, hashed_payload])
        signature = sign(
            calculate_key(self.creds['secret_key'], now[:8], region,
                          service),
            '\n'.join([ALGORITHM, now, scope,
                       hashlib.sha256(req).hexdigest()]),
            hex=True)
        if auth_headers is None:
            query_string += '&X-Amz-Signature=' + signature
        else:
            auth_headers += ['%s: %s' % (k, v) for k, v in headers.items()]
            auth_headers += [
                'Authorization: %s %s' % (ALGORITHM, ', '.join([
                    'Credential=%s' % credential,
                    'SignedHeaders=%s' % signed_headers,
                    'Signature=%s' % signature]))]
        return url + '?' + query_string

    def request(self, service, region, method, url, payload):
        auth_headers = None
        if method == 'GET':
            auth_headers = []
        url = self.get_url(service, region, method, url, payload,
                           auth_headers=auth_headers)
        headers, body = http(method, url, payload, auth_headers)
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
        return headers, body


def init(*args, **kwargs):
    """Create a singleton instance with module level functions"""
    if '_once' in globals():
        return
    globals()['_once'] = True
    aws = AWS(*args, **kwargs)
    import inspect
    for m in inspect.getmembers(aws, inspect.ismethod):
        if m[0] == '__init__':
            continue
        globals()[m[0]] = m[1]


def main(argv):
    if len(argv) < 4 or argv[1] == '-h' or (
            argv[2] != '--' and len(argv) > 5) or (
            argv[2] == '--' and len(argv) % 2 != 1):
        log("""Usage: %s

SERVICE[@REGION] METHOD URL [BODY]

SERVICE[@REGION] -- KEY VALUE ...
""" % argv[0])
        sys.exit(1)
    os.environ['AWS_NO_DOT'] = 'true'
    init()
    service_region = argv[1]
    service, s, region = service_region.partition('@')
    if not region:
        region = 'us-east-1'
    method = argv[2]
    if method == '--':
        query = []
        for i in xrange(3, len(argv), 2):
            query.append((argv[i], argv[i + 1]))
        headers, body = request(service, region, 'GET',
                                '/?' + urllib.urlencode(query), '')
    else:
        url = argv[3]
        data = ''
        if len(argv) > 4:
            data = argv[4]
        file_name = '/dev/null'
        if data.startswith('@'):
            if data[1:] == '-':
                data = sys.stdin
            else:
                file_name = data[1:]
                data = None
        with open(file_name, 'rb') as f:
            if data is None:
                data = f
            headers, body = request(service, region, method, url, data)
    try:
        if headers.get('_parsed'):
            body = json.dumps(body, indent=2) + '\n'
    except:
        log(repr(headers) + '\n')
        log(body + '\n')
        raise
    log(json.dumps(headers, indent=2) + '\n')
    sys.stdout.write(body)


if __name__ == '__main__':
    main(sys.argv)
