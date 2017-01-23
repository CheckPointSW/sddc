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

import base64
import collections
import contextlib
import hashlib
import hmac
import inspect
import json
import os
import re
import subprocess
import sys
import time
import urllib
import urllib2
import xml.dom.minidom

# services with more specific path should precede
ARM_VERSIONS = collections.OrderedDict([
    ('storage', '2015-06-15'),
    ('resources/deployments/operations', '2015-11-01'),
    ('resources/deployments', '2015-11-01'),
    ('resources/', '2015-01-01'),
    ('network/virtualnetworks', '2016-06-01'),
    ('network/', '2015-06-15'),
    ('compute/', '2015-06-15'),
    ('classicstorage/', '2015-12-01'),
    ('classiccompute/', '2015-12-01'),
])


def logger(msg):
    sys.stderr.write(msg)

logger.log = logger
logger.debug = logger if 'AZURE_REST_DEBUG' in os.environ else None


def log(msg):
    logger.log(msg)


def debug(msg):
    if logger.debug:
        logger.debug(msg)


def set_logger(log, debug=None):
    logger.log = log
    logger.debug = debug

if os.path.isfile('/etc/cp-release'):
    os.environ.setdefault('AZURE_REST_CURL', 'curl_cli')
    if 'CURL_CA_BUNDLE' not in os.environ:
        if 'CPDIR' not in os.environ:
            raise Exception(
                'Please define CPDIR in env for the CA bundle')
        ca_bundle = os.environ['CPDIR'] + '/conf/ca-bundle.crt'
        os.environ['CURL_CA_BUNDLE'] = ca_bundle


class RequestException(Exception):
    def __init__(self, proto, code, reason, body):
        message = '%s %d %s\n%s' % (proto, code, reason, body)
        super(Exception, self).__init__(message)
        self.message = message
        self.args = (proto, code, reason, body)
        self.proto = proto
        self.code = code
        self.reason = reason
        self.body = body

    def __str__(self):
        return self.message


def request(method, url, cert=None, body=None, headers=None, pool=None,
            max_time=None):
    if 'AZURE_NO_DOT' not in os.environ or os.environ[
            'AZURE_NO_DOT'].lower() != 'true':
        log('.')

    if os.environ.get('AZURE_REST_CURL'):
        headers, response = request_curl(method, url, cert, body, headers,
                                         max_time)
    elif os.environ.get('AZURE_REST_HTTP'):
        if 'http' not in globals():
            global http
            import imp
            http = imp.load_source('http', os.environ['AZURE_REST_HTTP'])
            http.debug = debug
        headers, response = http.request(method, url, cert, body, headers,
                                         pool, max_time)
    else:
        raise Exception('No request function')

    if not (200 <= int(headers['code']) < 300):
        raise RequestException(
            headers['proto'], headers['code'], headers['reason'], response)

    if not response:
        document = None
    elif headers.get('content-type', '').startswith('application/xml'):
        document = xml.dom.minidom.parseString(response)
    elif headers.get('content-type', '').startswith('application/json'):
        document = json.loads(response,
                              object_pairs_hook=collections.OrderedDict)
    elif method == 'HEAD':
        document = None
    else:
        document = response

    return headers, document


class CurlException(Exception):
    def __init__(self, err, cmd):
        super(Exception, self).__init__(err)
        self.cmd = cmd


def request_curl(method, url, cert=None, body=None, headers=None,
                 max_time=None):
    args = [
        os.environ['AZURE_REST_CURL'],
        '--silent',
        '--show-error',
        '--globoff',
        '--dump-header', '/dev/fd/2',
        '--url', url,
    ]
    if method == 'HEAD':
        args += ['--head']
    else:
        args += ['--request', method]
    if cert:
        args += ['--cert', cert]
    if body:
        args += ['--data-binary', '@-']
        args += ['--header', 'content-length: %d' % len(body)]
    elif method == 'PUT' or method == 'POST':
        args += ['--header', 'content-length: 0']

    if max_time:
        args += ['--max-time', str(max_time)]

    if headers:
        for h in headers:
            args += ['--header', h]

    args_no_auth = []
    for arg in args:
        if arg.lower().startswith('authorization'):
            key, col, val = arg.partition(':')
            arg = '%s%s *' % (key, col)
        args_no_auth.append(arg)
    debug('%s\n' % args_no_auth)

    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    response, headers = p.communicate(body)
    debug('%s\n' % headers)
    if p.poll():
        raise CurlException(headers, args_no_auth)

    # use only the last set of headers
    lines = [h.strip() for h in headers.strip().split('\n')]
    ends = [i for i, line in enumerate(lines) if line == '']
    if len(ends) > 0:
        lines = lines[ends[-1] + 1:]
    try:
        proto, code, reason = lines[0].split(' ', 2)
    except:
        raise CurlException(
            'Bad status line: %s' % repr(lines[0]), args_no_auth)
    headers = {'proto': proto, 'code': int(code), 'reason': reason}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        key = key.strip().lower()
        if key in {'proto', 'code', 'reason'}:
            raise Exception('Unexpected HTTP header: %s' % key)
        headers[key] = value.strip()

    return headers, response


class Environment(object):
    ATTRIBUTES = ['name', 'login', 'core', 'arm', 'graph']
    s = {}

    def __init__(self, **kwargs):
        if set(self.ATTRIBUTES) != set(kwargs.keys()):
            raise Exception('Too many or too few environment parameters')
        for attr in kwargs.keys():
            setattr(self, attr, kwargs[attr])
        self.s[self.name] = self

Environment(
    name='AzureCloud', login='login.windows.net',
    core='core.windows.net', arm='management.azure.com',
    graph='graph.windows.net')
Environment(
    name='AzureChinaCloud', login='login.chinacloudapi.cn',
    core='core.chinacloudapi.cn', arm='management.chinacloudapi.cn',
    graph='graph.chinacloudapi.cn')
Environment(
    name='AzureUSGovernment', login='login-us.microsoftonline.com',
    core='core.usgovcloudapi.net', arm='management.usgovcloudapi.net',
    graph='graph.windows.net')
Environment(
    name='AzureGermanCloud', login='login.microsoftonline.de',
    core='core.cloudapi.de', arm='management.microsoftazure.de',
    graph='graph.cloudapi.de')


class Azure(object):
    def __init__(self, subscription=None, credentials={}, max_time=None,
                 environment=None):
        self.pool = {}
        self.tokens = {}
        self.accounts = {}
        self.subscription = subscription
        if isinstance(credentials, basestring):
            if credentials.startswith('{'):
                credentials = json.loads(credentials)
            else:
                with open(credentials) as f:
                    credentials = json.load(f)
        self.credentials = credentials.copy()
        self.max_time = max_time
        if not environment:
            environment = 'AzureCloud'
        if isinstance(environment, basestring):
            environment = Environment.s[environment]
        self.environment = environment

    @contextlib.contextmanager
    def get_token(self, tenant='common', resource=None):
        if not resource:
            resource = 'https://management.%s/' % self.environment.core
        if (resource not in self.tokens or
                not self.tokens[resource].get('access') or
                self.tokens[resource].get('expires', 0) < time.time()):
            debug('get_token: %s: no cache\n' % resource)
            credentials = self.credentials.copy()
            tenant = credentials.pop('tenant', tenant)
            url = 'https://' + self.environment.login
            url += '/%s/oauth2/token?api-version=1.0' % tenant
            credentials['resource'] = resource
            if 'username' in credentials:
                credentials.setdefault('grant_type', 'password')
                credentials.setdefault(
                    'client_id', '04b07795-8ddb-461a-bbee-02f9e1bf7b46')
            self.tokens[resource] = {'expires': time.time() - 120}
            h, b = request(
                'POST', url, body=urllib.urlencode(credentials),
                pool=self.pool, max_time=self.max_time)
            self.tokens[resource]['access'] = b['access_token']
            self.tokens[resource]['expires'] += int(b['expires_in'])
        try:
            yield self.tokens[resource]['access']
        except RequestException as e:
            if e.code in {401, 403}:
                debug('get_token: %s: delete from cache\n' % resource)
                del self.tokens[resource]
            raise

    def arm(self, method, path, body=None, headers=None, aggregate=False):
        if not path.startswith('/tenants') and not path.startswith(
                '/subscriptions'):
            if not self.subscription:
                raise Exception('subscription was not specified')
            path = '/subscriptions/' + self.subscription + path
        url = 'https://' + self.environment.arm + path

        if headers is None:
            headers = []

        if body:
            for i, h in enumerate(headers):
                if h.lower().startswith('content-type:'):
                    break
            else:
                headers += ['content-type: application/json']

        if 'api-version=' not in path:
            provider_prefix = '/providers/microsoft.'
            provider_index = path.lower().find(provider_prefix)
            if provider_index < 0:
                if path.lower().find('/providers/') >= 0:
                    raise Exception('unexpected provider:\n%s' % url)
                version = ARM_VERSIONS['resources/']
            else:
                provider_index += len(provider_prefix)
                for r in ARM_VERSIONS:
                    if path.lower()[provider_index:].startswith(r):
                        version = ARM_VERSIONS[r]
                        break
                else:
                    raise Exception('no api version:\n%s' % url)
            if '?' in url:
                url += '&'
            else:
                url += '?'
            url += 'api-version=' + version

        value = []
        while True:
            with self.get_token() as token:
                headers_with_auth = headers + [
                    'authorization: Bearer ' + token]
                h, b = request(method, url, body=body,
                               headers=headers_with_auth, pool=self.pool,
                               max_time=self.max_time)
            if not aggregate or method != 'GET':
                return h, b
            value += b['value']
            if 'nextLink' not in b:
                break
            url = b['nextLink']
        return {}, {'value': value}

    def graph(self, method, path, body=None, headers=None):
        if headers is None:
            headers = []

        resource = 'https://' + self.environment.graph
        url = resource + path

        if body:
            for i, h in enumerate(headers):
                if h.lower().startswith('content-type:'):
                    break
            else:
                headers += ['content-type: application/json']

        if 'api-version=' not in url:
            version = 'api-version=1.6'
            if '?' in url:
                url += '&'
            else:
                url += '?'
            url += version

        with self.get_token(resource=resource) as token:
            headers_with_auth = headers + ['authorization: Bearer ' + token]
            return request(method, url, body=body, headers=headers_with_auth,
                           pool=self.pool, max_time=self.max_time)

    def account_key(self, account):
        if account is None:
            raise Exception('storage account was not specified')

        def get_account(account, provider, key_name):
            self.accounts.setdefault('ids', {})
            if account not in self.accounts['ids']:
                accounts = self.arm(
                    'GET', '/providers/microsoft.' + provider)[1]['value']
                for a in accounts:
                    if a['properties']['provisioningState'] != 'Succeeded':
                        continue
                    self.accounts['ids'][a['name']] = a['id']
            if account not in self.accounts['ids']:
                return
            self.accounts['keys'][account] = self.arm(
                'POST',
                self.accounts['ids'][account] + '/listKeys')[1][key_name]

        self.accounts.setdefault('keys', {})
        if account not in self.accounts['keys']:
            get_account(account, 'storage/storageaccounts', 'key1')
        if account not in self.accounts['keys']:
            get_account(account, 'classicstorage/storageaccounts',
                        'primaryKey')
        if account not in self.accounts['keys']:
            raise Exception('Could not find keys for "%s"' % account)
        return account, self.accounts['keys'][account]

    def blob(self, method, account, path, body=None, headers=None, tag=None):
        debug('blob: %s %s %s %s %s\n' % (
            method, account, path,
            repr(body[:1024]) if isinstance(body, basestring) else str(body),
            headers))
        headers_dict = {}
        if headers is not None:
            for h in headers:
                name, val = h.split(':', 1)
                name = name.strip().lower()
                val = val.strip()
                headers_dict[name] = val
        if body and 'content-type' not in headers_dict:
            headers_dict['content-type'] = 'application/octet-stream'
            md5 = hashlib.md5()
            md5.update(body)
            headers_dict['content-md5'] = base64.b64encode(md5.digest())
        date = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
        headers_dict['x-ms-date'] = date
        if 'x-ms-version' not in headers_dict:
            headers_dict['x-ms-version'] = '2015-04-05'
        if account is None:
            m = re.match(
                r'https?://([^\.]+)\.blob\.%s(.*)$' %
                self.environment.core.replace('.', '\\.'), path)
            if m:
                account = m.group(1)
                path = m.group(2)
        markers = []
        result = []
        while True:
            marker_path = path
            if markers:
                marker_path += '&marker=' + markers[0]
            path_for_sig, sep, query = marker_path.partition('?')
            if query:
                params = {}
                for p in query.split('&'):
                    n, v = p.split('=', 1)
                    v = urllib2.unquote(v)
                    if '\n' in v or ',' in v:
                        raise Exception('cannot sign url with "\\n" or ","')
                    if n not in params:
                        params[n] = []
                    params[n].append(v)
                for n in sorted(params):
                    path_for_sig += (
                        '\n' + urllib2.unquote(n) + ':' + ','.join(params[n]))
            data = (
                method + '\n' +
                headers_dict.get('content-encoding', '') + '\n' +
                headers_dict.get('content-language', '') + '\n' +
                (str(len(body)) if body else '') + '\n' +  # content-length
                headers_dict.get('content-md5', '') + '\n' +
                headers_dict.get('content-type', '') + '\n' +
                headers_dict.get('date', '') + '\n' +
                headers_dict.get('if-modified-since', '') + '\n' +
                headers_dict.get('if-match', '') + '\n' +
                headers_dict.get('if-none-match', '') + '\n' +
                headers_dict.get('if-unmodified-since', '') + '\n' +
                headers_dict.get('range', '') + '\n')
            for h in sorted(headers_dict):
                if h.startswith('x-ms'):
                    data += h + ':' + headers_dict[h] + '\n'
            account, key = self.account_key(account)
            data += '/' + account + path_for_sig
            sig = base64.b64encode(hmac.HMAC(
                base64.b64decode(key), data, hashlib.sha256).digest())
            headers_dict['authorization'] = 'SharedKey ' + account + ':' + sig
            headers = ['%s: %s' % (n, headers_dict[n]) for n in headers_dict]
            h, b = request(
                method,
                'https://' + account + '.blob.core.windows.net' + marker_path,
                body=body,
                headers=headers,
                pool=self.pool,
                max_time=self.max_time)
            if not tag:
                return h, b
            result += [e for e in b.getElementsByTagName(tag)]
            markers = values(b, 'NextMarker')
            if not markers:
                break
        b = xml.dom.minidom.parseString('<' + tag + 's/>')
        for e in result:
            b.documentElement.appendChild(e)
        return {}, b

    def eventhub(self, method, connection, path, body=None, headers=None):
        if headers is None:
            headers = []
        if body:
            for i, h in enumerate(headers):
                if h.lower().startswith('content-type:'):
                    break
            else:
                if body[0] == '[':
                    headers += [
                        'content-type: ' +
                        'application/vnd.microsoft.servicebus.json']
                else:
                    headers += [
                        'content-type: ' +
                        'application/atom+xml;type=entry;charset=utf-8']
        if not connection:
            connection = os.environ['AZURE_EVENTHUB']
        conn = {}
        for part in connection.split(';'):
            k, _, v = part.partition('=')
            conn[k] = v
        url = 'https' + conn['Endpoint'][2:] + conn['EntityPath'] + path
        key_name = conn['SharedAccessKeyName']
        key = str(conn['SharedAccessKey'])
        sr = urllib2.quote(url, '').lower()
        se = str(int(time.time() + 300))
        string_to_sign = sr + '\n' + se
        sig = hmac.HMAC(key, string_to_sign, hashlib.sha256).digest()
        sig = urllib2.quote(base64.b64encode(sig), '')
        headers += [
            'Authorization: SharedAccessSignature ' +
            'sig=%s&se=%s&skn=%s&sr=%s' % (sig, se, key_name, sr)]
        return request(method, url, body=body, headers=headers,
                       pool=self.pool, max_time=self.max_time)

    def loganalytics(self, customer_id, key, log_type, body):
        method = 'POST'
        path = '/api/logs'
        date = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
        body = json.dumps(body)

        customer_id = str(customer_id)
        key = str(key)

        headers = {
            'content-length': str(len(body)),
            'content-type': 'application/json',
            'Log-Type': log_type,
            'x-ms-date': date
        }
        string_to_sign = '\n'.join([
            method,
            headers['content-length'],
            headers['content-type'],
            'x-ms-date:' + headers['x-ms-date'],
            path
        ])
        sig = base64.b64encode(hmac.new(base64.b64decode(key), string_to_sign,
                               digestmod=hashlib.sha256).digest())
        headers['Authorization'] = 'SharedKey %s:%s' % (customer_id, sig)

        url = ''.join([
            'https://', customer_id, '.ods.opinsights.azure.com', path,
            '?api-version=2016-04-01'])

        headers = ['%s: %s' % (name, headers[name])
                   for name in headers if name != 'content-length']
        return request(method, url, body=body, headers=headers,
                       pool=self.pool, max_time=self.max_time)


def init(*args, **kwargs):
    if '_once' not in globals():
        globals()['_once'] = True
        for m in inspect.getmembers(Azure, inspect.ismethod):
            if m[0] in globals():
                raise Exception('symbol collision for "%s"' % m[0])

    subscription = kwargs.get('subscription')
    if not subscription:
        subscription = os.environ.get('AZURE_SUBSCRIPTION')
        if subscription:
            kwargs['subscription'] = subscription

    credentials = kwargs.get('credentials')
    if not credentials:
        if 'AZURE_CREDENTIALS' in os.environ:
            credentials = os.environ['AZURE_CREDENTIALS']
        elif 'AZURE_USERNAME' in os.environ and 'AZURE_PASSWORD' in os.environ:
            credentials = {
                'username': os.environ['AZURE_USERNAME'],
                'password': os.environ['AZURE_PASSWORD']}
        if credentials:
            kwargs['credentials'] = credentials

    max_time = kwargs.get('max_time')
    if not max_time:
        max_time = os.environ.get('AZURE_MAX_TIME')
        if max_time:
            kwargs['max_time'] = max_time

    environment = kwargs.get('environment')
    if not environment:
        environment = os.environ.get('AZURE_ENVIRONMENT')
        if environment:
            kwargs['environment'] = environment

    azure = Azure(*args, **kwargs)

    for m in inspect.getmembers(azure, inspect.ismethod):
        if m[0].startswith('_'):
            continue
        globals()[m[0]] = m[1]


def values(parent, *tags):
    result = []
    for tag in tags:
        result.append([e.firstChild.nodeValue
                       for e in parent.getElementsByTagName(tag)
                       if e.firstChild])
    if len(tags) == 1:
        return result[0]
    return zip(*result)


def usage():
    log('''Usage: %s %s ...

    arm METHOD RESOURCE [{BODY | -} [HEADER...]]
        METHOD: the HTTP verb {'PUT'|'GET'|'HEAD'|'POST'|'PATCH'|'DELETE'}
        RESOURCE: a path with optional query to such as '/resourcegroups/...'
        BODY: '-' means read the data from standard input
        HEADER: zero or more header in the form: 'NAME: VALUE'

    graph METHOD RESOURCE [{BODY | -} [HEADER...]]
        METHOD, BODY, HEADER...: see above
        RESOURCE: a path with optional query to such as '/users/...'

    blob METHOD {ACCOUNT | -} RESOURCE [{BODY | -} [HEADER...]]
        METHOD, BODY, HEADER...: see above
        ACCOUNT: '-' means get from RESOURCE
        RESOURCE: a path to the requested resource in the form:
            /CONTAINTER[/BLOB][?QUERY] if ACCOUNT is specified or
            https://ACCOUNT.blob.core.windows.net/CONTAINER[/BLOB][?QUERY]

    eventhub METHOD CONNECTION RESOURCE [{BODY | -} [HEADER...]]
        CONNECTION: the connection string of the eventhub; '-' means get from
            the environment variable AZURE_EVENTHUB.
            The connection string format: (the next 4 lines should be joined)
                Endpoint=sb://SERVICE-BUS-NAMESPACE.servicebus.windows.net;
                 SharedAccessKeyName=POLICY-NAME;
                 SharedAccessKey=POLICY-SAS-KEY;
                 EntityPath=EVENT-HUB-NAME
        METHOD, BODY, HEADER...: see above
        RESOURCE: a path such as /messages

''' % (sys.executable, sys.argv[0]))
    sys.exit(1)


def main(*args):
    global arm, blob, graph, eventhub  # for pyflakes
    init()
    if 'AZURE_NO_DOT' not in os.environ:
        os.environ['AZURE_NO_DOT'] = 'true'

    def collect(i, check_slash=True):
        if check_slash and (
                len(args) <= i - 1 or not args[i - 1].startswith('/')):
            log('The resource does not begin with a /\n')
            usage()
        body = None
        if len(args) > i:
            body = args[i]
            if body == '-':
                body = sys.stdin.read()
        headers = list(args[i + 1:])
        return {'body': body, 'headers': headers}

    if len(args) <= 3 or args[1] == '-h':
        usage()
    api = args[1]
    method = args[2]
    if method not in {'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH'}:
        log('Invalid HTTP method "%s"\n' % method)
        usage()
    if api == 'blob':
        account = None
        resource = args[3]
        if resource.startswith('https://') or resource.startswith('http://'):
            kwargs = collect(4, False)
        else:
            account = args[3]
            resource = args[4]
            kwargs = collect(5)
        if account == '-':
            account = None
        kwargs['tag'] = os.environ.get('AZURE_BLOB_TAG')
        h, b = blob(method, account, resource, **kwargs)
    elif api == 'arm':
        kwargs = collect(4)
        kwargs['aggregate'] = os.environ.get('AZURE_ARM_AGGREGATE')
        h, b = arm(method, args[3], **kwargs)
    elif api == 'graph':
        kwargs = collect(4)
        h, b = graph(method, args[3], **kwargs)
    elif api == 'eventhub':
        kwargs = collect(5)
        connection = args[3]
        if connection == '-':
            connection = None
        h, b = eventhub(method, connection, args[4], **kwargs)
    else:
        log('Unknown API "%s"\n' % api)
        usage()
    log(json.dumps(h, indent=2) + '\n')
    if hasattr(b, 'toprettyxml'):
        print b.toprettyxml().encode('utf-8')
    elif isinstance(b, dict) or isinstance(b, list):
        print json.dumps(b, indent=2).encode('utf-8')
    elif b is not None:
        sys.stdout.write(b)

if __name__ == '__main__':
    main(*sys.argv)
