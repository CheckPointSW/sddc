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

import os
import subprocess
import sys
import urllib

import aws


def get_cpstat(flavor, flag, metrics):
    out = subprocess.check_output(
        'cpstat -f %s %s' % (flavor, flag), shell=True)
    stats = {}
    for line in out.split('\n'):
        name, colon, value = line.partition(':')
        value = value.strip()
        if value.isdigit():
            value = int(value)
        else:
            value = 0
        stats[name] = value

    return [(m, stats[m], metrics[m]) for m in metrics]


def main(argv):
    os.environ['AWS_CURL'] = 'curl_cli'
    os.environ['AWS_CA_BUNDLE'] = os.environ['CPDIR'] + '/conf/ca-bundle.crt'
    os.environ['AWS_NO_DOT'] = 'true'

    region = aws.http(
        'GET', aws.META_DATA + '/placement/availability-zone', '')[1][:-1]
    instance = aws.http('GET', aws.META_DATA + '/instance-id', '')[1]

    aws.init(key_file='IAM')

    metrics = []

    sources = [
        ['all', 'fw', {'Num. connections': 'Count'}],
        ['all', 'polsrv', {'Connected users': 'Count'}],
        ['all', 'os', {
            'Active Virtual Memory (Bytes)': 'Bytes',
            'Active Real Memory (Bytes)': 'Bytes',
            'Free Real Memory (Bytes)': 'Bytes',
            'Memory Swaps/Sec': 'Count/Second',
            'Memory To Disk Transfers/Sec': 'Count/Second',
            'CPU User Time (%)': 'Percent',
            'CPU System Time (%)': 'Percent',
            'CPU Idle Time (%)': 'Percent',
            'CPU Usage (%)': 'Percent',
            'CPU Queue Length': 'Count',
            'CPU Interrupts/Sec': 'Count/Second',
            'Disk Requests Queue': 'Count',
            'Disk Free Space (%)': 'Percent',
            'Disk Total Free Space (Bytes)': 'Bytes',
            'Disk Available Free Space (Bytes)': 'Bytes',
            'Disk Total Space (Bytes)': 'Bytes'}],
        ['all', 'vpn', {
            'Encrypted packets': 'Count',
            'Decrypted packets': 'Count',
            'Encryption errors': 'Count',
            'Decryption errors': 'Count',
            'IKE current SAs': 'Count',
            'IKE no response from peer (initiator errors)': 'Count',
            'IPsec current Inbound SAs': 'Count',
            'IPsec current Outbound SAs': 'Count',
            'IPsec number of VPN-1 peers': 'Count',
            'IPsec number of VPN-1 RA peers': 'Count'}]
    ]

    for source in sources:
        metrics += get_cpstat(*source)

    def put_metric(qs):
        if not len(qs):
            return
        qs['Action'] = 'PutMetricData'
        qs['Namespace'] = 'Check Point'
        aws.request(
            'monitoring', region, 'GET', '/?' + urllib.urlencode(qs), '')

    qs = {}
    for i, m in enumerate(metrics):
        if i % 16 == 0:
            put_metric(qs)
            qs = {}
        prefix = 'MetricData.member.' + str(i % 16 + 1) + '.'
        qs[prefix + 'MetricName'] = m[0]
        qs[prefix + 'Value'] = m[1]
        qs[prefix + 'Unit'] = m[2]
        qs[prefix + 'Dimensions.member.1.Name'] = 'InstanceID'
        qs[prefix + 'Dimensions.member.1.Value'] = instance

    put_metric(qs)


if __name__ == '__main__':
    main(sys.argv)
