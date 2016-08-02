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
import httplib
import inspect
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib
import urllib2
import urlparse
import xml.dom.minidom

# services with more specific path should precede
ARM_VERSIONS = {
    'web/sourcecontrols': '2015-08-01',
    'web/sites/slots/metrics': '2015-08-01',
    'web/sites/slots/metricdefinitions': '2015-08-01',
    'web/sites/slots/instances/extensions': '2015-08-01',
    'web/sites/slots/instances': '2015-08-01',
    'web/sites/slots/hostnamebindings': '2015-08-01',
    'web/sites/slots/extensions': '2015-08-01',
    'web/sites/slots': '2015-08-01',
    'web/sites/recommendations': '2015-08-01',
    'web/sites/premieraddons': '2015-08-01',
    'web/sites/metrics': '2015-08-01',
    'web/sites/metricdefinitions': '2015-08-01',
    'web/sites/instances/extensions': '2015-08-01',
    'web/sites/instances': '2015-08-01',
    'web/sites/hostnamebindings': '2015-08-01',
    'web/sites/extensions': '2015-08-01',
    'web/sites': '2015-08-01-preview',
    'web/serverfarms/metrics': '2015-08-01',
    'web/serverfarms/metricdefinitions': '2015-08-01',
    'web/serverfarms': '2015-08-01',
    'web/runtimes': '2015-08-01',
    'web/recommendations': '2015-08-01',
    'web/publishingusers': '2015-08-01',
    'web/operations': '2015-08-01',
    'web/managedhostingenvironments': '2015-08-01',
    'web/listsitesassignedtohostname': '2015-08-01',
    'web/ishostnameavailable': '2015-08-01',
    'web/ishostingenvironmentnameavailable': '2015-08-01',
    'web/hostingenvironments/workerpools/metrics': '2015-08-01',
    'web/hostingenvironments/workerpools/metricdefinitions': '2015-08-01',
    'web/hostingenvironments/workerpools/instances/metrics': '2015-08-01',
    'web/hostingenvironments/workerpools/instances/metricdefinitions':
        '2015-08-01',
    'web/hostingenvironments/workerpools/instances': '2015-08-01',
    'web/hostingenvironments/workerpools': '2015-08-01',
    'web/hostingenvironments/multirolepools/metrics': '2015-08-01',
    'web/hostingenvironments/multirolepools/metricdefinitions': '2015-08-01',
    'web/hostingenvironments/multirolepools/instances/metrics': '2015-08-01',
    'web/hostingenvironments/multirolepools/instances/metricdefinitions':
        '2015-08-01',
    'web/hostingenvironments/multirolepools/instances': '2015-08-01',
    'web/hostingenvironments/multirolepools': '2015-08-01',
    'web/hostingenvironments/metrics': '2015-08-01',
    'web/hostingenvironments/metricdefinitions': '2015-08-01',
    'web/hostingenvironments': '2015-08-01',
    'web/georegions': '2015-08-01',
    'web/deploymentlocations': '2015-08-01',
    'web/classicmobileservices': '2015-08-01',
    'web/certificates': '2015-08-01-preview',
    'web/availablestacks': '2015-08-01',
    'visualstudio/account/project': '2014-04-01-preview',
    'visualstudio/account': '2014-04-01-preview',
    'support/supporttickets': '2015-07-01-Preview',
    'support/operations': '2015-07-01-Preview',
    'streamanalytics/streamingjobs/metricdefinitions': '2014-04-01',
    'streamanalytics/streamingjobs/diagnosticsettings': '2014-04-01',
    'streamanalytics/operations': '2015-10-01',
    'streamanalytics/locations/quotas': '2015-10-01',
    'streamanalytics/locations': '2015-10-01',
    'storage/usages': '2015-06-15',
    'storage/storageaccounts/services/metricdefinitions': '2014-04-01',
    'storage/storageaccounts/services': '2014-04-01',
    'storage/storageaccounts': '2015-06-15',
    'storage/operations': '2015-06-15',
    'storage/checknameavailability': '2015-06-15',
    'sql/servers/usages': '2014-04-01-preview',
    'sql/servers/serviceobjectives': '2014-04-01-preview',
    'sql/servers/securityalertpolicies': '2015-05-01-preview',
    'sql/servers/restorabledroppeddatabases': '2014-04-01-preview',
    'sql/servers/resourcepools': '2014-04-01-preview',
    'sql/servers/recoverabledatabases': '2014-04-01-preview',
    'sql/servers/recommendedelasticpools': '2014-04-01-preview',
    'sql/servers/operationresults': '2014-04-01-preview',
    'sql/servers/importexportoperationresults': '2014-04-01-preview',
    'sql/servers/import': '2014-04-01-preview',
    'sql/servers/firewallrules': '2014-04-01-preview',
    'sql/servers/elasticpools/metrics': '2014-04-01-preview',
    'sql/servers/elasticpools/metricdefinitions': '2014-04-01-preview',
    'sql/servers/elasticpools/advisors': '2015-05-01-preview',
    'sql/servers/elasticpools': '2014-04-01-preview',
    'sql/servers/elasticpoolestimates': '2015-05-01-preview',
    'sql/servers/disasterrecoveryconfiguration': '2014-04-01-preview',
    'sql/servers/databasesecuritypolicies': '2014-04-01-preview',
    'sql/servers/databases/topqueries/querytext': '2014-04-01-preview',
    'sql/servers/databases/topqueries': '2014-04-01-preview',
    'sql/servers/databases/securityalertpolicies': '2014-04-01-preview',
    'sql/servers/databases/metrics': '2014-04-01-preview',
    'sql/servers/databases/metricdefinitions': '2014-04-01-preview',
    'sql/servers/databases/datamaskingpolicies/rules': '2014-04-01-preview',
    'sql/servers/databases/datamaskingpolicies': '2014-04-01-preview',
    'sql/servers/databases/connectionpolicies': '2014-04-01-preview',
    'sql/servers/databases/auditingsettings': '2015-05-01-preview',
    'sql/servers/databases/auditingpolicies': '2014-04-01-preview',
    'sql/servers/databases/advisors': '2015-05-01-preview',
    'sql/servers/databases': '2015-05-01-preview',
    'sql/servers/connectionpolicies': '2014-04-01-preview',
    'sql/servers/communicationlinks': '2014-04-01-preview',
    'sql/servers/auditingsettings': '2015-05-01-preview',
    'sql/servers/auditingpolicies': '2014-04-01-preview',
    'sql/servers/aggregateddatabasemetrics': '2014-04-01-preview',
    'sql/servers/advisors': '2015-05-01-preview',
    'sql/servers/administrators': '2014-04-01-preview',
    'sql/servers/administratoroperationresults': '2014-04-01-preview',
    'sql/servers': '2014-04-01-preview',
    'sql/operations': '2014-04-01-preview',
    'sql/locations/capabilities': '2014-04-01-preview',
    'sql/locations': '2014-04-01-preview',
    'sql/checknameavailability': '2014-04-01-preview',
    'servicefabric/clusters': '2015-01-01-alpha',
    'servicebus/operations': '2015-08-01',
    'servicebus/namespaces': '2015-08-01',
    'servicebus/checknamespaceavailability': '2015-08-01',
    'servermanagement/nodes': '2015-07-01-preview',
    'servermanagement/gateways': '2015-07-01-preview',
    'security/webapplicationfirewalls': '2015-06-01-preview',
    'security/tasks': '2015-06-01-preview',
    'security/securitystatuses': '2015-06-01-preview',
    'security/securitystatus/virtualmachines': '2015-06-01-preview',
    'security/securitystatus/subnets': '2015-06-01-preview',
    'security/securitystatus/endpoints': '2015-06-01-preview',
    'security/securitystatus': '2015-06-01-preview',
    'security/policies': '2015-06-01-preview',
    'security/monitoring/patch': '2015-06-01-preview',
    'security/monitoring/baseline': '2015-06-01-preview',
    'security/monitoring/antimalware': '2015-06-01-preview',
    'security/monitoring': '2015-06-01-preview',
    'security/datacollectionresults': '2015-06-01-preview',
    'security/datacollectionagents': '2015-06-01-preview',
    'security/appliances': '2015-06-01-preview',
    'security/alerts': '2015-06-01-preview',
    'search/searchservices': '2015-08-19',
    'search/operations': '2015-08-19',
    'search/checkservicenameavailability': '2015-02-28',
    'search/checknameavailability': '2015-08-19',
    'scheduler/operations': '2014-08-01-preview',
    'scheduler/jobcollections': '2014-08-01-preview',
    'scheduler/flows': '2015-08-01-preview',
    'resources/tenants': '2015-01-01',
    'resources/subscriptions/tagnames/tagvalues': '2015-01-01',
    'resources/subscriptions/tagnames': '2015-01-01',
    'resources/subscriptions/resources': '2015-01-01',
    'resources/subscriptions/resourcegroups/resources': '2015-01-01',
    'resources/subscriptions/resourcegroups': '2015-01-01',
    'resources/subscriptions/providers': '2015-01-01',
    'resources/subscriptions/operationresults': '2015-01-01',
    'resources/subscriptions/locations': '2015-01-01',
    'resources/subscriptions': '2015-01-01',
    'resources/resources': '2015-01-01',
    'resources/resourcegroups': '2015-01-01',
    'resources/providers': '2015-01-01',
    'resources/operations': '2015-01-01',
    'resources/links': '2015-01-01',
    'resources/deployments/operations': '2015-11-01',
    'resources/deployments': '2015-11-01',
    'resources/checkresourcename': '2015-01-01',
    'resourcehealth/availabilitystatuses': '2015-01-01',
    'operationalinsights/workspaces': '2015-11-01-preview',
    'operationalinsights/storageinsightconfigs': '2014-10-10',
    'operationalinsights/operations': '2014-11-10',
    'operationalinsights/linktargets': '2015-03-20',
    'notificationhubs/operations': '2014-09-01',
    'notificationhubs/namespaces/notificationhubs': '2014-09-01',
    'notificationhubs/namespaces': '2014-09-01',
    'notificationhubs/checknamespaceavailability': '2014-09-01',
    'notificationhubs/billingtier': '2014-09-01',
    'network/virtualnetworks': '2015-06-15',
    'network/virtualnetworkgateways': '2015-06-15',
    'network/trafficmanagerprofiles': '2015-11-01',
    'network/routetables': '2015-06-15',
    'network/publicipaddresses': '2015-06-15',
    'network/operations': '2015-06-15',
    'network/networksecuritygroups': '2015-06-15',
    'network/networkinterfaces': '2015-06-15',
    'network/locations/usages': '2015-06-15',
    'network/locations/operations': '2015-06-15',
    'network/locations/operationresults': '2015-06-15',
    'network/locations/checkdnsnameavailability': '2015-06-15',
    'network/locations': '2015-06-15',
    'network/localnetworkgateways': '2015-06-15',
    'network/loadbalancers': '2015-06-15',
    'network/expressrouteserviceproviders': '2015-06-15',
    'network/expressroutecircuits': '2015-06-15',
    'network/dnszones/txt': '2015-05-04-preview',
    'network/dnszones/srv': '2015-05-04-preview',
    'network/dnszones/ptr': '2015-05-04-preview',
    'network/dnszones/mx': '2015-05-04-preview',
    'network/dnszones/cname': '2015-05-04-preview',
    'network/dnszones/aaaa': '2015-05-04-preview',
    'network/dnszones/a': '2015-05-04-preview',
    'network/dnszones': '2015-05-04-preview',
    'network/connections': '2015-06-15',
    'network/checktrafficmanagernameavailability': '2015-11-01',
    'network/applicationgateways': '2015-06-15',
    'marketplaceordering/operations': '2015-06-01',
    'marketplaceordering/agreements': '2015-06-01',
    'logic/workflows': '2015-08-01-preview',
    'logic/operations': '2015-08-01-preview',
    'logic/managedapis': '2015-08-01-preview',
    'logic/managedapiconnections': '2015-08-01-preview',
    'logic/apioperations': '2015-08-01-preview',
    'keyvault/vaults/secrets': '2015-06-01',
    'keyvault/vaults': '2015-06-01',
    'keyvault/operations': '2015-06-01',
    'insights/webtests': '2015-05-01',
    'insights/queries': '2015-05-01',
    'insights/operations': '2015-04-01',
    'insights/metricdefinitions': '2015-07-01',
    'insights/logdefinitions': '2015-07-01',
    'insights/locations/operationresults': '2015-04-01',
    'insights/locations': '2015-04-01',
    'insights/eventtypes': '2015-04-01',
    'insights/diagnosticsettings': '2015-07-01',
    'insights/components': '2015-05-01',
    'insights/autoscalesettings': '2015-04-01',
    'insights/automatedexportsettings': '2015-04-01',
    'insights/alertrules': '2015-04-01',
    'features/providers': '2015-12-01',
    'features/operations': '2015-12-01',
    'features/features': '2015-12-01',
    'eventhub/operations': '2015-08-01',
    'eventhub/namespaces': '2014-09-01',
    'eventhub/checknamespaceavailability': '2015-08-01',
    'dynamicslcs/operations': '2015-02-01-preview',
    'dynamicslcs/lcsprojects/connectors': '2015-05-01-alpha',
    'dynamicslcs/lcsprojects/clouddeployments': '2015-05-01-alpha',
    'dynamicslcs/lcsprojects': '2015-05-01-alpha',
    'domainregistration/validatedomainregistrationinformation': '2015-04-01',
    'domainregistration/topleveldomains': '2015-04-01',
    'domainregistration/operations': '2015-04-01',
    'domainregistration/listdomainrecommendations': '2015-04-01',
    'domainregistration/generatessorequest': '2015-04-01',
    'domainregistration/domains': '2015-04-01',
    'domainregistration/checkdomainavailability': '2015-04-01',
    'documentdb/operations': '2015-04-08',
    'documentdb/databaseaccounts': '2015-04-08',
    'documentdb/databaseaccountnames': '2015-04-08',
    'devtestlab/operations': '2015-05-21-preview',
    'devtestlab/locations/operations': '2015-05-21-preview',
    'devtestlab/locations': '2015-05-21-preview',
    'devtestlab/labs/virtualmachines': '2015-05-21-preview',
    'devtestlab/labs/environments': '2015-05-21-preview',
    'devtestlab/labs': '2015-05-21-preview',
    'devtestlab/environments': '2015-05-21-preview',
    'devices/operations': '2015-08-15-preview',
    'devices/iothubs': '2015-08-15-preview',
    'devices/checknameavailability': '2015-08-15-preview',
    'datalakestore/operations': '2015-10-01-preview',
    'datalakeanalytics/operations': '2015-10-01-preview',
    'datafactory/operations': '2015-10-01',
    'datafactory/datafactoryschema': '2015-10-01',
    'datafactory/datafactories/metricdefinitions': '2014-04-01',
    'datafactory/datafactories/diagnosticsettings': '2014-04-01',
    'datafactory/datafactories': '2015-10-01',
    'datafactory/checkdatafactorynameavailability': '2015-05-01-preview',
    'datafactory/checkazuredatafactorynameavailability': '2015-10-01',
    'containerservice/operations': '2015-11-01-preview',
    'containerservice/locations/operations': '2015-11-01-preview',
    'containerservice/locations': '2015-11-01-preview',
    'containerservice/containerservices': '2015-11-01-preview',
    'compute/virtualmachinescalesets/virtualmachines/networkinterfaces':
        '2015-06-15',
    'compute/virtualmachinescalesets/virtualmachines': '2015-06-15',
    'compute/virtualmachinescalesets/networkinterfaces': '2015-06-15',
    'compute/virtualmachinescalesets/extensions': '2015-06-15',
    'compute/virtualmachinescalesets': '2015-06-15',
    'compute/virtualmachines/metricdefinitions': '2014-04-01',
    'compute/virtualmachines/extensions': '2015-06-15',
    'compute/virtualmachines/diagnosticsettings': '2014-04-01',
    'compute/virtualmachines': '2015-06-15',
    'compute/operations': '2015-06-15',
    'compute/locations/vmsizes': '2015-06-15',
    'compute/locations/usages': '2015-06-15',
    'compute/locations/publishers': '2015-06-15',
    'compute/locations/operations': '2015-06-15',
    'compute/locations': '2015-06-15',
    'compute/availabilitysets': '2015-06-15',
    'classicstorage/storageaccounts/services/metrics': '2014-04-01',
    'classicstorage/storageaccounts/services/metricdefinitions': '2014-04-01',
    'classicstorage/storageaccounts/services': '2014-04-01',
    'classicstorage/storageaccounts/metrics': '2014-04-01',
    'classicstorage/storageaccounts/metricdefinitions': '2014-04-01',
    'classicstorage/storageaccounts': '2015-12-01',
    'classicstorage/quotas': '2015-12-01',
    'classicstorage/osimages': '2015-12-01',
    'classicstorage/operations': '2015-12-01',
    'classicstorage/images': '2015-12-01',
    'classicstorage/disks': '2015-12-01',
    'classicstorage/checkstorageaccountavailability': '2015-12-01',
    'classicstorage/capabilities': '2015-12-01',
    'classicnetwork/virtualnetworks': '2015-12-01',
    'classicnetwork/reservedips': '2015-12-01',
    'classicnetwork/quotas': '2015-12-01',
    'classicnetwork/operations': '2015-12-01',
    'classicnetwork/networksecuritygroups': '2015-12-01',
    'classicnetwork/gatewaysupporteddevices': '2015-12-01',
    'classiccompute/virtualmachines/metrics': '2014-04-01',
    'classiccompute/virtualmachines/metricdefinitions': '2014-04-01',
    'classiccompute/virtualmachines/diagnosticsettings': '2014-04-01',
    'classiccompute/virtualmachines': '2015-12-01',
    'classiccompute/resourcetypes': '2015-12-01',
    'classiccompute/quotas': '2015-12-01',
    'classiccompute/operationstatuses': '2015-12-01',
    'classiccompute/operations': '2015-12-01',
    'classiccompute/movesubscriptionresources': '2015-12-01',
    'classiccompute/domainnames/slots/roles/metrics': '2014-04-01',
    'classiccompute/domainnames/slots/roles/metricdefinitions': '2014-04-01',
    'classiccompute/domainnames/slots/roles': '2015-12-01',
    'classiccompute/domainnames/slots': '2015-12-01',
    'classiccompute/domainnames': '2015-12-01',
    'classiccompute/checkdomainnameavailability': '2015-12-01',
    'classiccompute/capabilities': '2015-12-01',
    'cdn/profiles/endpoints/origins': '2015-06-01',
    'cdn/profiles/endpoints/customdomains': '2015-06-01',
    'cdn/profiles/endpoints': '2015-06-01',
    'cdn/profiles': '2015-06-01',
    'cdn/operations': '2015-06-01',
    'cdn/operationresults/profileresults/endpointresults/originresults':
        '2015-06-01',
    'cdn/operationresults/profileresults/endpointresults/customdomainresults':
        '2015-06-01',
    'cdn/operationresults/profileresults/endpointresults': '2015-06-01',
    'cdn/operationresults/profileresults': '2015-06-01',
    'cdn/operationresults': '2015-06-01',
    'cdn/edgenodes': '2015-06-01',
    'cdn/checknameavailability': '2015-06-01',
    'cache/redisconfigdefinition': '2015-08-01',
    'cache/redis/metricdefinitions': '2014-04-01',
    'cache/redis/diagnosticsettings': '2014-04-01',
    'cache/redis': '2015-08-01',
    'cache/operations': '2015-08-01',
    'cache/checknameavailability': '2015-08-01',
    'biztalkservices/biztalk': '2014-04-01-preview',
    'bingmaps/updatecommunicationpreference': '2015-07-02',
    'bingmaps/operations': '2015-07-02',
    'bingmaps/mapapis': '2015-07-02',
    'bingmaps/listcommunicationpreference': '2015-07-02',
    'batch/operations': '2015-12-01',
    'batch/locations/quotas': '2015-12-01',
    'batch/locations': '2015-09-01',
    'batch/batchaccounts': '2015-12-01',
    'automation/operations': '2015-10-31',
    'automation/automationaccounts/runbooks': '2015-10-31',
    'automation/automationaccounts': '2015-10-31',
    'authorization/roledefinitions': '2015-07-01',
    'authorization/roleassignments': '2015-07-01',
    'authorization/provideroperations': '2015-07-01-preview',
    'authorization/policydefinitions': '2015-10-01-preview',
    'authorization/policyassignments': '2015-10-01-preview',
    'authorization/permissions': '2015-07-01',
    'authorization/operations': '2015-07-01',
    'authorization/locks': '2015-01-01',
    'authorization/classicadministrators': '2015-06-01',
    'appservice/operations': '2015-03-01-preview',
    'appservice/gateways': '2015-03-01-preview',
    'appservice/deploymenttemplates': '2015-03-01-preview',
    'appservice/appidentities': '2015-03-01-preview',
    'appservice/apiapps': '2015-03-01-preview',
    'apimanagement/validateservicename': '2015-09-15',
    'apimanagement/service': '2015-09-15',
    'apimanagement/reportfeedback': '2015-09-15',
    'apimanagement/operations': '2015-09-15',
    'apimanagement/checkservicenameavailability': '2015-09-15',
    'apimanagement/checknameavailability': '2015-09-15',
    'apimanagement/checkfeedbackrequired': '2015-09-15',
    'adhybridhealthservice/services': '2014-01-01',
    'adhybridhealthservice/servicehealthmetrics': '2014-01-01',
    'adhybridhealthservice/reports': '2014-01-01',
    'adhybridhealthservice/operations': '2014-01-01',
    'adhybridhealthservice/logs': '2014-01-01',
    'adhybridhealthservice/configuration': '2014-01-01',
    'adhybridhealthservice/anonymousapiusers': '2014-01-01',
    'adhybridhealthservice/agents': '2014-01-01',
    'adhybridhealthservice/addsservices': '2014-01-01',
    'adhybridhealthservice/aadsupportcases': '2014-01-01',
}


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
    else:
        headers, response = request_py(method, url, cert, body, headers, pool,
                                       max_time)

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


class SecureHTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock = ssl.wrap_socket(
            self.sock, self.key_file, self.cert_file,
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=os.environ.get('CURL_CA_BUNDLE'))
        subjects = [h for t, h in self.sock.getpeercert()['subjectAltName']
                    if t == 'DNS']
        for subject in subjects:
            if self.subject == subject or (
                    subject.startswith('*.') and
                    self.subject.endswith(subject[1:])):
                debug('hostname matched: %s\n' % subject)
                break
        else:
            raise Exception('host name mismatch')


def request_py(method, url, cert=None, body=None, headers=None, pool=None,
               max_time=None):
    if max_time:
        raise Exception('timeout is not supported')
    url_parts = urlparse.urlparse(url)
    port = url_parts.port
    if not port:
        port = 443 if url_parts.scheme == 'https' else 80
    host = url_parts.hostname

    headers_dict = {}
    if headers is not None:
        for h in headers:
            name, val = h.split(':', 1)
            name = name.strip().lower()
            val = val.strip()
            headers_dict[name] = val
    if 'host' not in headers_dict:
        headers_dict['host'] = url_parts.netloc

    if body:
        headers_dict['content-length'] = '%d' % len(body)
    elif method == 'PUT' or method == 'POST':
        headers_dict['content-length'] = '0'

    headers_no_auth = {
        k: headers_dict[k] for k in headers_dict if k != 'authorization'}
    debug('%s\n' % [method, url, cert, headers_no_auth])

    conn_id = (os.getpid(), host, port)
    conn = None
    if pool is None:
        pool = {}
    try:
        conn, timestamp = pool.get(conn_id, (None, 0))
        if conn:
            del pool[conn_id]
            if timestamp < time.time() - 60:
                try:
                    conn.close()
                except:
                    pass
                conn = None
        if not conn:
            if 'https_proxy' in os.environ and os.environ['https_proxy']:
                proxy_url_parts = urlparse.urlparse(os.environ['https_proxy'])
                conn = SecureHTTPSConnection(
                    proxy_url_parts.hostname, proxy_url_parts.port)
                conn.set_tunnel(host, port)
            else:
                conn = SecureHTTPSConnection(host, port)
            conn.subject = host
            if cert:
                conn.key_file = conn.cert_file = cert

        conn.request(method, url_parts.path + '?' + url_parts.query,
                     body=body, headers=headers_dict)
        resp = conn.getresponse()
        resp_headers = dict(resp.getheaders())
        resp_headers['proto'] = 'HTTP/' + '.'.join(list(str(resp.version)))
        resp_headers['code'] = resp.status
        resp_headers['reason'] = resp.reason
        debug('%s\n' % resp_headers)
        resp_body = resp.read()

        pool[conn_id] = (conn, time.time())
    except:
        def cleanup():
            try:
                conn.close()
            except:
                pass
            try:
                pool[conn_id].close()
            except:
                pass
            try:
                del pool[conn_id]
            except:
                pass
        cleanup()
        raise

    return resp_headers, resp_body


def request_curl(method, url, cert=None, body=None, headers=None,
                 max_time=None):
    args = [
        os.environ['AZURE_REST_CURL'],
        '--silent',
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

    debug('%s\n' % args)

    if headers:
        for h in headers:
            args += ['--header', h]

    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    response, headers = p.communicate(body)
    debug('%s\n' % headers)
    if p.poll():
        raise Exception('curl exit is %d\n%s\n' % (p.poll(), headers))

    # use only the last set of headers
    lines = [h.strip() for h in headers.strip().split('\n')]
    ends = [i for i, line in enumerate(lines) if line == '']
    if len(ends) > 0:
        lines = lines[ends[-1] + 1:]
    proto, code, reason = lines[0].split(' ', 2)
    headers = {'proto': proto, 'code': int(code), 'reason': reason}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        key = key.strip().lower()
        if key in {'proto', 'code', 'reason'}:
            raise Exception('Unexpected HTTP header: %s' % key)
        headers[key] = value.strip()

    return headers, response


class Azure(object):
    def __init__(self, subscription=None, credentials={}, max_time=None):
        self.pool = {}
        self.tokens = {}
        self.accounts = {}
        self.subscription = subscription
        self.credentials = credentials.copy()
        self.max_time = max_time

    @contextlib.contextmanager
    def get_token(self, tenant='common',
                  resource='https://management.core.windows.net/'):
        if (resource not in self.tokens or
                not self.tokens[resource].get('access') or
                self.tokens[resource].get('expires', 0) < time.time()):
            debug('get_token: %s: no cache\n' % resource)
            credentials = self.credentials.copy()
            tenant = credentials.pop('tenant', tenant)
            url = 'https://login.windows.net'
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
        url = 'https://management.azure.com' + path

        if headers is None:
            headers = []

        if body:
            for i, h in enumerate(headers):
                if h.lower().startswith('content-type:'):
                    break
            else:
                headers += ['content-type: application/json']

        if 'api-version=' not in url:
            version = 'api-version=2015-01-01'
            for r in ARM_VERSIONS:
                if '/providers/microsoft.' + r in url.lower():
                    version = 'api-version=' + ARM_VERSIONS[r]
                    break
            if '?' in url:
                url += '&'
            else:
                url += '?'
            url += version

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

        resource = 'https://graph.windows.net'
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

        def get_accounts(provider, version, key_name):
            accounts = self.arm(
                'GET', '/providers/' + provider + '?api-version' + version
                )[1]['value']
            for a in accounts:
                if a['properties']['provisioningState'] != 'Succeeded':
                    continue
                key = self.arm(
                    'POST',
                    a['id'] + '/listKeys?api-version=' + version)[1][key_name]
                self.accounts[a['name']] = {'id': a['id'], 'key': key}

        if account not in self.accounts:
            get_accounts(
                'microsoft.storage/storageaccounts', '2015-06-15', 'key1')
        if account not in self.accounts:
            get_accounts(
                'microsoft.classicstorage/storageaccounts', '2015-06-01',
                'primaryKey')
        return account, self.accounts[account]['key']

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
                'https?://([^\.]+)\.blob\.core\.windows\.net(.*)$', path)
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
            if credentials.startswith('{'):
                credentials = json.loads(credentials)
            else:
                if not os.path.exists(
                        credentials) and os.path.sep not in credentials:
                    credentials = os.path.join(
                        os.path.dirname(__file__), credentials)
                with open(credentials) as f:
                    credentials = json.load(f)
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
