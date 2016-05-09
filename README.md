# Overview

Tools for integration with the Software Defined Data Center (SDDC).


# Monitor

The monitor.py script works in conjunction with:

* A Check Point R80 SmartCenter Server (the management)

* One or more cloud environments such as AWS or OpenStack (controllers)


The script will:

* Create gateway objects in the management as these are launched in the cloud

* Initialize secure internal communication between the instance and the management

* Install a security policy


The script uses specific tags (AWS) or metadata (OpenStack) in order to:

* Identify that an instance is as a Check Point gateway that should belong to the management

* Indicate which security policy and other settings should be applied to the gateway


In addition the script:

* Will delete the corresponding gateway object upon the instance termination.

* Exposes a simple web page providing information about the status of the provisioning of the gateways


## Installation

On any generic Linux with python 2.7 installed, download this repository.


## Configuration:

### Tags and metadata:

The following tags should be added to gateway instances:

|Tag name|Tag value|Comment|
|--------|---------|-------|
|x-chkp-management|The name of the management server as it appears in the configuration file|Mandatory|
|x-chkp-template|A name of a template as it appears in the configuration file|Mandatory|
|x-chkp-ip-address|The main IP address of the gateway or "private" or "public"|Only in AWS, Mandatory|
|x-chkp-tags|"TAG-NAME-1=TAG-VALUE-1:TAG-NAME-2=TAG-VALUE-2..." a list of tags separated by colons, with the name and value separated by an equal sign, the name should only include the part after the "x-chkp-" prefix (e.g., "management=my-management:template=my-template:ip-address=public")|Only in AWS, use the compound tag when instances already have close to 10 tags|
|x-chkp-interfaces|"NET-NAME-FOR-eth0:NET-NAME-FOR-eth1:..." a list of the neutron networks that are attached to each of the gateway interfaces|Only in OpenStack, Mandatory for gateways with more than one interface|

Optionally, in AWS, network interface objects (ENI) can optionally have the following tags:

|Tag name|Tag value|
|--------|---------|
|x-chkp-topology|one of "external" or "internal"|
|x-chkp-anti-spoofing|"true" or "false"|


The script takes a configuration file in JSON format

    {
        "delay": 30,
        "management": {
            "name": "my-management",
            "host": "IP-ADDRESS-OR-HOST-NAME[:PORT]",
            "fingerprint": "sha256:FINGERPRINT-IN-HEX",
            "user": "SMARTCENTER-ADMIN-USERNAME",
            "password": "STRING",
            "proxy": "http://PROXY-HOST-NAME-OR-ADDRESS:PROXY-PORT",
            "custom-script": "PATH-TO-CUSTOMIZATION-SCRIPT"
        },
        "templates": {
            "BASE-TEMPLATE-NAME": {
                "one-time-password": "STRING",
                "version": "R77.30",
                "custom-parameters": "PARAM-1 PARAM-2 ...",
                ...  // optional attributes of a simple-gateway web_api object
            },
            "TEMPLATE1-NAME": {
                "proto": "BASE-TEMPLATE-NAME",
                "policy": "POLICY1-NAME",
                "generation": "SOME-VALUE (Optional)",
                "proxy-ports": ["8080"],
                "ips-profile": "Optimized",
                ...  // optional attributes of a simple-gateway web_api object
                "color": "orange",
                "application-control": true,
                "ips": true,
                ...
            },
            "TEMPLATE2-NAME": {
                "proto": "BASE-TEMPLATE-NAME",
                "policy": "POLICY2-NAME",
                ...  // optional attributes of a simple-gateway web_api object
            }
        },
        "controllers": {
            "AWS-PROD": {
                "class": "AWS",
                "access-key": "AWS-ACCESS-KEY",
                "secret-key": "AWS-SECRET-KEY",
                "regions": ["us-east-1", "us-west-2"]
            },
            "OPENSTACK-DEVTEST": {
                "class": "OpenStack",
                "scheme": "https",
                "host": "IP-ADDRESS-OR-HOST-NAME:KEYSTONE-PORT",
                "fingerprint": "sha256:FINGERPRINT-IN-HEX",
                "user: "OPENSTACK-USER",
                "password": "STRING",
                "tenant": "TENANT-UUID"
            }
        }
    }


In reference to the above configuration:

* delay: time to wait in seconds after each poll cycle

* management:

    * name: a string representing the management server. This should match the x-chkp-management tag on the instance

    * host: the IP address or host name of the management server.

    * fingerprint: the SHA256 fingerprint of the management certificate. disable fingerprint checking by providing an empty string "" (insecure but reasonable if running locally on the management server). To retrieve the fingerprint, run the following command on the management server (in bash):

            cpopenssl s_client -connect 127.0.0.1:443 2>/dev/null </dev/null | cpopenssl x509 -outform DER | sha256sum | awk '{printf "sha256:%s\n", $1}'


    * user: a SmartCenter administrator username

    * One of the following:

        * password: The password associated with the user

        * b64password: The base64 encoded password (for additional obscurity)

    * If the host is either localhost or 127.0.0.1, and the user is omitted then the login will be done with the mgmt_cli tool "login-as-root" feature.

    * proxy: an optional value for the https_proxy environment variable.

    * custom-script: an optional script to run just before the policy is installed when a gateway is provisioned, and at the beginning of the deprovisioning process. When a gateway is added the script will be run with the keyword 'add', with the gateway name and the custom-parameters attribute in the template. When a gateway is deleted the script will run with the keyword 'delete' and the gateway name. In the case of a configuration update (for example, a load balancing configuration change or a template/generation change), the custom script will be run with 'delete' and later again with 'add' and the custom parameters.


* templates:

    * An object with one or more templates.

    * The name of each template must be unique.

    * When a new gateway instance is detected, the script uses the x-chkp-template tag value to select a template from this list.

    * Templates can inherit attributes from other templates through the "proto" attribute.

    * The selected template determines the eventual gateway configuration including:

        * one-time-password: the one time password used to initiate secure internal communication between the gateway and the management

        * version: the gateway version (e.g. R77.30)

        * policy: a name of pre-existing security policy package to be installed on the gateway

        * generation: an optional string or number that can be used to force re-applying a template to an already existing gateway. If generation is specified and its value is different than the previous value, then the template settings will be reapplied to the gateway

        * proxy-ports: an optional list of TCP ports on which to enable the proxy on gateway feature

        * ips-profile: an optional IPS profile name to associate with a pre-R80 gateway

        * custom-parameters: an optional string with space separated parameters or a list of string parameters to specify when a gateway is added and a custom script is specified in the management section.

        * any other attribute that can be set with the set-simple-gateway R80 Web API as documented in the [Management API Reference](https://sc1.checkpoint.com/documents/R80/APIs/index.html#web/set-simple-gateway)


* controllers:

    * An object with one or more controller configuration objects.

    * The name of each controller must be unique

    * Controller attributes:

        * class: either "AWS" or "OpenStack"

        * For AWS controllers:

            * regions: a list of AWS region names

            * One of the following alternatives for specifying credentials:

                * Explicit:

                    * access-key: AWS-ACCESS-KEY

                    * secret-key: AWS-SECRET-KEY

                * From file:

                    * cred-file: the path to a text file containing AWS credentials in the following format

                        * AWSAccessKeyId=AWS-ACCESS-KEY

                        * AWSSecretKey=AWS-SECRET-KEY

                * Using an IAM role profile:

                    * cred-file: "IAM"

        * For OpenStack controllers:

            * scheme: one of "https" or "http"

            * host: The IP address and port of the keystone endpoint

            * fingerprint: the SHA256 fingerprint of the controller certificate. disable fingerprint checking by providing an empty string "" (insecure)

            * tenant: The tenant UUID

            * user: An OpenStack username

            * One of the following:

                * password: The password associated with the user

                * b64password: The base64 encoded password (for additional obscurity)


## AWS IAM role

If you are using a IAM role profile, you need to provide it with the following permissions:

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeSubnets",
            "ec2:DescribeInstances",
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeTags",
            "autoscaling:DescribeAutoScalingGroups"
          ],
          "Effect": "Allow",
          "Resource": "*"
        }
      ]
    }


## Running:

    ./monitor.py --port 80 conf.json

The script will start a web server on port 80 where a simple status page can be viewed with a web browser.
