# Overview

Tools for integration with the Software Defined Data Center (SDDC).


# Monitor

The monitor.py script works in conjunction with:

* A Check Point R80 SmartCenter Server (the management)

* One or more cloud environments such as AWS, Azure, or GCP (controllers)


The script will:

* Create gateway objects in the management as these are launched in the cloud

* Initialize secure internal communication between the instance and the management

* Install a security policy


The script uses specific tags in order to:

* Identify that an instance is as a Check Point gateway that should belong to the management

* Indicate which security policy and other settings should be applied to the gateway


In addition the script:

* Will delete the corresponding gateway object upon the instance termination.


## Installation

On any generic Linux with python 2.7 installed, download this repository.


## Configuration

### Tags and metadata

The following tags should be added to gateway instances (in GCP, tags do not have name/value, so these tags are specified as x-chkp-TAGNAME--TAGVALUE):

|Tag name|Tag value|Comment|
|--------|---------|-------|
|x-chkp-management|The name of the management server as it appears in the configuration file|Mandatory|
|x-chkp-template|A name of a template as it appears in the configuration file|Mandatory|
|x-chkp-ip-address|The main IP address of the gateway or "private" or "public"|AWS and Azure, defaults to "public"|
|x-chkp-tags|"TAG-NAME-1=TAG-VALUE-1:TAG-NAME-2=TAG-VALUE-2..." a list of tags separated by colons, with the name and value separated by an equal sign, the name should only include the part after the "x-chkp-" prefix (e.g., "management=my-management:template=my-template:ip-address=public")|Only in AWS, use the compound tag when instances already have close to 10 tags|

Optionally, in AWS and in Azure, network interface objects (ENIs/networkInterfaces) can have the following tags (in GCP these tags are specified as part of the instance tags, as x-chkp-TAGNAME-eth0--TAGVALUE):

|Tag name|Tag value|Comment|
|--------|---------|-------|
|x-chkp-topology|one of "external", "internal" or "specific"|A qualification of the address space that is found "behind" the interface. If not specified, on single interface gateways or on interfaces that are associated with a public IP address, this value defaults to be "external" and otherwise to "internal". The value "external" means the internet address space minus the addresses specified on "internal" and "specific". The value "internal" means the address range of the subnet to which the interface is connected. The value "specific" means the addresses represented by the network object group that is specified in the "specific-network" attribute of the template in the configuration file. Alternatively, if the value is of the form "specific:NETWORK-OBJECT-GROUP", then the addresses represented by the pre-existing object named NETWORK-OBJECT-GROUP are taken (overriding the configuration file)|
|x-chkp-anti-spoofing|"true" or "false"|Whether to enforce Anti Spoofing protection on traffic going through the interface, this is overridden to be "false" for single interface gateways|


### Configuration file

The script takes a configuration file in JSON format

    {
        "delay": 30,
        "management": {
            "name": "my-management",
            "host": "IP-ADDRESS-OR-HOST-NAME[:PORT]",
            "domain": "MANAGEMENT-DOMAIN (Optional)",
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
                "specific-network": "INTERNAL-NETWORK-OBJECT-GROUP (Optional)",
                "generation": "SOME-VALUE (Optional)",
                "restrictive-policy": "RESTRICTIVE-POLICY-NAME",
                "proxy-ports": ["8080"],
                "https-inspection": true,
                "identity-awareness": true,
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
            },
            "VPN-TEMPLATE-NAME": {
                "one-time-password": "STRING",
                "policy": "VPN-POLICY-NAME",
                "version": "R80.10",
                // VPN specific settings:
                "vpn-community-star-as-center": "STAR-COMMUNITY-NAME",
                "vpn-domain": "ENCRYPTION-DOMAIN-GROUP-NAME",
                "vpn": true,
                ...
            }
        },
        "controllers": {
            "AWS-PROD": {
                "class": "AWS",
                "domain": "DOMAIN-1 (Optional)",
                "templates": ["TEMPLATE1-NAME"],  // Optional
                "communities": ["COMMUNITY1-NAME"],  // Optional
                "access-key": "AWS-ACCESS-KEY",
                "secret-key": "AWS-SECRET-KEY",
                "sub-creds": {  // Optional
                    "SUB-ACCOUNT1": {
                        "access-key": "AWS-ACCESS-KEY",
                        "secret-key": "AWS-SECRET-KEY"
                    },
                    ...
                },
                "regions": ["us-east-1", "us-west-2"]
            },
            "AZURE-RESOURCES": {
                "class": "Azure",
                "domain": "DOMAIN-1 (Optional)",
                "templates": ["TEMPLATE2-NAME"],  // Optional
                "subscription": "SUBSCRIPTION-ID",
                "environment": "AzureCloud",  // Optional
                "credentials": {
                    "tenant": "THE-ACTIVE-DIRECTORY-TENANT-ID",
                    "grant_type": "client_credentials",
                    "client_id": "THE-APP-ID",
                    "client_secret": "THE-SERVICE-PRINCIPAL-PASSWORD"
                }
            },
            "GCP-DEPLOYMENT": {
                "class": "GCP",
                "domain": "DOMAIN-2 (Optional)",
                "project": "my-project",
                "credentials": "IAM"
            }
        }
    }


In reference to the above configuration:

* delay: time to wait in seconds after each poll cycle

* management:

    * name: a string representing the management server. This should match the x-chkp-management tag on the instance

    * host: the IP address or host name of the management server.

    * domain: the name or UID of the management domain if applicable (optional).

    * fingerprint: the SHA256 fingerprint of the management certificate. disable fingerprint checking by providing an empty string "" (insecure but reasonable if running locally on the management server). To retrieve the fingerprint, run the following command on the management server (in bash):

            cpopenssl s_client -connect 127.0.0.1:443 2>/dev/null </dev/null | cpopenssl x509 -outform DER | sha256sum | awk '{printf "sha256:%s\n", $1}'


    * user: a SmartCenter administrator username

    * One of the following:

        * password: The password associated with the user

        * b64password: The base64 encoded password (for additional obscurity)

    * If the host is either localhost or 127.0.0.1, and the user is omitted then the login will be done with the mgmt_cli tool "login-as-root" feature.

    * proxy: an optional value for the https_proxy environment variable.

    * custom-script: an optional script to run just after the policy is installed when a gateway is provisioned, and at the beginning of the deprovisioning process. When a gateway is added the script will be run with the keyword 'add', with the gateway name and the custom-parameters attribute in the template. When a gateway is deleted the script will run with the keyword 'delete' and the gateway name. In the case of a configuration update (for example, a load balancing configuration change or a template/generation change), the custom script will be run with 'delete' and later again with 'add' and the custom parameters.


* templates:

    * An object with one or more templates.

    * The name of each template must be unique.

    * When a new gateway instance is detected, the script uses the x-chkp-template tag value to select a template from this list.

    * Templates can inherit attributes from other templates through the "proto" attribute. An attribute (like "policy") can be specified either in the template object or in the template object referred in the "proto" attribute. The value in the template always overrides the parent ("proto") template value. If the attribute is also missing in the parent, it is looked up in the parent's parent (if applicable) and so on.

    * The selected template determines the eventual gateway configuration including:

        * one-time-password: the one time password used to initiate secure internal communication between the gateway and the management

        * version: the gateway version (e.g. R77.30)

        * policy: a name of a pre-existing security policy package to be installed on the gateway

        * specific-network: an optional name of a pre-existing network object group that defines the topology settings for the interfaces marked with "specific" topology. This attribute is mandatory if any of the scanned instances has an interface with a topology set to "specific". Typically this should point to the name of a "Group with Exclusions" object, which contains a network group holding the VPC address range and excludes a network group which contains the "external" networks of the VPC, that is, networks that are connected to the internet

        * generation: an optional string or number that can be used to force re-applying a template to an already existing gateway. If generation is specified and its value is different than the previous value, then the template settings will be reapplied to the gateway

        * restrictive-policy: an optional name of a pre-existing policy package to be installed as the first policy on a new provisioned gateway. (Created to avoid a limitation in which Access Policy and Threat Prevention Policy cannot be installed at the first time together). In the case where no attribute is provided, a default policy will be used (the default policy has only the implied rules and a drop-all cleanup rule). The value null can be used to explicitly avoid any such policy.

        * proxy-ports: an optional list of TCP ports on which to enable the proxy on gateway feature

        * https-inspection: an optional boolean attribute indicating whether to enable the HTTPS Inspection feature on the gateway

        * identity-awareness: an optional boolean attribute indicating whether to enable the Identity Awareness feature on the gateway

        * ips-profile: an optional IPS profile name to associate with a pre-R80 gateway

        * vpn-community-star-as-center: the star community in which to place the VPN gateway (with "vpn": true) as center (optional)

        * vpn-domain: the group object to be set as the VPN domain for the VPN gateway (with "vpn": true). An empty string will automatically set an empty group as the encryption domain. No value or null will set the encryption domain to addresses behind the gateways

        * custom-parameters: an optional string with space separated parameters or a list of string parameters to specify when a gateway is added and a custom script is specified in the management section.

        * any other attribute that can be set with the set-simple-gateway R80 Web API as documented in the [Management API Reference](https://sc1.checkpoint.com/documents/R80/APIs/index.html#web/set-simple-gateway)


* controllers:

    * An object with one or more controller configuration objects.

    * The name of each controller must be unique.

    * Controller attributes:

        * class: either "AWS", "Azure" or "GCP"

        * domain: the name or UID of the management domain if applicable (optional). In MDS, instances that are discovered by this controller, will be defined in this domain. If not specified, the domain specified in the management object (in the configuration), will be used. This attribute should not be specified if the management server is not an MDS

        * templates: an optional list of of templates, which are allowed for instances that are discovered by this controller. If this attribute is missing or its value is an empty list, the meaning is that any template may be used by gateways that belong to this controller. This is useful in MDS environments, where controllers work with different domains and it is necessary to restrict a gateway to only use templates that were intended for its domain

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

                * Using an STS assumed role:

                    * accesss-key/secret-key or cred-file (path to file or "IAM") for retreiving the STS temporary credentials

                    * sts-role: the STS RoleArn of the role to assume

                    * sts-external-id: optional STS ExternalId to use when assuming the role

            * sub-creds: an optional object containing credentials specified with the options above (access-key/secret-key or cred-file, optionally with STS role to assume)

            * communities: an optional list of of communities, which are allowed for VPN connections that are discovered by this controller. If this attribute is missing or its value is an empty list, the meaning is that any community may be joined by VPN connections that belong to this controller. This is useful to prevent automatic addition of VPN connections to a community based on the customer gateway public IP address

        * For Azure controllers:

            * subscription: the Azure subscription ID

            * environment: an optional attribute to specify the Azure environemnt. The default is "AzureCloud", but one of the other environments like "AzureChinaCloud", "AzureGermanCloud" or "AzureUSGovernment" can be speciied instead

            * credentials: an object containing one of the following alternatives (in any case the entity for which the credentials are specified (a service principal or a user) must have "read" access to the relevant resources in the subscription):

                * Service Principal:

                    * tenant: the Azure Active Directory tenant ID

                    * grant_type: "client_credentials"

                    * client_id: the application ID with which the service principal is associated

                    * client_secret: the service principal password

                * User name and password:

                    * username: the Azure fully qualified user name

                    * password: the password for the user

        * For GCP controllers:

            * project: the GCP project ID in which to scan for VM instances

            * credentials: a string with the special value "IAM" for automatic retrieval of the service account credentials from the VM instance metadata (when the management server is run in GCP; or a path to a file containing service account credentials


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
            "elasticloadbalancing:DescribeListeners",
            "elasticloadbalancing:DescribeTargetGroups",
            "elasticloadbalancing:DescribeRules",
            "elasticloadbalancing:DescribeTargetHealth",
            "autoscaling:DescribeAutoScalingGroups"
          ],
          "Effect": "Allow",
          "Resource": "*"
        }
      ]
    }


## GCP service account IAM settings

If a service account credentials are used, then the service account should have at least Compute Engine Read Only scope (compute.readonly).
