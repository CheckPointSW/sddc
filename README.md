# Overview

Tools for integration with the Software Defined Data Center (SDDC).


# Monitor

The monitor.py script works in conjucntion with:

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

|Tag name |Tag value |Comment|
|--------|---------|-------|
|x-chkp-management|The name of the management server as it appears in the configuraiton file|Mandatory|
|x-chkp-template|A name of a template as it appears in the configuration file|Mandatory|
|x-chkp-ip-address|The main IP address of the gateway or "private" or "public"|Only in AWS, Mandatory|
|x-chkp-interfaces|"NET-NAME-FOR-eth0:NET-NAME-FOR-eth1:..." a list of the neutron networks that are attached to each of the gateway interfaces|Only in OpenStack, Mandatory for gateways with more than one interface|

Optionally, in AWS, network interface objects (ENI) can optionally have the following tags:

|Tag name |Tag value|
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
	        "password": "STRING"
	    },
	    "templates": {
	        "BASE-TEMPLATE-NAME": {
	            "one-time-password": "STRING",
                    "version": "R77.30",
	            ...  // optional attributes of a simple-gateway web_api object
	        },
	        "TEMPLATE1-NAME": {
	            "proto": "BASE-TEMPLATE-NAME",
	            "policy": "POLICY1-NAME",
	            "proxy-ports": ["8080"],
	            ...  // optional attributes of a simple-gateway web_api object
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

	* name: a string represnting the management server. This should match the x-chkp-management tag on the instance
	* host: the IP address or host name of the management server.
	* fingerprint: the SHA256 fingerprint of the management certificate. disable fingerprint checking by providing an empty string "" (insecure)
    * user: A SmartCenter administrator username
	* One of the following:
		* password: The password associated with the user
		* b64password: The base64 encoded password (for additional obscurity)

* templates:
	* An object with one or more templates.
	* The name of each template must be unique.
	* When a new gateway instance is detected, the script uses the x-chkp-template tag value to
	* select a template from this list.
	* Templates can inherit attributes from other templates through the "proto" attribute.
	* The selected template determines the eventual gateway configuration including:
		* one-time-password: the one time password used to initiate secure internal communication between the gateway and the management
		* policy: a name of pre-existing security policy package to be installed on the gateway
		* proxy-ports: an optional list of TCP ports on which to enable the proxy on gateway feature

* controllers:
	* An object with one or more controller configuration objects.
	* The name of each controller must be unique
	* Controller attributes:
		* class: either "AWS" or "OpenStack"
		* For AWS controllers:
			* regions: a list of AWS region names
			* One of the following alternatives for specifying credenials:
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
		    "ec2:DescribeInstances"
		  ],
		  "Effect": "Allow",
		  "Resource": "*"
		}
	  ]
	}


## Running:
	./monitor.py --port 80 @conf.json

The script will start a web server on port 80 where a simple status page can be
viewed with a web browser.
