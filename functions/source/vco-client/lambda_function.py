#!/usr/bin/env python3
##########################################################################
# Project: VMware SD-WAN AWS CloudWAN Quickstart
# Function: AWS Lambda
# Author: David Wight
# Date: 2022-06
##########################################################################

import boto3
from botocore.exceptions import ClientError
import time
import json
import cfnresponse
import requests
import re
import os
import logging
import uuid
import urllib3
from copy import deepcopy

logger = logging.getLogger()

config_d = {
    "profile_id": 0,
    "edge_count": 2,
    "TransitVpcName": "VMware-SDWAN-Transit",
    "SegmentList": [
        "Global"  # Global Segment can not be changed, always first in list
    ],
    "SubnetIdList": [],
    "VpcAttachList": [],
    "policy_d": {}
}


def _clean_method_name(raw_name):
    # Ensure method name is properly formatted prior to initiating request
    return raw_name.strip("/")


def _get_root_url(hostname):
    # Translate VCO hostname to a root url for API calls
    if hostname.startswith("http"):
        re.sub("http(s)?://", "", hostname)
    proto = "https://"
    return proto + hostname


def _remove_null_properties(data):
    return {k: v for k, v in data.iteritems() if v is not None}


class VcoClient(object):
    def __init__(self, hostname, verify_ssl=True):
        self._session = requests.Session()
        self._verify_ssl = verify_ssl
        self._root_url = _get_root_url(hostname)
        self._portal_url = self._root_url + "/portal/"
        self._seqno = 0

    def authenticate(self, username, password, is_operator=False):
        # Authenticate to API - on success, a cookie is stored in the session
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        path = "/login/operatorLogin" if is_operator else "/login/enterpriseLogin"
        url = self._root_url + path
        data = {"username": username, "password": password}
        headers = {"Content-Type": "application/json"}
        self._session.post(url, headers=headers, data=json.dumps(data),
                           allow_redirects=False, verify=self._verify_ssl)

    def request(self, method, params, ignore_null_properties=False):
        # Build and submit a request. Returns method result as a Python dictionary
        self._seqno += 1
        headers = {"Content-Type": "application/json"}
        method = _clean_method_name(method)
        payload = {"jsonrpc": "2.0",
                   "id": self._seqno,
                   "method": method,
                   "params": params}

        url = self._portal_url
        r = self._session.post(url, headers=headers,
                               data=json.dumps(payload), verify=self._verify_ssl)

        kwargs = {}
        if ignore_null_properties:
            kwargs["object_hook"] = _remove_null_properties
        response_dict = r.json(**kwargs)
        if "error" in response_dict:
            raise ApiException(response_dict["error"]["message"])
        return response_dict["result"]


class ApiException(Exception):
    pass


def get_enterprise_id():
    call_method = {"method": "enterprise/getEnterprise",
                   "params": {},
                   "help": "Get Enterprise ID"
                   }
    return call_method


def get_profile_id(ent_id=0):
    call_method = {"method": "enterprise/getEnterpriseConfigurations",
                   "params": {
                       "enterpriseId": ent_id
                   },
                   "help": "Get Profile ID"
                   }
    return call_method


def create_edge_cluster(vco_dict):
    logging.info("Creating Hub Cluster and added Edges...")
    edgeList = []
    i = 0
    try:
        while i < vco_dict["edge_count"]:
            edgeList.extend([vco_dict["edges"][i]["edgeId"]])
            i += 1
        logging.info("Creating Hub Cluster and added Edges... Done")
    except Exception as e:
        logging.error("Could not extend edgeList for Hub Cluster: " + str(e))

    d = {"method": "enterprise/insertEnterpriseEdgeCluster",
         "params": {
             "enterpriseId": vco_dict["enterprise_id"],
             "name": vco_dict["projectName"] + "-" + str(uuid.uuid4())[:4],
             "type": "edgeHubCluster",
             "data": {
                 "autoRebalance": True
             },
             "description": vco_dict["projectName"],
             "edges": edgeList
         },
         "help": "Create Hub Cluster"
         }
    return d


def delete_hub_cluster(vco_dict):
    logging.info("Deleting Hub Cluster...")

    d = {"method": "enterprise/deleteEnterpriseService",
         "params": {
             "enterpriseId": vco_dict["enterprise_id"],
             "id": vco_dict["HubClusterID"]
         },
         "help": "Delete Hub Cluster"
         }
    return d


def create_enterprise_edge(profile_id=0):
    edge_name = "SD-WAN-Edge-" + str(uuid.uuid4())[:4]
    d = {"method": "edge/edgeProvision",
         "params": {
             "name": edge_name,
             "configurationId": profile_id,
             "modelNumber": "virtual",
             "site": {
                 "lat": "37.774",
                 "lon": "-122.419"
             },
             "edgeLicenseId": 1
         },
         "ttl_supported": True,
         "help": "Provision edges and returns the activation key"
         }
    return d


def get_edge_info(edge_id=0):
    d = {"method": "edge/getEdge",
         "params": {
             "id": edge_id,
             "with": [
                 "recentLinks"
             ]
         },
         "help": "Get edge info"
         }
    return d


def delete_edge(ent_id=0, edge_id=0):
    d = {"method": "edge/deleteEdge",
         "params": {
             "enterpriseId": ent_id,
             "id": edge_id
         },
         "help": "Delete edge"
         }
    return d


def write_config_to_s3(filename, bucket_name, json_data):
    for k, v in json_data.items():
        r = k, v
        logging.info(r)

    s3 = boto3.resource("s3")
    s3object = s3.Object(bucket_name, filename)
    s3object.put(Body=(bytes(json.dumps(json_data).encode("UTF-8"))))


def get_subnet_cidr(cidr="", bump=0):
    x = cidr.split(".")
    y = x[3].split("/")
    z = int(x[2]) + bump
    ip_address = str(x[0] + "." + x[1] + "." + str(z) + "." + y[0] + "/24")
    return ip_address


def get_ip_address(cidr="", bump=0):
    x = cidr.split(".")
    y = x[3].split("/")
    z = int(y[0]) + bump
    ip_address = str(x[0] + "." + x[1] + "." + x[2] + "." + str(z))
    return ip_address


def get_edge_configuration_stack(edge_id=0):
    d = {"method": "edge/getEdgeConfigurationStack",
         "params": {
             "edgeId": edge_id
         },
         "ttl_supported": False,
         "help": "Get Edge Device Settings"
         }
    return d


def get_edge_configuration_info(edge_id=0):
    d = {"method": "edge/getEdge",
         "params": {
             "id": edge_id,
             "with": ["links"]
         },
         "ttl_supported": False,
         "help": "Gets the specified Edge with optional link, site, configuration, certificate, or enterprise details."
         }
    return d


def update_edge_configuration_module():
    d = {"method": "configuration/updateConfigurationModule",
         "params": {},
         "ttl_supported": False,
         "help": "Update Edge Device Settings"
         }
    return d


def enable_cloud_vpn(res):
    ProfileSettingsData = {}
    moduleId = ""
    try:
        ProfileSettings = [m for m in res["modules"] if m["name"] == "deviceSettings"][0]
        ProfileSettingsData = ProfileSettings["data"]
        moduleId = ProfileSettings["id"]
        ProfileSettingsData["segments"][0]["vpn"]["enabled"] = True
        ProfileSettingsData["segments"][1]["vpn"]["enabled"] = True
        ProfileSettingsData["lan"]["networks"][0]["bindEdgeAddress"] = True
        ProfileSettingsData["lan"]["networks"][0]["cidrIp"] = "169.254.0.1"
        ProfileSettingsData["lan"]["networks"][0]["advertise"] = False
        ProfileSettingsData["lan"]["networks"][0]["cidrPrefix"] = "24"
        ProfileSettingsData["lan"]["networks"][0]["netmask"] = "255.255.255.0"
        ProfileSettingsData["lan"]["networks"][0]["dhcp"]["enabled"] = False
        ProfileSettingsData["lan"]["networks"][0]["interfaces"] = ["GE1"]
    except Exception as e:
        logging.error("Could not Enable Cloud VPN: " + str(e))

    params = {
        "id": moduleId,
        "_update": {"data": ProfileSettingsData},
    }
    return params


def create_enterprise_service(t_details):
    d = {"method": "enterprise/insertEnterpriseService",
         "params": {
             "enterpriseId": t_details.get("enterprise_id"),
             "name": t_details.get("name"),
             "type": t_details.get("service_type"),
             "edgeId": t_details.get("edgeId"),
             "data": {
                 "typeAlias": "genericIKEv2Router",
                 "tunnelMode": "ACTIVE_ACTIVE",
                 "automateDeployment": False,
                 "bgp": {
                     "__comment__": "futual project",
                     "enabled": False
                 },
                 "cssp": False,
                 "enabled": True,
                 "keepBackupServerConnected": True,
                 "providerCategory": "DATACENTER",
                 "routingPolicy": "POLICY",
                 "tunnelingProtocol": "IPSEC",
                 "primaryServer": {
                     "IKEPROP": {
                         "DHGroup": 14,
                         "PFS": 0,
                         "authenticationAlgorithm": "SHA_256",
                         "authenticationMethod": "PSK",
                         "dpdTimeoutSeconds": 20,
                         "dpdType": "Disable",
                         "encryptionAlgorithm": "Any",
                         "ikev1MainMode": True,
                         "lifeTimeSeconds": 86400,
                         "peerIkeId": {
                             "__comment__": "futual project",
                             "ikeId": "",
                             "ikeIdType": "FQDN"
                         },
                         "protocolVersion": 2
                     },
                     "IPSECPROP": {
                         "authenticationAlgorithm": "SHA_256",
                         "encryptionAlgorithm": "AES_256_CBC",
                         "ipsecTunnelType": "ROUTE",
                         "lifeTimeSeconds": 28800,
                         "protocol": "ESP_AUTH"
                     },
                     "localLinkIp": "",
                     "nvsPublicIp": t_details.get("PrimaryDestIP"),
                     "peerLinkIp": ""
                 },
                 "backupServer": {
                     "enabled": True,
                     "sameTunnelSettingsAsPrimary": True,
                     "IKEPROP": {
                         "DHGroup": 14,
                         "PFS": 0,
                         "authenticationAlgorithm": "SHA_256",
                         "authenticationMethod": "PSK",
                         "dpdTimeoutSeconds": 20,
                         "dpdType": "Disable",
                         "encryptionAlgorithm": "Any",
                         "ikev1MainMode": True,
                         "lifeTimeSeconds": 86400,
                         "peerIkeId": {
                             "__comment__": "futual project",
                             "ikeId": "",
                             "ikeIdType": "FQDN"
                         },
                         "protocolVersion": 2
                     },
                     "IPSECPROP": {
                         "authenticationAlgorithm": "SHA_256",
                         "encryptionAlgorithm": "AES_256_CBC",
                         "ipsecTunnelType": "ROUTE",
                         "lifeTimeSeconds": 28800,
                         "protocol": "ESP_AUTH"
                     },
                     "localLinkIp": "",
                     "nvsPublicIp": t_details.get("SecondaryDestIP"),
                     "peerLinkIp": ""
                 },
                 "sharedIkeAuth": False,
                 "sourceSubnets": {
                     "__comment__": "only needed for Policy based IPSEC",
                     "subnets": []
                 },
                 "peerSubnets": {
                     "alwaysReachable": False,
                     "subnets": [],
                     "version": "1635972021"
                 },
                 "provider": "genericIKEv2Router",
                 "type": "genericIKEv2Router",
                 "version": "1635972021"
             },
         },
         "ttl_supported": False,
         "help": "Creates a new enterprise service for the specified enterprise."
         }
    return d


def get_enterprise_service(vco_dict, service_type=""):
    d = {"method": "enterprise/getEnterpriseServices",
         "params": {
             "enterpriseId": vco_dict.get("enterprise_id"),
             "type": service_type
         },
         "ttl_supported": False,
         "help": "Gets all network service JSON objects defined for the specified enterprise."
         }
    return d


def create_enterprise_segment(vco_dict):
    d = {"method": "enterprise/insertEnterpriseNetworkSegment",
         "params": {
             "enterpriseId": vco_dict["enterprise_id"],
             "name": vco_dict["SegmentList"][1],
             "description": "Segment for Dev Engineers Only",
             "type": "REGULAR",
             "data": {
                 "delegateToEnterprise": True,
                 "delegateToEnterpriseProxy": True
             }
         },
         "ttl_supported": False,
         "help": "Creates a new network segment for the specified enterprise."
         }
    return d


def get_profile_configuration(ent_id=0, profile_id=0):
    d = {"method": "configuration/getConfiguration",
         "params": {
             "id": profile_id,
             "enterpriseId": ent_id,
             "with": ["modules", "edgeCount", "enterprises", "enterpriseCount", "counts"]
         },
         "ttl_supported": False,
         "help": "Get Edge Device Settings"
         }
    return d


def update_profile_configuration():
    d = {"method": "configuration/updateConfigurationModule",
         "params": {},
         "ttl_supported": False,
         "help": "Update Profile Configuration"
         }
    return d


def update_profile_device_settings(res):
    # Update Profile Device Settings for segment
    edgeSpecificProfile = res[1]
    edgeSpecificProfileDeviceSettings = \
        [m for m in edgeSpecificProfile["modules"] if m["name"] == "deviceSettings"][0]
    edgeSpecificProfileDeviceSettingsData = edgeSpecificProfileDeviceSettings["data"]
    moduleId = edgeSpecificProfileDeviceSettings["id"]
    edgeSpecificProfileDeviceSettingsData["lan"]["networks"][0]["segmentId"] = 1

    params = {
        "id": moduleId,
        "returnData": "true",
        "_update": {"data": edgeSpecificProfileDeviceSettingsData},
        "name": "deviceSettings"}
    return params


def update_edge_device_settings_for_edge_direct(res, vco_dict, edge=0):
    edgeDeviceSettings = res[0]
    edgeSpecificDeviceSettings = [m for m in edgeDeviceSettings["modules"] if m["name"] == "deviceSettings"][0]
    profileDeviceSettings = [m for m in res[1]["modules"] if m["name"] == "deviceSettings"][0]
    moduleId = edgeSpecificDeviceSettings["id"]
    edgeSpecificDeviceSettingsData = edgeSpecificDeviceSettings["data"]

    addEdgeDirect = [
        {
            "segment": {
                "segmentId": 0,
                "name": "Global Segment",
                "type": "REGULAR",
            },
            "routes": {
                "static": [],
                "icmpProbes": [],
                "icmpResponders": [],
                "staticV6": [],
                "nsd": []
            },
            "bgp": {
                "enabled": True,
                "routerId": 0,
                "ASN": "65534",
                "networks": [],
                "neighbors": [],
                "overlayPrefix": True,
                "disableASPathCarryOver": False,
                "uplinkCommunity": 0,
                "connectedRoutes": True,
                "propagateUplink": False,
                "ospf": {
                    "enabled": False,
                    "metric": 20
                },
                "defaultRoute": {
                    "enabled": False,
                    "advertise": "CONDITIONAL"
                },
                "v6Detail": {
                    "networks": [],
                    "connectedRoutes": True,
                    "defaultRoute": {
                        "enabled": False,
                        "advertise": "CONDITIONAL"
                    },
                    "neighbors": []
                },
                "asn": 0,
                "isEdge": True,
                "filters": [],
                "override": True
            },
            "edgeDirect": {
                "enabled": True,
                "override": True,
                "provider": {
                    "ref": "deviceSettings:edgeDirectNvs:provider"
                },
                "providers": [
                    {
                        "logicalId": vco_dict["edges"][edge]["Vpns"][0]["nvsViaEdgeServiceLogicalId"],
                        "config": {
                            "useAllPublicWanLinks": False,
                            "enabled": True
                        },
                        "sites": [
                            {"data": {
                                "enabled": True,
                                "linkInternalLogicalId": vco_dict["edges"][edge]["EdgeLinkID"],
                                "primaryTunnel": {
                                    "__comment__": "tunnel for primary NVS",
                                    "ikeAuth": {
                                        "ikeId": vco_dict["edges"][edge]["publicIp"],
                                        "ikeIdType": "IPv4",
                                        "psk": vco_dict["edges"][edge]["Vpns"][0]["PrimaryPreSharedKey"],
                                        "pskType": "alpha"
                                    },
                                    "nvsPublicIp": vco_dict["edges"][edge]["Vpns"][0]["PrimaryOutsideIpAddress"],
                                    "localLinkIp": "",
                                    "peerLinkIp": "",
                                    "keepalive": {
                                        "destinationIp": "",
                                        "intervalSeconds": 5,
                                        "payloadSize": 0,
                                        "sourceIp": ""
                                    },
                                    "bgpNeighbor": {
                                        "neighborIp": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][0]["PrimaryTunnelInsideCidr"], 1),
                                        "neighborAS": "64512",
                                        "inboundFilter": {
                                            "ids": []
                                        },
                                        "outboundFilter": {
                                            "ids": []
                                        },
                                        "sourceInterface": "",
                                        "localIP": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][0]["PrimaryTunnelInsideCidr"], 2),
                                        "maxHop": "1"
                                    }
                                },
                                "backupTunnel": {
                                    "__comment__": "tunnel for backup1 NVS",
                                    "ikeAuth": {
                                        "ikeId": vco_dict["edges"][edge]["publicIp"],
                                        "ikeIdType": "IPv4",
                                        "psk": vco_dict["edges"][edge]["Vpns"][0]["SecondaryPreSharedKey"],
                                        "pskType": "alpha"
                                    },
                                    "nvsPublicIp": vco_dict["edges"][edge]["Vpns"][0]["SecondaryOutsideIpAddress"],
                                    "localLinkIp": "",
                                    "peerLinkIp": "",
                                    "keepalive": {
                                        "destinationIp": "",
                                        "intervalSeconds": 5,
                                        "payloadSize": 0,
                                        "sourceIp": ""
                                    },
                                    "bgpNeighbor": {
                                        "neighborIp": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][0]["SecondaryTunnelInsideCidr"], 1),
                                        "neighborAS": "64512",
                                        "inboundFilter": {
                                            "ids": []
                                        },
                                        "outboundFilter": {
                                            "ids": []
                                        },
                                        "maxHop": "1",
                                        "sourceInterface": "",
                                        "localIP": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][0]["SecondaryTunnelInsideCidr"], 2),
                                    }
                                }
                            }
                            }
                        ]
                    }
                ]
            }
        },
        {
            "segment": {
                "segmentId": 1,
                "name": vco_dict["SegmentList"][1],
                "type": "REGULAR",
            },
            "routes": {
                "static": [],
                "icmpProbes": [],
                "icmpResponders": [],
                "staticV6": []
            },
            "bgp": {
                "enabled": True,
                "routerId": 0,
                "ASN": "65534",
                "networks": [],
                "neighbors": [],
                "overlayPrefix": True,
                "disableASPathCarryOver": False,
                "uplinkCommunity": 0,
                "connectedRoutes": True,
                "propagateUplink": False,
                "ospf": {
                    "enabled": False,
                    "metric": 20
                },
                "defaultRoute": {
                    "enabled": False,
                    "advertise": "CONDITIONAL"
                },
                "v6Detail": {
                    "networks": [],
                    "connectedRoutes": True,
                    "defaultRoute": {
                        "enabled": False,
                        "advertise": "CONDITIONAL"
                    },
                    "neighbors": []
                },
                "asn": 0,
                "isEdge": True,
                "filters": [],
                "override": True
            },
            "edgeDirect": {
                "enabled": True,
                "override": True,
                "provider": {
                    "ref": "deviceSettings:edgeDirectNvs:provider"
                },
                "providers": [
                    {
                        "logicalId": vco_dict["edges"][edge]["Vpns"][1]["nvsViaEdgeServiceLogicalId"],
                        "config": {
                            "useAllPublicWanLinks": False,
                            "enabled": True
                        },
                        "sites": [
                            {"data": {
                                "enabled": True,
                                "linkInternalLogicalId": vco_dict["edges"][edge]["EdgeLinkID"],
                                "primaryTunnel": {
                                    "__comment__": "tunnel for primary NVS",
                                    "ikeAuth": {
                                        "ikeId": vco_dict["edges"][edge]["publicIp"],
                                        "ikeIdType": "IPv4",
                                        "psk": vco_dict["edges"][edge]["Vpns"][1]["PrimaryPreSharedKey"],
                                        "pskType": "alpha"
                                    },
                                    "nvsPublicIp": vco_dict["edges"][edge]["Vpns"][1]["PrimaryOutsideIpAddress"],
                                    "localLinkIp": "",
                                    "peerLinkIp": "",
                                    "keepalive": {
                                        "destinationIp": "",
                                        "intervalSeconds": 5,
                                        "payloadSize": 0,
                                        "sourceIp": ""
                                    },
                                    "bgpNeighbor": {
                                        "neighborIp": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][1]["PrimaryTunnelInsideCidr"], 1),
                                        "neighborAS": "64512",
                                        "inboundFilter": {
                                            "ids": []
                                        },
                                        "outboundFilter": {
                                            "ids": []
                                        },
                                        "sourceInterface": "",
                                        "localIP": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][1]["PrimaryTunnelInsideCidr"], 2),
                                        "maxHop": "1"
                                    }
                                },
                                "backupTunnel": {
                                    "__comment__": "tunnel for backup1 NVS",
                                    "ikeAuth": {
                                        "ikeId": vco_dict["edges"][edge]["publicIp"],
                                        "ikeIdType": "IPv4",
                                        "psk": vco_dict["edges"][edge]["Vpns"][1]["SecondaryPreSharedKey"],
                                        "pskType": "alpha"
                                    },
                                    "nvsPublicIp": vco_dict["edges"][edge]["Vpns"][1]["SecondaryOutsideIpAddress"],
                                    "localLinkIp": "",
                                    "peerLinkIp": "",
                                    "keepalive": {
                                        "destinationIp": "",
                                        "intervalSeconds": 5,
                                        "payloadSize": 0,
                                        "sourceIp": ""
                                    },
                                    "bgpNeighbor": {
                                        "neighborIp": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][1]["SecondaryTunnelInsideCidr"], 1),
                                        "neighborAS": "64512",
                                        "inboundFilter": {
                                            "ids": []
                                        },
                                        "outboundFilter": {
                                            "ids": []
                                        },
                                        "sourceInterface": "",
                                        "localIP": get_ip_address(
                                            vco_dict["edges"][edge]["Vpns"][1]["SecondaryTunnelInsideCidr"], 2),
                                        "maxHop": "1"
                                    }
                                }
                            }
                            }
                        ]
                    }
                ]
            }
        }
    ]

    edgeSpecificDeviceSettings["data"]["segments"] = addEdgeDirect

    if not edgeSpecificDeviceSettings["refs"].get("deviceSettings:edgeDirectNvs:provider"):
        edgeSpecificDeviceSettings["refs"]["deviceSettings:edgeDirectNvs:provider"] = []
    elif isinstance(edgeSpecificDeviceSettings["refs"]["deviceSettings:edgeDirectNvs:provider"], dict):
        edgeSpecificDeviceSettings["refs"]["deviceSettings:edgeDirectNvs:provider"] = [
            edgeSpecificDeviceSettings["refs"]["deviceSettings:edgeDirectNvs:provider"]]
    edgeSpecificDeviceSettings["refs"]["deviceSettings:edgeDirectNvs:provider"] += [
        {
            "ref": "deviceSettings:edgeDirectNvs:provider",
            "configurationId": edgeSpecificDeviceSettings["configurationId"],
            "moduleId": edgeSpecificDeviceSettings["id"],
            "segmentObjectId": profileDeviceSettings["refs"]["deviceSettings:segment"][0]["enterpriseObjectId"],
            "segmentLogicalId": profileDeviceSettings["refs"]["deviceSettings:segment"][0]["logicalId"],
            "enterpriseObjectId": vco_dict["edges"][edge]["Vpns"][0]["nvsViaEdgeServiceId"],
            "logicalId": vco_dict["edges"][edge]["Vpns"][0]["nvsViaEdgeServiceLogicalId"]
        },
        {
            "ref": "deviceSettings:edgeDirectNvs:provider",
            "configurationId": edgeSpecificDeviceSettings["configurationId"],
            "moduleId": edgeSpecificDeviceSettings["id"],
            "segmentObjectId": profileDeviceSettings["refs"]["deviceSettings:segment"][1]["enterpriseObjectId"],
            "segmentLogicalId": profileDeviceSettings["refs"]["deviceSettings:segment"][1]["logicalId"],
            "enterpriseObjectId": vco_dict["edges"][edge]["Vpns"][1]["nvsViaEdgeServiceId"],
            "logicalId": vco_dict["edges"][edge]["Vpns"][1]["nvsViaEdgeServiceLogicalId"]
        }
    ]

    params = {
        "enterpriseId": config_d.get("enterprise_id"),
        "configurationModuleId": moduleId,
        "_update": {
            "data": edgeSpecificDeviceSettingsData,
            "refs": edgeSpecificDeviceSettings["refs"]
        }
    }

    return params


def get_segment_policy(url):
    logging.info("Getting policy document from " + url)

    http = urllib3.PoolManager()
    response = http.request('GET', url)
    data = response.data
    config_d["policy_d"] = json.loads(data)

    return


def aws_get_vpcId(vpc_name):
    logging.info("Getting VPC info for " + vpc_name)
    client = boto3.client("ec2")
    response = {}

    vpcId = ""

    try:
        response = client.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [vpc_name]}])
        logging.info("Getting VPC info... Done")
    except ClientError as e:
        logging.error(e)

    if len(response["Vpcs"]) > 0:
        vpcId = response["Vpcs"][0].get("VpcId")
    else:
        raise Exception("Unknown: '" + response["Vpcs"] + "'.")

    return vpcId


def aws_create_stack_greenfield(vco_dict):
    logging.info("Creating CloudFormation VMware/CloudWAN Greenfield Stack...")
    cf = boto3.client("cloudformation")

    try:
        cf.create_stack(StackName=vco_dict["edges"][0]["edgeName"],
                        TemplateURL=vco_dict["cf_greenfield_url"],
                        Parameters=[
                            {"ParameterKey": "ResourcePrefix",
                             "ParameterValue": vco_dict["TransitVpcName"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "EdgeDeploymentCount",
                             "ParameterValue": str(vco_dict["edge_count"]),
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "ActivationKey",
                             "ParameterValue": vco_dict["edges"][0]["activationKey"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "IgnoreCertificateValidation",
                             "ParameterValue": vco_dict["ignore_cert_error"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "VCO", "ParameterValue": vco_dict["vco"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "VpcCidrBlockValue",
                             "ParameterValue": vco_dict["vpc_cidr"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "AvailabilityZone1",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][0]["availabilityZone"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "AvailabilityZone2",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][1]["availabilityZone"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "AvailabilityZone3",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][2]["availabilityZone"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az1PublicSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][0]["publicSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az1PrivateSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][0]["privateSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az2PublicSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][1]["publicSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az2PrivateSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][1]["privateSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az3PublicSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][2]["publicSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "Az3PrivateSubnetValue",
                             "ParameterValue": vco_dict["PublicPrivateSubnetList"][2]["privateSubnet"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "VeloCloudKeyPairName",
                             "ParameterValue": vco_dict["key_pair_name"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"}
                        ])

        stackComplete = False
        i = 0
        while i < 30:  # Set for five minute timeout
            logging.info("Waiting for stack completion...")
            api_response = cf.describe_stacks(StackName=vco_dict["edges"][0]["edgeName"])
            if api_response["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE":
                logging.info("Creating CloudFormation VMware/CloudWAN Greenfield Stack... Completed")
                stackComplete = True
                break
            else:
                time.sleep(10)
            i += 1

        if not stackComplete:
            raise ValueError("Stack creation timed-out!")

    except ClientError as e:
        logging.info("Greenfield stack deployment failed" + str(e))

    return vco_dict["edges"][0]["edgeName"]


def aws_create_stack_brownfield(vco_dict, itr=1):
    logging.info("Creating CloudFormation VMware/CloudWAN Brownfield Stack...")
    cf = boto3.client("cloudformation")

    try:
        cf.create_stack(StackName=vco_dict["edges"][itr]["edgeName"],
                        TemplateURL=vco_dict["cf_brownfield_url"],
                        Parameters=[
                            {"ParameterKey": "ResourcePrefix",
                             "ParameterValue": vco_dict["edges"][itr]["edgeName"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "ActivationKey",
                             "ParameterValue": vco_dict["edges"][itr]["activationKey"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "IgnoreCertificateValidation",
                             "ParameterValue": vco_dict["ignore_cert_error"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "VCO", "ParameterValue": vco_dict.get("vco"),
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "ExistingVpc", "ParameterValue": vco_dict["VpcID"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "ExistingPublicSubnet",
                             "ParameterValue": vco_dict["edges"][itr]["PublicSubnetID"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "ExistingPrivateSubnet",
                             "ParameterValue": vco_dict["edges"][itr]["PrivateSubnetID"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"},
                            {"ParameterKey": "VeloCloudKeyPairName",
                             "ParameterValue": vco_dict["key_pair_name"],
                             "UsePreviousValue": False,
                             "ResolvedValue": "string"}
                        ])
        logging.info("Creating CloudFormation VMware/CloudWAN Brownfield Stack... Completed")
    except ClientError as e:
        logging.error(e)

    return vco_dict["edges"][itr]["edgeName"]


def aws_delete_stack(stack_name):
    logging.info("Deleting CloudFormation Stack: " + stack_name)
    cf = boto3.client("cloudformation")

    try:
        cf.delete_stack(StackName=stack_name)
        stackDeleted = False
        i = 0
        while i < 30:  # Set for five minute timeout
            logging.info("Waiting for stack deletion...")
            api_response = cf.describe_stacks(StackName=stack_name)
            if api_response["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
                logging.info("Deletion of CloudFormation Stack... Completed")
                stackDeleted = True
                break
            else:
                time.sleep(10)
            i += 1

        if not stackDeleted:
            raise ValueError("Stack deletion timed-out!")

    except ClientError:
        return

    return


def aws_get_subnetId(subnet_name):
    logging.info("Getting Subnet Id for " + subnet_name)
    client = boto3.client("ec2")
    response = {}

    try:
        response = client.describe_subnets(Filters=[{"Name": "tag:Name", "Values": [subnet_name]}])
        logging.info("Getting Subnet info... Done")
    except ClientError as e:
        logging.error(e)

    subnetId = response["Subnets"][0]["SubnetId"]

    return subnetId


def aws_get_az(vco_dict):
    logging.info("Getting availability zones...")
    client = boto3.client("ec2")

    try:
        response = client.describe_availability_zones()
        azListSize = len(response["AvailabilityZones"])
        edgeListSize = len(vco_dict["edges"])

        if edgeListSize <= azListSize:
            i = 0
            while i < edgeListSize:
                vco_dict["edges"][i]["availabilityZone"] = response["AvailabilityZones"][i]["ZoneName"]
                vco_dict["PublicPrivateSubnetList"][i]["availabilityZone"] = response["AvailabilityZones"][i][
                    "ZoneName"]
                i += 1
        else:
            raise ValueError("ERROR: AZ to Edge Mapping not equal")

        logging.info("Getting availability zones... Done")
    except ClientError as e:
        logging.error(e)

    return


def aws_create_cgw(edge_name="", public_ip=""):
    logging.info("Creating CGW for Edge " + edge_name + " with Public IP " + public_ip)
    client = boto3.client("ec2")
    response = {}

    try:
        response = client.create_customer_gateway(
            BgpAsn=65534, PublicIp=public_ip, Type="ipsec.1",
            DeviceName=edge_name,
            TagSpecifications=[{
                "ResourceType": "customer-gateway",
                "Tags": [{"Key": "Name", "Value": "AwsCloudWanCgw"}]}]  # NOTE: Can"t update Tag with variable
        )
        logging.info("Creating CGW... Done")
    except ClientError as e:
        logging.error(e)

    return response["CustomerGateway"]["CustomerGatewayId"]


def aws_create_vpn_connection(vcoDict, index=0):
    logging.info("Creating a dangling VPN Connection...")
    client = boto3.client("ec2")
    vpn_list = []
    response = {}
    time.sleep(5)

    # Create First Site-To-Site for SD-WAN Segment (Global)
    try:
        response = client.create_vpn_connection(
            CustomerGatewayId=vcoDict["edges"][index]["cgwId"],
            Type="ipsec.1",
            Options={"StaticRoutesOnly": False},
            TagSpecifications=[{
                "ResourceType": "vpn-connection",
                "Tags": [{"Key": "Name", "Value": "AwsCloudWanVPN"}]}]
        )
        logging.info("Creating VPN Connection (Global Segment)... Done")
    except ClientError as e:
        logging.error("Creating VPN Connection (Global Segment)... FAILED" + str(e))
        logging.error(response)

    vpn_details = {
        "VpnConnectionId": response["VpnConnection"]["VpnConnectionId"],
        "PrimaryOutsideIpAddress": response["VpnConnection"]["Options"]["TunnelOptions"][0]["OutsideIpAddress"],
        "PrimaryTunnelInsideCidr": response["VpnConnection"]["Options"]["TunnelOptions"][0]["TunnelInsideCidr"],
        "PrimaryPreSharedKey": response["VpnConnection"]["Options"]["TunnelOptions"][0]["PreSharedKey"],
        "SecondaryOutsideIpAddress": response["VpnConnection"]["Options"]["TunnelOptions"][1]["OutsideIpAddress"],
        "SecondaryTunnelInsideCidr": response["VpnConnection"]["Options"]["TunnelOptions"][1]["TunnelInsideCidr"],
        "SecondaryPreSharedKey": response["VpnConnection"]["Options"]["TunnelOptions"][1]["PreSharedKey"]
    }
    vpn_list.append(vpn_details)

    # Create Second Site-To-Site for SD-WAN Second Segment
    try:
        response = client.create_vpn_connection(
            CustomerGatewayId=vcoDict["edges"][index]["cgwId"],
            Type="ipsec.1",
            Options={"StaticRoutesOnly": False},
            TagSpecifications=[{
                "ResourceType": "vpn-connection",
                "Tags": [{"Key": "Name", "Value": "AwsCloudWanVPN"}]}]
        )
        logging.info("Creating VPN Connection (Second Segment)... Done")
    except ClientError as e:
        logging.error("Creating VPN Connection (Second Segment)... FAILED" + str(e))
        logging.error(response)

    vpn_details = {
        "VpnConnectionId": response["VpnConnection"]["VpnConnectionId"],
        "PrimaryOutsideIpAddress": response["VpnConnection"]["Options"]["TunnelOptions"][0]["OutsideIpAddress"],
        "PrimaryTunnelInsideCidr": response["VpnConnection"]["Options"]["TunnelOptions"][0]["TunnelInsideCidr"],
        "PrimaryPreSharedKey": response["VpnConnection"]["Options"]["TunnelOptions"][0]["PreSharedKey"],
        "SecondaryOutsideIpAddress": response["VpnConnection"]["Options"]["TunnelOptions"][1]["OutsideIpAddress"],
        "SecondaryTunnelInsideCidr": response["VpnConnection"]["Options"]["TunnelOptions"][1]["TunnelInsideCidr"],
        "SecondaryPreSharedKey": response["VpnConnection"]["Options"]["TunnelOptions"][1]["PreSharedKey"]
    }
    vpn_list.append(vpn_details)
    vcoDict["edges"][index]["Vpns"] = vpn_list

    return


def aws_create_global_network(vco_dict):
    logging.info("Creating AWS Global Network...")
    client = boto3.client("networkmanager")

    response = client.create_global_network(
        Description="VMware-SDWAN-CloudWAN-Quickstart",
        Tags=[
            {
                "Key": "Name",
                "Value": "VMware-SDWAN-Global-Network"
            },
        ]
    )
    vco_dict["GlobalNetworkId"] = response["GlobalNetwork"]["GlobalNetworkId"]
    logging.info(str("Global Network ID: " + vco_dict["GlobalNetworkId"]))

    # Checking GLOBAL-NETWORK State
    globalNetworkComplete = False
    i = 0
    while i < 30:  # Set for five minute timeout
        logging.info("Waiting for Global-network to become available...")
        api_response = client.describe_global_networks(GlobalNetworkIds=[vco_dict["GlobalNetworkId"]])
        if api_response["GlobalNetworks"][0]["State"] == "AVAILABLE":
            logging.info("Global-network now AVAILABLE")
            globalNetworkComplete = True
            break
        else:
            time.sleep(10)
        i += 1

    if not globalNetworkComplete:
        raise ValueError("Global-network creation timed-out!")

    return


def aws_create_core_network(vco_dict):
    logging.info("Creating AWS Core Network...")
    client = boto3.client("networkmanager")

    response = client.create_core_network(
        GlobalNetworkId=vco_dict["GlobalNetworkId"],
        Description="VMware-SDWAN-CloudWAN-Quickstart",
        Tags=[
            {
                "Key": "Name",
                "Value": "VMware-SDWAN-Core-Network"
            },
        ],
        PolicyDocument=json.dumps(vco_dict["policy_d"])
    )

    vco_dict["CoreNetworkId"] = response["CoreNetwork"]["CoreNetworkId"]
    logging.info(str("Core Network ID: " + vco_dict["CoreNetworkId"]))

    # Checking CORE-NETWORK State
    coreComplete = False
    i = 0
    while i < 30:  # Set for five minute timeout
        logging.info("Waiting for core-network to become available...")
        api_response = client.get_core_network(CoreNetworkId=vco_dict["CoreNetworkId"])
        if api_response["CoreNetwork"]["State"] == "AVAILABLE":
            logging.info("Core-network now AVAILABLE")
            coreComplete = True
            break
        else:
            time.sleep(10)
        i += 1

    if not coreComplete:
        raise ValueError("Core-network creation timed-out!")

    return


def aws_build_vpc_attach_list():
    logging.info("Building VPC/Subnet Attach List...")
    client = boto3.client("ec2")

    i = 0
    while i < len(config_d["SubnetIdList"]):
        response = client.describe_subnets(Filters=[{"Name": "subnet-id", "Values": [config_d["SubnetIdList"][i]]}])

        BuildList = {
            "VpcId": response["Subnets"][0]["VpcId"],
            "VpcARN": str(config_d["regional_arn"] + ":vpc/" + response["Subnets"][0]["VpcId"]),
            "SubnetARN": response["Subnets"][0]["SubnetArn"]
        }

        config_d["VpcAttachList"].append(BuildList)
        i += 1

    logging.info(config_d["VpcAttachList"])

    return


def aws_create_vpc_attachment(vco_dict, i=0):
    logging.info("Creating VPC Attachment...")
    client = boto3.client("networkmanager")

    if i == 0:
        response = client.create_vpc_attachment(
            CoreNetworkId=vco_dict["CoreNetworkId"],
            VpcArn=vco_dict["VpcAttachList"][i]["VpcARN"],
            SubnetArns=[
                vco_dict["VpcAttachList"][i]["SubnetARN"],
            ],
            Options={
                "Ipv6Support": False
            },
            Tags=[
                {
                    "Key": "Name",
                    "Value": "VMware-SDWAN-VPC-Attachment"
                },
                {
                    "Key": "segment",
                    "Value": vco_dict["SegmentList"][0]
                }
            ]
        )
    else:
        response = client.create_vpc_attachment(
            CoreNetworkId=vco_dict["CoreNetworkId"],
            VpcArn=vco_dict["VpcAttachList"][i]["VpcARN"],
            SubnetArns=[
                vco_dict["VpcAttachList"][i]["SubnetARN"],
            ],
            Options={
                "Ipv6Support": False
            },
            Tags=[
                {
                    "Key": "Name",
                    "Value": "VMware-SDWAN-VPC-Attachment"
                },
                {
                    "Key": "segment",
                    "Value": vco_dict["SegmentList"][1]
                }
            ]
        )

    return response


def aws_create_site_to_site_vpn_attachment(vco_dict, i=0):
    logging.info("Creating AWS Site-To-Site VPN Attachment...")
    client = boto3.client("networkmanager")

    vpnConnArn = str(vco_dict["regional_arn"] + ":vpn-connection/")

    connectionARN = str(vpnConnArn + vco_dict["edges"][i]["Vpns"][0]["VpnConnectionId"])
    client.create_site_to_site_vpn_attachment(
        CoreNetworkId=vco_dict["CoreNetworkId"],
        VpnConnectionArn=connectionARN,
        Tags=[
            {
                "Key": "Name",
                "Value": "VMware-SDWAN-Site-To-Site-VPN-Attachment",
            },
            {
                "Key": "segment",
                "Value": vco_dict["SegmentList"][0]
            },
        ]
    )

    connectionARN = str(vpnConnArn + vco_dict["edges"][i]["Vpns"][1]["VpnConnectionId"])
    client.create_site_to_site_vpn_attachment(
        CoreNetworkId=vco_dict["CoreNetworkId"],
        VpnConnectionArn=connectionARN,
        Tags=[
            {
                "Key": "Name",
                "Value": "VMware-SDWAN-Site-To-Site-VPN-Attachment",
            },
            {
                "Key": "segment",
                "Value": vco_dict["SegmentList"][1]
            },
        ]
    )

    return


def aws_delete_vpn_cgw(vco_dict):
    logging.info("Deleting AWS Customer Gateway and Site-To-Site VPN...")
    client = boto3.client("ec2")

    try:
        client.delete_vpn_connection(VpnConnectionId=vco_dict["edges"][0]["Vpns"][0]["VpnConnectionId"])
        client.delete_vpn_connection(VpnConnectionId=vco_dict["edges"][0]["Vpns"][1]["VpnConnectionId"])
        client.delete_vpn_connection(VpnConnectionId=vco_dict["edges"][1]["Vpns"][0]["VpnConnectionId"])
        client.delete_vpn_connection(VpnConnectionId=vco_dict["edges"][1]["Vpns"][1]["VpnConnectionId"])
        client.delete_customer_gateway(CustomerGatewayId=vco_dict["edges"][0]["cgwId"])
        client.delete_customer_gateway(CustomerGatewayId=vco_dict["edges"][1]["cgwId"])
    except ClientError as e:
        logging.error("Cloud not delete VPN connections and/or CGWs: " + str(e))
    return


def lambda_handler(event, context):
    def authenticate_to_vco():
        """Get the VCO credentials from AWS Secrets Manager and then
        authenticate to the VCO"""

        try:
            logger.debug("Configuring the AWS Secrets Manager client...")
            secrets_client = boto3.client("secretsmanager")
        except Exception as e:
            logger.error("Failed to configure client: '" + str(e) + "'.")
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        try:
            arn = os.environ.get("VcoCredentialsArn", "")
            logger.info("Getting VCO credentials: '" + arn + "'.")
            response: dict = secrets_client.get_secret_value(
                SecretId = arn
            )
            logger.info("Got VCO credentials: '" + arn + "'.")

            credentials = json.loads(response.get("SecretString"))
        except Exception as e:
            logger.error("Error getting secret: '" + str(e) + "'.")
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        try:
            logger.info("Authenticating to the VCO...")
            client.authenticate(credentials.get("username", ""), credentials.get("password", ""))
            logger.info("Authenticated to the VCO.")
        except Exception as e:
            logger.error("Login error: '" + str(e) + "'.")

        logger.debug("Overwriting credentials in memory...")
        credentials = {
            "username": str(uuid.uuid4()),
            "password": str(uuid.uuid4()),
        }


    # CloudFormation CREATE request

    if event["RequestType"] == "Create":
        # Set the log level based on a variable configured in the Lambda environment.
        logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))
        logger.debug("Event: %s", event)
        logging.info("CloudFormation RequestType = Request")

        # Get environment variables from quickstart-vmware-sd-wan-aws-cloud-wan-cf-start.json
        config_d["projectName"] = os.environ["projectName"]
        config_d["vco"] = os.environ["VCO"]
        config_d["ignore_cert_error"] = os.environ["ignoreCertError"]
        config_d["profile_name"] = os.environ["profileName"]
        config_d["SegmentList"].append(os.environ["segmentName"])
        config_d["s3_bucket_name"] = os.environ["s3BucketName"]
        config_d["policy_d"] = json.loads(os.environ["policyJson"])
        config_d["cf_greenfield_url"] = os.environ["gfCfUrl"]
        config_d["cf_brownfield_url"] = os.environ["bfCfUrl"]
        config_d["key_pair_name"] = os.environ["keyPairName"]
        config_d["regional_arn"] = os.environ["regionalName"]
        config_d["vpc_cidr"] = os.environ["vpcCIDR"]
        config_d["SubnetIdList"] = [os.environ["segmentOneSubnet"],
                                    os.environ["segmentTwoSubnet"]]
        config_d["PublicPrivateSubnetList"] = [{"availabilityZone": "",
                                                "publicSubnet": get_subnet_cidr(config_d["vpc_cidr"], 0),
                                                "publicSubnetName": str(config_d["TransitVpcName"] + "-AZ1-Public-SN"),
                                                "privateSubnet": get_subnet_cidr(config_d["vpc_cidr"], 1),
                                                "privateSubnetName": str(
                                                    config_d["TransitVpcName"] + "-AZ1-Private-SN")},
                                               {"availabilityZone": "",
                                                "publicSubnet": get_subnet_cidr(config_d["vpc_cidr"], 2),
                                                "publicSubnetName": str(config_d["TransitVpcName"] + "-AZ2-Public-SN"),
                                                "privateSubnet": get_subnet_cidr(config_d["vpc_cidr"], 3),
                                                "privateSubnetName": str(
                                                    config_d["TransitVpcName"] + "-AZ2-Private-SN")},
                                               {"availabilityZone": "",
                                                "publicSubnet": get_subnet_cidr(config_d["vpc_cidr"], 4),
                                                "publicSubnetName": str(config_d["TransitVpcName"] + "-AZ3-Public-SN"),
                                                "privateSubnet": get_subnet_cidr(config_d["vpc_cidr"], 5),
                                                "privateSubnetName": str(
                                                    config_d["TransitVpcName"] + "-AZ3-Private-SN")}]
        logging.info("Edge count set to: " + str(config_d["edge_count"]))

        # Authenticate with VCO
        client = VcoClient(config_d["vco"], verify_ssl=False)
        authenticate_to_vco()

        # Get VCO Enterprise ID
        try:
            call = get_enterprise_id()
            api_results = client.request(call.get("method"), call.get("params"))
            config_d["enterprise_id"] = api_results["id"]
            config_d["enterprise_logicalId"] = api_results["logicalId"]
            logging.info("Enterprise ID set to : " + str(config_d["enterprise_id"]))
        except Exception as e:
            logging.error("Could not get Enterprise ID: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Get VCO Profile ID
        try:
            call = get_profile_id(int(config_d["enterprise_id"]))
            api_results = client.request(call.get("method"), call.get("params"))
            i = 0
            while i < len(api_results):
                if api_results[i]["name"] == config_d["profile_name"]:
                    config_d["profile_id"] = api_results[i]["id"]
                    config_d["profile_logicalId"] = api_results[i]["logicalId"]
                    break
                i += 1

            if config_d["profile_id"] == 0:
                logging.info("Could not get ProfileID based on provide profile name: " + config_d["profile_name"])
                cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])
            else:
                logging.info("Profile ID set to : " + str(config_d["profile_id"]))

        except Exception as e:
            logging.error("Error trying to resolve Profile name: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create Edge(s) for deployment
        try:
            edge_list = []

            for x in range(config_d["edge_count"]):
                # Set Deployment Field Type
                if x == 0:
                    deploymentField = "green"
                elif x > 0:
                    deploymentField = "brown"
                else:
                    deploymentField = "unknown"

                call = create_enterprise_edge(config_d["profile_id"])
                api_results = client.request(call.get("method"), call.get("params"))
                edge_list.append({"edgeId": api_results.get("id"),
                                  "edgeName": call.get("params").get("name"),
                                  "deploymentField": deploymentField,
                                  "activationKey": api_results.get("activationKey"),
                                  "edgeLogicalId": api_results.get("logicalId")})
                config_d["edges"] = edge_list

            for x in range(config_d["edge_count"]):
                logging.info("Created Edge Name: " + config_d["edges"][x]["edgeName"] + " with Key: " +
                             config_d["edges"][x]["activationKey"])

        except Exception as e:
            logging.error("Encountered error while creating Edges in VCO: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Get deployment region and availability zones
        try:
            aws_get_az(config_d)
        except Exception as e:
            logging.error("Could not get availability zones: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        for k, v in config_d.items():
            r = k, v
            logging.info(r)

        # Create Greenfield & Brownfield SD-WAN Stacks
        try:
            i = 0
            while i < len(config_d["edges"]):
                if config_d["edges"][i]["deploymentField"] == "green":
                    config_d["edges"][i]["StackName"] = aws_create_stack_greenfield(config_d)
                    config_d["VpcID"] = aws_get_vpcId(str(config_d["TransitVpcName"] + "-VPC"))
                    config_d["edges"][i]["PublicSubnetID"] = aws_get_subnetId(
                        config_d["PublicPrivateSubnetList"][i]["publicSubnetName"])
                    config_d["edges"][i]["PrivateSubnetID"] = aws_get_subnetId(
                        config_d["PublicPrivateSubnetList"][i]["privateSubnetName"])
                    config_d["edges"][i]["availabilityZone"] = config_d["PublicPrivateSubnetList"][i][
                        "availabilityZone"]
                    logging.info(
                        "Created Cloudformation Greenfield - Stack name: " + str(config_d["edges"][i]["StackName"]))
                elif config_d["edges"][i]["deploymentField"] == "brown":
                    config_d["edges"][i]["PublicSubnetID"] = aws_get_subnetId(
                        config_d["PublicPrivateSubnetList"][i]["publicSubnetName"])
                    config_d["edges"][i]["PrivateSubnetID"] = aws_get_subnetId(
                        config_d["PublicPrivateSubnetList"][i]["privateSubnetName"])
                    config_d["edges"][i]["availabilityZone"] = config_d["PublicPrivateSubnetList"][i][
                        "availabilityZone"]
                    config_d["edges"][i]["StackName"] = aws_create_stack_brownfield(config_d, i)
                    logging.info(
                        "Created Cloudformation Brownfield - Stack name: " + str(config_d["edges"][i]["StackName"]))
                else:
                    logging.error("Deployment field type unknown")
                    cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])
                i += 1
        except Exception as e:
            logging.error("Could not create Cloudformation stack: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Get the PublicIP from the Edge(s)
        try:
            for x in range(config_d["edge_count"]):
                edgeOnline = False
                i = len(config_d["edges"]) - 1
                while i < 30:  # Set for five minute timeout
                    call = get_edge_info(config_d["edges"][x]["edgeId"])
                    api_results = client.request(call.get("method"), call.get("params"))
                    if "recentLinks" in api_results:
                        config_d["edges"][x]["publicIp"] = api_results["recentLinks"][0]["ipAddress"]
                        config_d["edges"][x]["EdgeLinkID"] = api_results["recentLinks"][0]["internalId"]
                        edgeOnline = True
                        logging.info(
                            "Public IP for Edge: " + config_d["edges"][x]["edgeName"] + " is " + config_d["edges"][x][
                                "publicIp"])
                        break
                    else:
                        logging.info("Waiting for WAN link for: " + config_d["edges"][x]["edgeName"] + " to come up")
                        time.sleep(10)
                    i += 1

                if not edgeOnline:
                    raise ValueError("Edge WAN link not up before timeout!")

        except ApiException as e:
            logging.error("Encountered API error with call edges public IP: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create Hub Cluster and add Edges
        try:
            call = create_edge_cluster(config_d)
            res = client.request(call.get("method"), call.get("params"))
            config_d["HubClusterID"] = res["id"]
            logging.info("Created Hub Cluster and added Edges")
        except Exception as e:
            logging.error("Could not create Hub Cluster: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create AWS Customer Gateways and Site-To-Site VPNs
        logging.info("Creating AWS Customer Gateway and Site-To-Site VPN...")
        try:
            for x in range(config_d["edge_count"]):
                config_d["edges"][x]["cgwId"] = aws_create_cgw(config_d["edges"][x]["edgeName"],
                                                               config_d["edges"][x]["publicIp"])
                aws_create_vpn_connection(config_d, x)
        except Exception as e:
            logging.error("Could not create AWS Customer Gateway or Site-To-Site VPN " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create VCO Enterprise Services for Global Segment
        try:
            for x in range(config_d["edge_count"]):
                segment = 0
                name = str(config_d["edges"][x]["edgeName"] + "-Global")
                tunnel_details = {
                    "enterprise_id": config_d.get("enterprise_id"),
                    "name": name,
                    "service_type": "nvsViaEdgeService",
                    "PrimaryDestIP": config_d["edges"][x]["Vpns"][segment]["PrimaryOutsideIpAddress"],
                    "SecondaryDestIP": config_d["edges"][x]["Vpns"][segment]["SecondaryOutsideIpAddress"],
                    "edgeId": config_d["edges"][x]["edgeId"]
                }
                call = create_enterprise_service(tunnel_details)
                client.request(call.get("method"), call.get("params"))
                config_d["edges"][x]["Vpns"][segment]["nvsViaEdgeServiceName"] = name
                logging.info("Created Enterprise Service: " + name)

                # Create Enterprise Services for AWS Segment
                segment += 1
                name = str(config_d["edges"][x]["edgeName"] + "-" + config_d["SegmentList"][1])
                tunnel_details = {
                    "enterprise_id": config_d.get("enterprise_id"),
                    "name": name,
                    "service_type": "nvsViaEdgeService",
                    "PrimaryDestIP": config_d["edges"][x]["Vpns"][segment]["PrimaryOutsideIpAddress"],
                    "SecondaryDestIP": config_d["edges"][x]["Vpns"][segment]["SecondaryOutsideIpAddress"],
                    "edgeId": config_d["edges"][x]["edgeId"]
                }
                call = create_enterprise_service(tunnel_details)
                client.request(call.get("method"), call.get("params"))
                config_d["edges"][x]["Vpns"][segment]["nvsViaEdgeServiceName"] = name
                logging.info("Created Enterprise Service: " + name)
        except Exception as e:
            logging.error("Could not create enterprise service: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Get VCO Enterprise Services
        try:
            logging.info("Getting Enterprise Services for Edges")
            call = get_enterprise_service(config_d, "nvsViaEdgeService")
            res = client.request(call.get("method"), call.get("params"))

            i = 0
            while i < len(res):
                if res[i]["name"] == config_d["edges"][0]["Vpns"][0]["nvsViaEdgeServiceName"]:
                    config_d["edges"][0]["Vpns"][0]["nvsViaEdgeServiceLogicalId"] = res[i]["logicalId"]
                    config_d["edges"][0]["Vpns"][0]["nvsViaEdgeServiceId"] = res[i]["id"]
                    break
                i += 1
            i = 0
            while i < len(res):
                if res[i]["name"] == config_d["edges"][0]["Vpns"][1]["nvsViaEdgeServiceName"]:
                    config_d["edges"][0]["Vpns"][1]["nvsViaEdgeServiceLogicalId"] = res[i]["logicalId"]
                    config_d["edges"][0]["Vpns"][1]["nvsViaEdgeServiceId"] = res[i]["id"]
                    break
                i += 1
            i = 0
            while i < len(res):
                if res[i]["name"] == config_d["edges"][1]["Vpns"][0]["nvsViaEdgeServiceName"]:
                    config_d["edges"][1]["Vpns"][0]["nvsViaEdgeServiceLogicalId"] = res[i]["logicalId"]
                    config_d["edges"][1]["Vpns"][0]["nvsViaEdgeServiceId"] = res[i]["id"]
                    break
                i += 1
            i = 0
            while i < len(res):
                if res[i]["name"] == config_d["edges"][1]["Vpns"][1]["nvsViaEdgeServiceName"]:
                    config_d["edges"][1]["Vpns"][1]["nvsViaEdgeServiceLogicalId"] = res[i]["logicalId"]
                    config_d["edges"][1]["Vpns"][1]["nvsViaEdgeServiceId"] = res[i]["id"]
                    break
                i += 1
        except Exception as e:
            logging.error("Could not get enterprise services: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        target_segment_name = config_d["SegmentList"][1]

        logging.info("Target segment specified - provisioning segment " + target_segment_name)

        customer_segments = client.request("enterprise/getEnterpriseNetworkSegments", {
            "enterpriseId": config_d.get("enterprise_id")
        })
        try:
            target_segment = [segment for segment in customer_segments if segment["name"] == target_segment_name][0]
        except IndexError:
            logging.error("Target segment %s not found, aborting..." % target_segment_name)
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        customer_profiles = client.request("enterprise/getEnterpriseConfigurations", {
            "enterpriseId": config_d.get("enterprise_id"),
            "with": ["modules", "refs"]
        })

        target_profile_name = config_d["profile_name"]
        try:
            target_profile = [profile for profile in customer_profiles if profile["name"] == target_profile_name][0]
        except IndexError:
            logging.error("Target profile %s not found, aborting..." % target_profile_name)
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        device_settings = [m for m in target_profile["modules"] if m["name"] == "deviceSettings"][0]
        device_settings_data = device_settings["data"]
        # Append new segment config by copying global
        device_settings_data["segments"].append(deepcopy(device_settings_data["segments"][0]))
        # Revise segment metadata for new segment
        device_settings_data["segments"][-1]["segment"]["name"] = target_segment["name"]
        device_settings_data["segments"][-1]["segment"]["type"] = target_segment["type"]
        device_settings_data["segments"][-1]["segment"]["segmentId"] = target_segment["data"]["segmentId"]
        device_settings_data["segments"][-1]["segment"]["segmentLogicalId"] = target_segment["logicalId"]

        # Update refs
        device_settings_refs = device_settings["refs"]
        if not isinstance(device_settings_refs["deviceSettings:segment"], list):
            device_settings_refs["deviceSettings:segment"] = [device_settings_refs["deviceSettings:segment"]]
        device_settings_refs["deviceSettings:segment"].append({
            "enterpriseObjectId": target_segment["id"],
            "logicalId": target_segment["logicalId"],
            "configurationId": target_profile["id"],
            "moduleId": device_settings["id"],
            "ref": "deviceSettings:segment",
        })

        try:
            client.request("configuration/updateConfigurationModule", {
                "enterpriseId": config_d.get("enterprise_id"),
                "configurationModuleId": device_settings["id"],
                "_update": {
                    "data": device_settings_data,
                    "refs": device_settings_refs,
                }
            })
        except ApiException as e:
            logging.error("Failed to update profile" + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        logging.info("Successfully added segment %s to profile %s" % (target_segment_name, target_profile["name"]))

        # Enable CloudVPN per Segment
        try:
            call = get_profile_configuration(config_d.get("enterprise_id"), config_d.get("profile_id"))
            res = client.request(call.get("method"), call.get("params"))
            params = enable_cloud_vpn(res)
            call = update_profile_configuration()
            client.request(call.get("method"), params)
            logging.info("Enabled Cloud VPN for Enterprise")
        except Exception as e:
            logging.error("Could not enable Cloud VPN: " + str(e))

        # Update Profile DeviceSettings to move Corp VLAN to secondary segment (VLENG-80168)
        try:
            for x in range(config_d["edge_count"]):
                call = get_edge_configuration_stack(config_d["edges"][x]["edgeId"])
                res = client.request(call.get("method"), call.get("params"))
                params = update_profile_device_settings(res)
                call = update_edge_configuration_module()
                client.request(call.get("method"), params)
        except Exception as e:
            logging.error("Could not update profile device settings: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Add NSD Direct from Edge per Segment w/BGP Peering
        try:
            for x in range(config_d["edge_count"]):
                call = get_edge_configuration_stack(config_d["edges"][x]["edgeId"])
                res = client.request(call.get("method"), call.get("params"))
                params = update_edge_device_settings_for_edge_direct(res, config_d, x)
                call = update_edge_configuration_module()
                client.request(call.get("method"), params)
                logging.info("Enabled Edge Direct for: " + config_d["edges"][x]["edgeName"] + " Segment")
        except Exception as e:
            logging.error("Could not update Edge Direct configuration: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create AWS Global Network
        try:
            aws_create_global_network(config_d)
            logging.info("Created AWS Global Network")
        except Exception as e:
            logging.error("Could not create global network: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create AWS Core Network
        try:
            aws_create_core_network(config_d)
            logging.info("Created AWS Core Network")
        except Exception as e:
            logging.error("Could not create core network: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Build VPC/Subnet Attach List per Segment
        try:
            aws_build_vpc_attach_list()
            logging.info("Created VPC/Subnet Attach List")
        except Exception as e:
            logging.error("Could not create VPC/Subnet Attach List: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create AWS VPC Attachments
        try:
            i = 0
            while i < len(config_d["VpcAttachList"]):
                aws_create_vpc_attachment(config_d, i)
                logging.info("Created AWS VPC Attachments")
                i += 1
        except Exception as e:
            logging.error("Could not create vpc attachments: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Create Site-To-Site VPN Attachments
        try:
            i = 0
            while i < len(config_d["edges"]):
                aws_create_site_to_site_vpn_attachment(config_d, i)
                logging.info("Created AWS Site-to-Site VPN Attachments for: " + config_d["edges"][i]["edgeName"])
                i += 1
        except Exception as e:
            logging.error("Could not create Site-to-Site VPN Attachments: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Write configuration to CloudWatch and S3 Bucket
        try:
            write_config_to_s3(str(config_d["projectName"] + ".json"), config_d["s3_bucket_name"], config_d)
            logging.info(
                "Wrote configuration file: " + str(config_d["projectName"] + ".json ") + "to S3 Bucket: " + config_d[
                    "s3_bucket_name"])
        except Exception as e:
            logging.error("Could not write configuration file: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event["RequestId"])

    # CloudFormation UPDATE request
    if event["RequestType"] == "Update":
        # Set the log level based on a variable configured in the Lambda environment.
        logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))
        logger.debug("Event: %s", event)
        logging.info("CloudFormation RequestType = Update")
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event["RequestId"])

    # CloudFormation DELETE request
    if event["RequestType"] == "Delete":
        # Set the log level based on a variable configured in the Lambda environment.
        logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))
        logger.debug("Event: %s", event)
        logging.info("CloudFormation RequestType = Delete")

        configuration_file = str(os.environ["projectName"] + ".json")
        s3_bucket_name = os.environ["s3BucketName"]

        try:
            # Load configuration JSON file from S3
            s3 = boto3.resource("s3")
            content_object = s3.Object(s3_bucket_name, configuration_file)
            file_content = content_object.get()["Body"].read().decode("utf-8")
            config_in = json.loads(file_content)
        except Exception as e:
            logging.error("Could not get the JSON file from S3: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Dump configuration to CloudWatch
        try:
            for k, v in config_in.items():
                r = k, v
                logging.info(r)

        except Exception as e:
            logging.error("Could not write configuration file to CloudWatch: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        logging.info("Edge count set to: " + str(config_in["edge_count"]))

        # Delete Edge from List in reverse order to ensure Brownfield(s) are deleted first then Greenfield last.
        try:
            i = len(config_in["edges"]) - 1
            while i < len(config_in["edges"]):
                if i > 0:
                    aws_delete_stack(config_in["edges"][i]["edgeName"])  # Delete Brownfield(s) first
                else:
                    break
                i -= 1

            aws_delete_stack(config_in["edges"][0]["edgeName"])  # Delete Greenfield last
            aws_delete_stack(config_in["projectName"])

        except Exception as e:
            logging.error("Could not delete CloudFormation Stack: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        # Cleanup VCO
        client = VcoClient(config_in["vco"], verify_ssl=False)
        authenticate_to_vco()

        # Ensure Edges are OFFLINE before deleting
        try:
            for x in range(config_in["edge_count"]):
                edgeDeleted = False
                i = len(config_in["edges"]) - 1
                while i < 30:  # Set for five minute timeout
                    call = get_edge_info(config_in["edges"][x]["edgeId"])
                    api_results = client.request(call.get("method"), call.get("params"))
                    if api_results["edgeState"] == "OFFLINE":
                        call = delete_edge(config_in["enterprise_id"], config_in["edges"][x]["edgeId"])
                        client.request(call.get("method"), call.get("params"))
                        edgeDeleted = True
                        logging.info("Deleted VCO Edge: " + config_in["edges"][x]["edgeName"])
                        break
                    else:
                        time.sleep(10)
                    i += 1

                if not edgeDeleted:
                    raise ValueError("Edge deletion timed-out!")

        except ApiException as e:
            logging.error("Encountered API error with call to delete edge: " + str(e))
            cfnresponse.send(event, context, cfnresponse.FAILED, {}, event["RequestId"])

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, event["RequestId"])
