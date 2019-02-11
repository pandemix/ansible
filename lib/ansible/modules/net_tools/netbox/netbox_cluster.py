#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Caleb Cullen (@pandemix) <ccullen@easydns.com>
# based closely upon netbox_device.py by:
# Copyright: (c) 2018, Mikhail Yohman (@FragmentedPacket) <mikhail.yohman@gmail.com>
# Copyright: (c) 2018, David Gomez (@amb1s1) <david.gomez@networktocode.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: netbox_cluster
short_description: Create, modify or delete clusters
description:
  - Creates, modifies or removes clusters within Netbox
notes:
  - Tags should be defined as a YAML list
  - This should be run with connection C(local) and hosts C(localhost)
author:
  - Caleb Cullen (@pandemix)
  - Mikhail Yohman (@FragmentedPacket)
  - David Gomez (@amb1s1)
requirements:
  - pynetbox
version_added: '2.8'
options:
  netbox_url:
    description:
      - URL of the Netbox instance resolvable by Ansible control host.
    required: true
  netbox_token:
    description:
      - The token created within Netbox to authorize API access.
    required: true
  data:
    description:
      - Defines the cluster.
    suboptions:
      name:
        description:
          - The name of the cluster.
          - Required
      type:
        description:
          - The name of the cluster-type within Netbox.
          - Required
      group:
        description:
          - The name of the cluster-group within Netbox.
      site:
        description:
          - The name of the site of this cluster within Netbox.
      comments:
        description:
          - Comments about this cluster.
      tags:
        description:
          - A list of tags to apply to the virtual interface.
      custom_fields:
        description:
          - A dict of fieldname - value pairs appropriate to the types of the custom fields.
          - Custom fields must be set up in the administrative pages of Netbox before they can be used.
    required: true
  state:
    description:
      - Use C(present) or C(absent) for adding or removing.
    choices: [ absent, present ]
    default: present
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    default: 'yes'
    type: bool
'''

# TODO: fix the examples
EXAMPLES = r'''
- name: "Test Netbox modules"
  connection: local
  hosts: localhost
  gather_facts: False

  tasks:
    - name: Create device within Netbox with only required information
      netbox_device:
        netbox_url: http://netbox.local
        netbox_token: thisIsMyToken
        data:
          name: Test (not really required, but helpful)
          device_type: C9410R
          device_role: Core Switch
          site: Main
        state: present

    - name: Delete device within netbox
      netbox_device:
        netbox_url: http://netbox.local
        netbox_token: thisIsMyToken
        data:
          name: Test
        state: absent

    - name: Create device with tags
      netbox_device:
        netbox_url: http://netbox.local
        netbox_token: thisIsMyToken
        data:
          name: Test
          device_type: C9410R
          device_role: Core Switch
          site: Main
          tags:
            - Schnozzberry
        state: present

    - name: Create device and assign to rack and position
      netbox_device:
        netbox_url: http://netbox.local
        netbox_token: thisIsMyToken
        data:
          name: Test
          device_type: C9410R
          device_role: Core Switch
          site: Main
          rack: Test Rack
          position: 10
          face: Front
'''

RETURN = r'''
cluster:
  description: Serialized object as created or already existent within Netbox
  returned: when C(state=present)
  type: dict
msg:
  description: Message indicating failure or info about what has been achieved
  returned: always
  type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.net_tools.netbox.netbox_utils import find_ids, normalize_data
import json
try:
    import pynetbox
    HAS_PYNETBOX = True
except ImportError:
    HAS_PYNETBOX = False


def main():
    '''
    Main entry point for module execution
    '''
    argument_spec = dict(
        netbox_url=dict(type="str", required=True),
        netbox_token=dict(type="str", required=True, no_log=True),
        data=dict(type="dict", required=True),
        state=dict(required=False, default='present', choices=['present', 'absent']),
        validate_certs=dict(type="bool", default=True)
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False)

    # Fail module if pynetbox is not installed
    if not HAS_PYNETBOX:
        module.fail_json(msg='pynetbox is required for this module')

    # Assign variables to be used with module
    app = 'virtualization'
    endpoint = 'clusters'
    url = module.params["netbox_url"]
    token = module.params["netbox_token"]
    data = module.params["data"]
    state = module.params["state"]
    validate_certs = module.params["validate_certs"]

    # Attempt to create Netbox API object
    try:
        nb = pynetbox.api(url, token=token, ssl_verify=validate_certs)
    except Exception as e:
        module.fail_json(msg="Failed to establish connection to Netbox API: %s" % e.message)
    try:
        nb_app = getattr(nb, app)
    except AttributeError:
        module.fail_json(msg="Incorrect application specified: %s" % (app))

    nb_endpoint = getattr(nb_app, endpoint)
    norm_data = normalize_data(data)
    try:
        if 'present' in state:
            return module.exit_json(
                **ensure_cluster_present(nb, nb_endpoint, norm_data)
            )
        else:
            return module.exit_json(
                **ensure_cluster_absent(nb_endpoint, norm_data)
            )
    except pynetbox.RequestError as e:
        return module.fail_json(msg=json.loads(e.error))


def ensure_cluster_present(nb, nb_endpoint, data):
    '''
    :returns dict(cluster, msg, changed): dictionary resulting of the request,
        where `cluster` is the cluster fetched or newly created in Netbox,
        cast to dict so that it will retain its deep structure
    '''
    nb_cluster = nb_endpoint.get(name=data["name"])
    if not nb_cluster:
        cluster = dict(_netbox_create_cluster(nb, nb_endpoint, data))
        changed = True
        msg = "Cluster %s created" % (data["name"])
    else:
        # since the record already exists, attempt to update it
        changed = _netbox_update_cluster(nb, nb_cluster, data)
        cluster = dict(nb_cluster)
        msg = "Cluster %s " % (data["name"])
        msg = msg + ("updated" if changed else "needed no update")

    return {"cluster": cluster, "msg": msg, "changed": changed}


def _netbox_create_cluster(nb, nb_endpoint, data):
    data = find_ids(nb, data)
    return nb_endpoint.create(data)

def _netbox_update_cluster(nb, cluster, data):
    data = find_ids(nb, data)
    return cluster.update(data)

def ensure_cluster_absent(nb_endpoint, data):
    '''
    :returns dict(msg, changed)
    '''
    cluster = nb_endpoint.get(name=data["name"])
    if cluster:
        cluster.delete()
        msg = 'Cluster %s deleted' % (data["name"])
        changed = True
    else:
        msg = 'Cluster %s not found' % (data["name"])
        changed = False

    return {"msg": msg, "changed": changed}


if __name__ == "__main__":
    main()
