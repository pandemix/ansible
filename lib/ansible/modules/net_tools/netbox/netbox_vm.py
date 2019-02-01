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
module: netbox_vm
short_description: Create, modify or delete virtual machines
description:
  - Creates, modifies or removes virtual machines from Netbox
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
      - Defines the virtual machine.
    suboptions:
      name:
        description:
          - The name of the virtual machine.
          - Required
      cluster:
        description:
          - Cluster where the virtual machine will run.
          - Required if I(state=present)
      vcpus:
        description:
          - Number of vCPUs assigned to this virtual machine.
      memory:
        description:
          - RAM assigned to this virtual machine in MB.
      disk:
        description:
          - Size of this virtual machine's storage file in GB.
      role:
        description:
          - The role of the virtual machine.
      tenant:
        description:
          - The tenant that the virtual machine will be assigned to.
      platform:
        description:
          - The platform of the virtual machine.
      site:
        description:
          - The site where this virtual machine is hosted.
      status:
        description:
          - The status of the virtual machine.
        choices:
          - Active
          - Offline
          - Staged
      comments:
        description:
          - Comments that may include additional information in regards to the device.
      tags:
        description:
          - A list of tags to apply to the virtual machine.
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
vm:
  description: Serialized object as created or already existent within Netbox
  returned: on creation
  type: dict
msg:
  description: Message indicating failure or info about what has been achieved
  returned: always
  type: str
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.net_tools.netbox.netbox_utils import find_ids, normalize_data, VM_STATUS
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
    endpoint = 'virtual-machines'
    url = module.params["netbox_url"]
    token = module.params["netbox_token"]
    data = module.params["data"]
    state = module.params["state"]
    validate_certs = module.params["validate_certs"]

    # Attempt to create Netbox API object
    try:
        nb = pynetbox.api(url, token=token, ssl_verify=validate_certs)
    except Exception:
        module.fail_json(msg="Failed to establish connection to Netbox API")
    try:
        nb_app = getattr(nb, app)
    except AttributeError:
        module.fail_json(msg="Incorrect application specified: %s" % (app))

    nb_endpoint = getattr(nb_app, endpoint)
    norm_data = normalize_data(data)
    try:
        if 'present' in state:
            return module.exit_json(
                **ensure_vm_present(nb, nb_endpoint, norm_data)
            )
        else:
            return module.exit_json(
                **ensure_vm_absent(nb_endpoint, norm_data)
            )
    except pynetbox.RequestError as e:
        return module.fail_json(msg=json.loads(e.error))


def ensure_vm_present(nb, nb_endpoint, data):
    '''
    :returns dict(vm, msg, changed): dictionary resulting of the request,
        where `vm` is the serialized vm fetched or newly created in
        Netbox
    '''
    nb_vm = nb_endpoint.get(name=data["name"])
    if not nb_vm:
        vm = _netbox_create_vm(nb, nb_endpoint, data).serialize()
        changed = True
        msg = "Virtual machine %s created" % (data["name"])
    else:
        msg = "Virtual machine %s already exists" % (data["name"])
        vm = nb_vm.serialize()
        changed = False

    return {"vm": vm, "msg": msg, "changed": changed}


def _netbox_create_vm(nb, nb_endpoint, data):
    if data.get("status"):
        data["status"] = VM_STATUS.get(data["status"].lower(), 0)
    data = find_ids(nb, data)
    return nb_endpoint.create(data)


def ensure_vm_absent(nb_endpoint, data):
    '''
    :returns dict(msg, changed)
    '''
    vm = nb_endpoint.get(name=data["name"])
    if vm:
        vm.delete()
        msg = 'Virtual machine %s deleted' % (data["name"])
        changed = True
    else:
        msg = 'Virtual machine %s already absent' % (data["name"])
        changed = False

    return {"msg": msg, "changed": changed}


if __name__ == "__main__":
    main()
