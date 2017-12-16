---
services: virtual-machines, key-vault
platforms: python
author: lmazuel
---

# Deploy Certificates to VMs from customer-managed Key Vault in Python

This sample explains how you can create a VM in Python, with certificates installed automatically 
from a Key Vault account.

## Features

This project framework provides the following features:

* Feature 1
* Feature 2
* ...

## Getting Started

### Prerequisites

- A Key Vault account. Example on how to create a Key Vault account can be found:

  - From CLI 2.0: https://docs.microsoft.com/azure/key-vault/key-vault-manage-with-cli2
  - From Python SDK: https://github.com/Azure-Samples/key-vault-python-manage

> In order to execute this sample, your Key Vault account MUST have the "enabled-for-deployment" special permission.
  The EnabledForDeployment flag explicitly gives Azure (Microsoft.Compute resource provider) permission to use the certificates stored as secrets for this deployment. 

### Installation

1.  If you don't already have it, [install Python](https://www.python.org/downloads/).

    This sample (and the SDK) is compatible with Python 2.7, 3.3, 3.4, 3.5 and 3.6.

2.  We recommend that you use a [virtual environment](https://docs.python.org/3/tutorial/venv.html)
    to run this example, but it's not required.
    Install and initialize the virtual environment with the "venv" module on Python 3 (you must install [virtualenv](https://pypi.python.org/pypi/virtualenv) for Python 2.7):

    ```
    python -m venv mytestenv # Might be "python3" or "py -3.6" depending on your Python installation
    cd mytestenv
    source bin/activate      # Linux shell (Bash, ZSH, etc.) only
    ./scripts/activate       # PowerShell only
    ./scripts/activate.bat   # Windows CMD only
    ```

1.  Clone the repository.

    ```
    git clone https://github.com/Azure-Samples/app-service-msi-keyvault-python.git
    ```

2.  Install the dependencies using pip.

    ```
    cd app-service-msi-keyvault-python
    pip install -r requirements.txt
    ```

3.  Set up the environment variable `KEY_VAULT_URL` with your KeyVault URL of replace the variable in the example file.

1. Export these environment variables into your current shell or update the credentials in the example file.

    ```
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your client id}
    export AZURE_CLIENT_SECRET={your client secret}
    ```

1. Run the sample.

    ```
    python example.py
    ```

### Quickstart
(Add steps to get up and running quickly)

1. git clone [repository clone url]
2. cd [respository name]
3. ...


## Demo

### Preliminary operations

This example setup some preliminary components that are no the topic of this sample and do not differ
from regular scenarios:

- A Resource Group
- A Virtual Network
- A Subnet
- A Public IP
- A Network Interface

For details about creation of these components, you can refer to the generic samples:

- [Resource Group](https://github.com/Azure-Samples/resource-manager-python-resources-and-groups)
- [Network and VM](https://github.com/Azure-Samples/virtual-machines-python-manage)

### Create a VM with Certificates from Key Vault

During the creation of the VM, only one attribute is necessary to ask Azure
to assign a MSI ID to the VM.

```python
params_create = {
    'location': LOCATION,
    'os_profile': get_os_profile(),
    'hardware_profile': get_hardware_profile(),
    'network_profile': get_network_profile(nic.id),
    'storage_profile': get_storage_profile(),
    # Activate MSI on that VM
    'identity': {
        'type': ResourceIdentityType.system_assigned
    }
}

vm_poller = compute_client.virtual_machines.create_or_update(
    GROUP_NAME,
    VM_NAME,
    params_create,
)
vm_result = vm_poller.result()
```


A demo app is included to show how to use the project.

To run the demo, follow these steps:

(Add steps to start up the demo)

1.
2.
3.

## Resources

(Any additional resources or related projects)

- Link to supporting information
- Link to similar sample
- ...
