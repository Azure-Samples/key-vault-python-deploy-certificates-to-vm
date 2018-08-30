---
services: virtual-machines, key-vault
platforms: python
author: lmazuel
---

# Deploy Certificates to VMs from customer-managed Key Vault in Python

This sample explains how you can create a VM in Python, with certificates installed automatically
from a Key Vault account.

## Getting Started

### Prerequisites

- An Azure subscription

- A Service Principal. Create an Azure service principal either through
[Azure CLI](https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [the portal](https://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).

### Installation

1.  If you don't already have it, [install Python](https://www.python.org/downloads/).

    This sample (and the SDK) is compatible with Python 2.7, 3.4, 3.5, 3.6 and 3.7.

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
    git clone https://github.com/Azure-Samples/key-vault-python-deploy-certificates-to-vm.git
    ```

2.  Install the dependencies using pip.

    ```
    cd key-vault-python-deploy-certificates-to-vm
    pip install -r requirements.txt
    ```

1. Export these environment variables into your current shell or update the credentials in the example file.

    ```
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your client id}
    export AZURE_CLIENT_SECRET={your client secret}
    export AZURE_SUBSCRIPTION_ID={your subscription id}
    ```

1. Run the sample.

    ```
    python example.py
    ```

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

### Creating a KeyVault account enabled for deployment

```python
    vault = kv_mgmt_client.vaults.create_or_update(
        GROUP_NAME,
        KV_NAME,
        {
            'location': LOCATION,
            'properties': {
                'sku': {
                    'name': 'standard'
                },
                'tenant_id': os.environ['AZURE_TENANT_ID'],
                'access_policies': [{
                    'tenant_id': os.environ['AZURE_TENANT_ID'],
                    'object_id': sp_object_id,
                    'permissions': {
                        # Only "certificates" and "secrets" are needed for this sample
                        'certificates': ['all'],
                        'secrets': ['all']
                    }
                }],
                # Critical to allow the VM to download certificates later
                'enabled_for_deployment': True
            }
        }
    )
```

You can also found different example on how to create a Key Vault account:

  - From CLI 2.0: https://docs.microsoft.com/azure/key-vault/key-vault-manage-with-cli2
  - From Python SDK: https://github.com/Azure-Samples/key-vault-python-manage

> In order to execute this sample, your Key Vault account MUST have the "enabled-for-deployment" special permission.
  The EnabledForDeployment flag explicitly gives Azure (Microsoft.Compute resource provider) permission to use the certificates stored as secrets for this deployment.

> Note that access policy takes an *object_id*, not a client_id as parameter. This samples also provide a quick way to convert a Service Principal client_id to an object_id using the `azure-graphrbac` client.

### Ask Key Vault to create a certificate for you

```python
    kv_client.create_certificate(
        vault.properties.vault_uri,
        certificate_name,
        certificate_policy=DEFAULT_POLICY
    )
```

An example of `DEFAULT_POLICY` is described in the sample file:
```python
DEFAULT_POLICY = CertificatePolicy(
    key_properties=KeyProperties(
        exportable=True,
        key_type='RSA',
        key_size=2048,
        reuse_key=True
    ),
    secret_properties=SecretProperties(content_type='application/x-pkcs12'),
    issuer_parameters=IssuerParameters(name='Self'),
    x509_certificate_properties=X509CertificateProperties(
        subject='CN=CLIGetDefaultPolicy',
        validity_in_months=12,
        key_usage=[
            "cRLSign",
            "dataEncipherment",
            "digitalSignature",
            "keyEncipherment",
            "keyAgreement",
            "keyCertSign"
        ]
    ),
    lifetime_actions=[{
        "action": Action(
            action_type="AutoRenew"
        ),
        "trigger": Trigger(
            days_before_expiry=90
        )
    }]
)
```

This is the same policy that:

- Is pre-configured in the Portal when you choose "Generate" in the Certificates tab
- You get when you use the CLI 2.0: `az keyvault certificate get-default-policy`

> Create certificate is an async operation. This sample provides a simple polling mechanism example.

### Create a VM with Certificates from Key Vault

First, get your certificate as a Secret object:

```python
    certificate_as_secret = kv_client.get_secret(
        vault.properties.vault_uri,
        certificate_name,
        "" # Latest version
    )
```

During the creation of the VM, use the `secrets` atribute to assign your certificate:.

```python
params_create = {
    'location': LOCATION,
    'hardware_profile': get_hardware_profile(),
    'network_profile': get_network_profile(nic.id),
    'storage_profile': get_storage_profile(),
    'os_profile': {
        'admin_username': ADMIN_LOGIN,
        'admin_password': ADMIN_PASSWORD,
        'computer_name': 'testkvcertificates',
        # This is the Key Vault critical part
        'secrets': [{
            'source_vault': {
                'id': vault.id,
            },
            'vault_certificates': [{
                'certificate_url': certificate_as_secret.id
            }]
        }]
    }
}

vm_poller = compute_client.virtual_machines.create_or_update(
    GROUP_NAME,
    VM_NAME,
    params_create,
)
vm_result = vm_poller.result()
```


## Resources

- https://azure.microsoft.com/services/key-vault/
- https://github.com/Azure/azure-sdk-for-python
- https://docs.microsoft.com/python/api/overview/azure/key-vault
