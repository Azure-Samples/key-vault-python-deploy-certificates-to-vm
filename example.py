"""Deploy Certificates to VMs from customer-managed Key Vault in Python.
"""
import logging
import os
import time

from haikunator import Haikunator

from azure.identity import ClientSecretCredential

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.certificates import LifetimeAction, CertificateClient, CertificatePolicy, CertificatePolicyAction
from azure.keyvault.secrets import SecretClient

HAIKUNATOR = Haikunator()

# Activate this if you want to see detailed log
# logging.basicConfig(level=logging.DEBUG)

# Resource

LOCATION = 'westus2'
GROUP_NAME = 'azure-kv-vm-certificate-sample-group'

# KeyVault

# Random name to avoid collision executing this sample
KV_NAME = HAIKUNATOR.haikunate()

# This default Certificate creation policy. This is the same policy that:
# - Is pre-configured in the Portal when you choose "Generate" in the Certificates tab
# - You get when you use the CLI 2.0: az keyvault certificate get-default-policy
DEFAULT_POLICY = CertificatePolicy(
    'Self',
    exportable=True,
    key_type='RSA',
    key_size=2048,
    reuse_key=True,
    content_type='application/x-pkcs12',
    subject='CN=CLIGetDefaultPolicy',
    validity_in_months=12,
    key_usage=[
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyEncipherment",
        "keyAgreement",
        "keyCertSign"
    ],
    lifetime_actions=[
        LifetimeAction(action=CertificatePolicyAction.auto_renew, days_before_expiry=90)
    ]
)

# Network

VNET_NAME = 'azure-sample-vnet'
SUBNET_NAME = 'azure-sample-subnet'
PUBLIC_IP_NAME = 'azure-sample-pip'
NIC_NAME = 'azure-sample-nic'
IP_CONFIG_NAME = 'azure-sample-ip-config'

# VM

VM_NAME = 'azuretestmsi'
ADMIN_LOGIN = 'Foo12'
ADMIN_PASSWORD = 'BaR@123' + GROUP_NAME


# Create a Linux VM with Key Vault certificates installed at creation.
#
# This script expects that the following environment vars are set:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Application Client ID
# AZURE_CLIENT_OBJECT_ID: with your Azure Active Directory Application Object ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Secret
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
#
def run_example():
    """Resource Group management example."""
    #
    # Create the Resource Manager Client with an Application (service principal) token provider
    #
    subscription_id = os.environ.get(
        'AZURE_SUBSCRIPTION_ID',
        '11111111-1111-1111-1111-111111111111')  # your Azure Subscription Id
    credential = ClientSecretCredential(
        client_id=os.environ['AZURE_CLIENT_ID'],
        client_secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant_id=os.environ['AZURE_TENANT_ID']
    )
    resource_client = ResourceManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    kv_mgmt_client = KeyVaultManagementClient(credential, subscription_id)

    cert_client = CertificateClient(
        "https://{}.vault.azure.net".format(KV_NAME),
        credential
    )

    # Create Resource group
    print('\nCreate Resource Group')
    resource_group = resource_client.resource_groups.create_or_update(
        GROUP_NAME,
        {'location': LOCATION}
    )
    print_item(resource_group)

    # Resolve the client_id as object_id for KeyVault access policy.
    # If you already know your object_id, you can skip this part
    sp_object_id = os.environ.get(
        'AZURE_CLIENT_OBJECT_ID',
        '11111111-1111-1111-1111-111111111111')  # your service principal's object id

    # Create Key Vault account
    print('\nCreate Key Vault account')
    async_vault_poller = kv_mgmt_client.vaults.begin_create_or_update(
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
    vault = async_vault_poller.result()
    print_item(vault)

    # # KeyVault recommentation is to wait 20 seconds after account creation for DNS update
    time.sleep(20)

    # Ask KeyVault to create a Certificate
    certificate_name = "cert1"
    print('\nCreate Key Vault Certificate')
    certificate_poller = cert_client.begin_create_certificate(
        certificate_name,
        policy=DEFAULT_POLICY
    )
    certificate_poller.wait()
    while True:
        check = cert_client.get_certificate_operation(certificate_name)
        if check.status != 'inProgress':
            break
        try:
            print("Waiting for certificate creation to finish")
            time.sleep(10)
        except KeyboardInterrupt:
            print("Certificate creation wait cancelled.")
            raise
    print_item(check)

    print('\nGet Key Vault created certificate as a secret')
    secret_client = SecretClient(
        "https://{}.vault.azure.net".format(KV_NAME),
        credential
    )
    certificate_as_secret = secret_client.get_secret(
        certificate_name,
        ""  # Latest version
    )
    print_item(certificate_as_secret)

    print("\nCreate Network")
    # Create Network components of the VM
    # This is not related to the main topic of this sample and is just required to create the VM
    subnet = create_virtual_network(network_client)
    public_ip = create_public_ip(network_client)
    nic = create_network_interface(network_client, subnet, public_ip)
    print_item(nic)

    # Create a VM with some Key Vault certificates
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

    print("\nCreate VM")
    vm_poller = compute_client.virtual_machines.begin_create_or_update(
        GROUP_NAME,
        VM_NAME,
        params_create,
    )
    vm_result = vm_poller.result()
    print_item(vm_result)

    # Get the PublicIP after VM creation, since assignment is dynamic
    public_ip = network_client.public_ip_addresses.get(
        GROUP_NAME,
        PUBLIC_IP_NAME
    )

    print("You can connect to the VM using:")
    print("ssh {}@{}".format(
        ADMIN_LOGIN,
        public_ip.ip_address,
    ))
    print("And password: {}\n".format(ADMIN_PASSWORD))

    print("Your certificate is available in this folder: /var/lib/waagent")
    print("You must be root to see it (sudo su)\n")

    input("Press enter to delete this Resource Group.")

    # Delete Resource group and everything in it
    print('Delete Resource Group')
    delete_async_operation = resource_client.resource_groups.begin_delete(GROUP_NAME)
    delete_async_operation.wait()
    print("\nDeleted: {}".format(GROUP_NAME))


def print_item(group):
    """Print a ResourceGroup instance."""
    if hasattr(group, 'name'):
        print("\tName: {}".format(group.name))
    print("\tId: {}".format(group.id))
    if hasattr(group, 'location'):
        print("\tLocation: {}".format(group.location))
    print_properties(getattr(group, 'properties', None))


def print_properties(props):
    """Print a ResourceGroup propertyies instance."""
    if props and hasattr(props, 'provisioning_state'):
        print("\tProperties:")
        print("\t\tProvisioning State: {}".format(props.provisioning_state))
    print("\n\n")

###### Network creation, not specific to MSI scenario ######


def create_virtual_network(network_client):
    """Usual VNet creation.
    """
    params_create = {
        'location': LOCATION,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16'],
        },
        'subnets': [{
            'name': SUBNET_NAME,
            'address_prefix': '10.0.0.0/24',
        }],
    }
    vnet_poller = network_client.virtual_networks.begin_create_or_update(
        GROUP_NAME,
        VNET_NAME,
        params_create,
    )
    vnet_poller.wait()

    return network_client.subnets.get(
        GROUP_NAME,
        VNET_NAME,
        SUBNET_NAME,
    )


def create_public_ip(network_client):
    """Usual PublicIP creation.
    """
    params_create = {
        'location': LOCATION,
        'public_ip_allocation_method': 'dynamic',
    }
    pip_poller = network_client.public_ip_addresses.begin_create_or_update(
        GROUP_NAME,
        PUBLIC_IP_NAME,
        params_create,
    )
    return pip_poller.result()


def create_network_interface(network_client, subnet, public_ip):
    """Usual create NIC.
    """
    params_create = {
        'location': LOCATION,
        'ip_configurations': [{
            'name': IP_CONFIG_NAME,
            'private_ip_allocation_method': "Dynamic",
            'subnet': subnet,
            'public_ip_address': {
                'id': public_ip.id
            }
        }]
    }
    nic_poller = network_client.network_interfaces.begin_create_or_update(
        GROUP_NAME,
        NIC_NAME,
        params_create,
    )
    return nic_poller.result()

###### VM creation, not specific to this scenario ######


def get_hardware_profile():
    return {
        'vm_size': 'standard_a0'
    }


def get_network_profile(network_interface_id):
    return {
        'network_interfaces': [{
            'id': network_interface_id,
        }],
    }


def get_storage_profile():
    return {
        'image_reference': {
            'publisher': 'Canonical',
            'offer': 'UbuntuServer',
            'sku': '16.04.0-LTS',
            'version': 'latest'
        }
    }


if __name__ == "__main__":
    run_example()
