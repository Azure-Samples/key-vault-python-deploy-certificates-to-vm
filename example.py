import base64
import binascii
import logging
import os
import time
import uuid

from haikunator import Haikunator

from azure.common.credentials import ServicePrincipalCredentials

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault import KeyVaultClient
from azure.keyvault.models import *

haikunator = Haikunator()

logging.basicConfig(level=logging.DEBUG)

# Resource

LOCATION = 'westus'
GROUP_NAME = 'azure-kv-vm-certificate-sample-group'

# KeyVault

KV_NAME = haikunator.haikunate() # Random name to avoid collision executing this sample

# This default Certificate creation policy was obtained by using CLI 2.0
# az keyvault certificate get-default-policy
DEFAULT_POLICY =  CertificatePolicy(
    KeyProperties(True, 'RSA', 2048, True),
    SecretProperties('application/x-pkcs12'),
    issuer_parameters=IssuerParameters('Self'),
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
        '11111111-1111-1111-1111-111111111111') # your Azure Subscription Id
    credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID']
    )
    resource_client = ResourceManagementClient(credentials, subscription_id)
    compute_client = ComputeManagementClient(credentials, subscription_id)
    network_client = NetworkManagementClient(credentials, subscription_id)
    kv_mgmt_client = KeyVaultManagementClient(credentials, subscription_id)

    kv_credentials = ServicePrincipalCredentials(
        client_id=os.environ['AZURE_CLIENT_ID'],
        secret=os.environ['AZURE_CLIENT_SECRET'],
        tenant=os.environ['AZURE_TENANT_ID'],
        resource="https://vault.azure.net"
    )
    kv_client = KeyVaultClient(kv_credentials)

    # Create Resource group
    print('\nCreate Resource Group')
    resource_group = resource_client.resource_groups.create_or_update(
        GROUP_NAME,
        {'location': LOCATION}
    )
    print_item(resource_group)

Solve
'https://graph.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/servicePrincipals?$filter=servicePrincipalNames%2Fany%28c%3Ac%20eq%20%2765fa0d3a-145a-4e86-997b-651a09112264%27%29&api-version=1.6'

    # Create Key Vault account
    print('\nCreate Key Vault account')
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
                    'object_id': "XXXX",
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

    # # KeyVault recommentation is to wait 20 seconds after account creation for DNS update
    time.sleep(20)
    # vault = kv_mgmt_client.vaults.get(GROUP_NAME, KV_NAME)

    # Ask KeyVault to create a Certificate
    certificate_name = "cert1"
    print('\nCreate Key Vault Certificate')
    kv_client.create_certificate(
        vault.properties.vault_uri,
        certificate_name,
        certificate_policy=DEFAULT_POLICY
    )
    while True:
        check = kv_client.get_certificate_operation(
            vault.properties.vault_uri,
            certificate_name
        )
        if check.status != 'inProgress':
            break
        try:
            print("Waiting for certificate creation to finish")
            time.sleep(10)
        except KeyboardInterrupt:
            print("Certificate creation wait cancelled.")
            raise        

    print('\nGet Key Vault created certificate as a secret')
    certificate_as_secret = kv_client.get_secret(
        vault.properties.vault_uri,
        certificate_name,
        "" # Latest version
    )

    print("\nCreate Network")
    # Create Network components of the VM
    # This is not MSI related and is just required to create the VM
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
            # This is the Key Vault interesting part
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
    vm_poller = compute_client.virtual_machines.create_or_update(
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

    print("Your certificate is available in this folder: /var/lib/waagent\n")

    input("Press enter to delete this Resource Group.")

    # Delete Resource group and everything in it
    print('Delete Resource Group')
    delete_async_operation = resource_client.resource_groups.delete(GROUP_NAME)
    delete_async_operation.wait()
    print("\nDeleted: {}".format(GROUP_NAME))

def print_item(group):
    """Print a ResourceGroup instance."""
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

def b64_to_hex(s):
    """
    Decodes a string to base64 on 2.x and 3.x
    :param str s: base64 encoded string
    :return: uppercase hex string
    :rtype: str
    """
    decoded = base64.b64decode(s)
    hex_data = binascii.hexlify(decoded).upper()
    if isinstance(hex_data, bytes):
        return str(hex_data.decode("utf-8"))
    return hex_data

###### Network creation, not specific to MSI scenario ######

def create_virtual_network(network_client):
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
    vnet_poller = network_client.virtual_networks.create_or_update(
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
    params_create = {
        'location': LOCATION,
        'public_ip_allocation_method': 'dynamic',
    }
    pip_poller = network_client.public_ip_addresses.create_or_update(
        GROUP_NAME,
        PUBLIC_IP_NAME,
        params_create,
    )
    return pip_poller.result()

def create_network_interface(network_client, subnet, public_ip):
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
    nic_poller = network_client.network_interfaces.create_or_update(
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
