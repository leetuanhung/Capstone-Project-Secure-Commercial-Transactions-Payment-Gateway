"""
Hardware Security Module (HSM) Client
Integration with AWS KMS for secure key management
"""
import boto3
import base64
from typing import Dict, Optional
from botocore.exceptions import ClientError
from datetime import datetime

class HSMClient:
    def __init__(self, region_name: str = 'us-east-1', kms_client=None, auto_init: bool = True):
        """Initialize HSMClient.

        Args:
            region_name: AWS region name used when creating a boto3 KMS client.
            kms_client: Optional boto3 KMS client instance to use (allows injection/mocking).
            auto_init: If False, do not create a boto3 client during __init__ (useful for unit tests).
        """
        self.key_cache = {}
        self._region_name = region_name

        # Allow injection of an existing client (for tests) or lazy creation.
        self.kms_client = None
        if kms_client is not None:
            self.kms_client = kms_client
        elif auto_init:
            # Create a boto3 client only when explicitly requested (auto_init=True)
            self.kms_client = boto3.client('kms', region_name=region_name)
    
    def create_master_key(self, key_alias: str, description: str = "Payment encryption key") -> str:
        """Create a new KMS master key"""
        try:
            response = self.kms_client.create_key(
                Description=description,
                KeyUsage='ENCRYPT_DECRYPT',
                Origin='AWS_KMS',
                MultiRegion=False
            )
            
            key_id = response['KeyMetadata']['KeyId']
            
            # Create alias for easier reference
            self.kms_client.create_alias(
                AliasName=f'alias/{key_alias}',
                TargetKeyId=key_id
            )
            
            return key_id
        except ClientError as e:
            raise Exception(f"Failed to create KMS key: {str(e)}")
    
    def encrypt_data(self, plaintext: str, key_id: str, 
                     context: Optional[Dict[str, str]] = None) -> str:
        """
        Encrypt data using KMS
        context: Additional authentication data
        """
        try:
            encryption_context = context or {}
            # Emit trace (redacted by tracer)
            try:
                from .tracer import trace_event
                trace_event('hsm.encrypt.request', {'key_id': key_id, 'context': encryption_context, 'plaintext': plaintext})
            except Exception:
                pass

            response = self.kms_client.encrypt(
                KeyId=key_id,
                Plaintext=plaintext.encode(),
                EncryptionContext=encryption_context
            )

            # Return base64 encoded ciphertext
            ct = base64.b64encode(response['CiphertextBlob']).decode('utf-8')
            try:
                from .tracer import trace_event
                trace_event('hsm.encrypt.response', {'key_id': key_id, 'ciphertext_len': len(ct)})
            except Exception:
                pass
            return ct
        except ClientError as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_data(self, ciphertext: str, key_id: str,
                     context: Optional[Dict[str, str]] = None) -> str:
        """
        Decrypt data using KMS
        context: Must match encryption context
        """
        try:
            encryption_context = context or {}
            try:
                from .tracer import trace_event
                trace_event('hsm.decrypt.request', {'key_id': key_id, 'ciphertext_len': len(ciphertext)})
            except Exception:
                pass

            # Decode base64 ciphertext
            ciphertext_blob = base64.b64decode(ciphertext)

            response = self.kms_client.decrypt(
                KeyId=key_id,
                CiphertextBlob=ciphertext_blob,
                EncryptionContext=encryption_context
            )

            out = response['Plaintext'].decode('utf-8')
            try:
                from .tracer import trace_event
                trace_event('hsm.decrypt.response', {'key_id': key_id, 'output_len': len(out)})
            except Exception:
                pass

            return out
        except ClientError as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def generate_data_key(self, key_id: str, key_spec: str = 'AES_256') -> Dict[str, str]:
        """
        Generate data encryption key (DEK)
        Returns both plaintext and encrypted version
        """
        try:
            response = self.kms_client.generate_data_key(
                KeyId=key_id,
                KeySpec=key_spec
            )
            
            return {
                'plaintext': base64.b64encode(response['Plaintext']).decode('utf-8'),
                'encrypted': base64.b64encode(response['CiphertextBlob']).decode('utf-8')
            }
        except ClientError as e:
            raise Exception(f"Failed to generate data key: {str(e)}")
    
    def rotate_key(self, key_id: str) -> bool:
        """Enable automatic key rotation"""
        try:
            self.kms_client.enable_key_rotation(KeyId=key_id)
            return True
        except ClientError as e:
            raise Exception(f"Failed to enable key rotation: {str(e)}")
    
    def get_key_metadata(self, key_id: str) -> Dict:
        """Retrieve key metadata"""
        try:
            response = self.kms_client.describe_key(KeyId=key_id)
            return response['KeyMetadata']
        except ClientError as e:
            raise Exception(f"Failed to get key metadata: {str(e)}")
    
    def list_keys(self) -> list:
        """List all KMS keys"""
        try:
            response = self.kms_client.list_keys()
            return response['Keys']
        except ClientError as e:
            raise Exception(f"Failed to list keys: {str(e)}")
    
    def encrypt_card_data(self, card_number: str, cvv: str, 
                         master_key_id: str) -> Dict[str, str]:
        """
        Encrypt sensitive card data using KMS
        Returns encrypted data with metadata
        """
        context = {
            'data_type': 'card_data',
            'timestamp': str(int(datetime.utcnow().timestamp()))
        }
        
        encrypted_card = self.encrypt_data(card_number, master_key_id, context)
        encrypted_cvv = self.encrypt_data(cvv, master_key_id, context)
        
        return {
            'encrypted_card_number': encrypted_card,
            'encrypted_cvv': encrypted_cvv,
            'key_id': master_key_id,
            'encryption_context': context
        }
    
    def decrypt_card_data(self, encrypted_data: Dict[str, str]) -> Dict[str, str]:
        """Decrypt card data"""
        card_number = self.decrypt_data(
            encrypted_data['encrypted_card_number'],
            encrypted_data['key_id'],
            encrypted_data['encryption_context']
        )
        
        cvv = self.decrypt_data(
            encrypted_data['encrypted_cvv'],
            encrypted_data['key_id'],
            encrypted_data['encryption_context']
        )
        
        return {
            'card_number': card_number,
            'cvv': cvv
        }
    
    def schedule_key_deletion(self, key_id: str, pending_days: int = 30) -> bool:
        """
        Schedule key for deletion
        minimum 7 days, maximum 30 days
        """
        try:
            self.kms_client.schedule_key_deletion(
                KeyId=key_id,
                PendingWindowInDays=pending_days
            )
            return True
        except ClientError as e:
            raise Exception(f"Failed to schedule key deletion: {str(e)}")
    
    def cancel_key_deletion(self, key_id: str) -> bool:
        """Cancel scheduled key deletion"""
        try:
            self.kms_client.cancel_key_deletion(KeyId=key_id)
            return True
        except ClientError as e:
            raise Exception(f"Failed to cancel key deletion: {str(e)}")
    
    def disable_key(self, key_id: str) -> bool:
        """Disable a KMS key"""
        try:
            self.kms_client.disable_key(KeyId=key_id)
            return True
        except ClientError as e:
            raise Exception(f"Failed to disable key: {str(e)}")
    
    def enable_key(self, key_id: str) -> bool:
        """Enable a KMS key"""
        try:
            self.kms_client.enable_key(KeyId=key_id)
            return True
        except ClientError as e:
            raise Exception(f"Failed to enable key: {str(e)}")
    
    def create_grant(self, key_id: str, grantee_principal: str, 
                     operations: list) -> str:
        """
        Create a grant for key usage
        operations: ['Encrypt', 'Decrypt', 'GenerateDataKey', etc.]
        """
        try:
            response = self.kms_client.create_grant(
                KeyId=key_id,
                GranteePrincipal=grantee_principal,
                Operations=operations
            )
            return response['GrantId']
        except ClientError as e:
            raise Exception(f"Failed to create grant: {str(e)}")
    
    def revoke_grant(self, key_id: str, grant_id: str) -> bool:
        """Revoke a grant"""
        try:
            self.kms_client.revoke_grant(
                KeyId=key_id,
                GrantId=grant_id
            )
            return True
        except ClientError as e:
            raise Exception(f"Failed to revoke grant: {str(e)}")
    
    def get_public_key(self, key_id: str) -> Dict:
        """Get public key for asymmetric KMS key"""
        try:
            response = self.kms_client.get_public_key(KeyId=key_id)
            return {
                'public_key': base64.b64encode(response['PublicKey']).decode('utf-8'),
                'key_usage': response['KeyUsage'],
                'signing_algorithms': response.get('SigningAlgorithms', []),
                'encryption_algorithms': response.get('EncryptionAlgorithms', [])
            }
        except ClientError as e:
            raise Exception(f"Failed to get public key: {str(e)}")

# Singleton instance
_SINGLETON_HSM_CLIENT = None


def get_hsm_client(region_name: str = 'us-east-1'):
    """Return a singleton HSMClient instance, creating it lazily.

    Use this helper in production code instead of importing a module-level instance
    so tests and environments without AWS credentials won't attempt network calls on import.
    """
    global _SINGLETON_HSM_CLIENT
    if _SINGLETON_HSM_CLIENT is None:
        _SINGLETON_HSM_CLIENT = HSMClient(region_name=region_name, auto_init=True)
    return _SINGLETON_HSM_CLIENT