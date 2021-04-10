import binascii
import os
import warnings

with warnings.catch_warnings():
  warnings.simplefilter('ignore', DeprecationWarning)
  from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
CRYPTOGRAPHY_BACKEND = default_backend()

from .exceptions import AnsibleVaultError, AnsibleVaultFormatError
from .utils import to_bytes


__all__ = ['CIPHERS']


def _unhexlify(b_data):
  try:
    return binascii.unhexlify(b_data)
  except (binascii.BinasciiError, TypeError) as exc:
    raise AnsibleVaultFormatError(f'Vault format unhexlify error: {exc}')


def _parse_vaulttext(b_vaulttext):
  b_vaulttext = _unhexlify(b_vaulttext)
  b_salt, b_crypted_hmac, b_ciphertext = b_vaulttext.split(b'\n', 2)
  b_salt = _unhexlify(b_salt)
  b_ciphertext = _unhexlify(b_ciphertext)

  return b_ciphertext, b_salt, b_crypted_hmac


def parse_vaulttext(b_vaulttext):
  """Parse the vaulttext.

  Args:
    b_vaulttext: A byte str containing the vaulttext (ciphertext, salt,
        crypted_hmac).
  Returns:
    A tuple of byte str of the ciphertext suitable for passing to a Cipher
    class's decrypt() function, a byte str of the salt, and a byte str of the
    crypted_hmac.
  Raises:
    AnsibleVaultFormatError: If the vaulttext format is invalid.
  """
  # SPLIT SALT, DIGEST, AND DATA
  try:
    return _parse_vaulttext(b_vaulttext)
  except AnsibleVaultFormatError:
    raise
  except Exception as exc:
    raise AnsibleVaultFormatError(f'Vault vaulttext format error: {exc}')


class CipherAES256:
  """Vault implementation using AES-CTR with an HMAC-SHA256 authentication code.

  Keys are derived using PBKDF2.
  """

  @staticmethod
  def _pbkdf2_prf(p, s):
    return HMAC.new(p, s, SHA256).digest()

  @classmethod
  def _gen_key_initctr(cls, b_password, b_salt):
    # 16 for AES 128, 32 for AES256
    key_length = 32

    iv_length = algorithms.AES.block_size // 8

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=2 * key_length + iv_length,
        salt=b_salt,
        iterations=10000,
        backend=CRYPTOGRAPHY_BACKEND)
    b_derivedkey = kdf.derive(b_password)

    b_iv = b_derivedkey[key_length * 2:key_length * 2 + iv_length]

    b_key1 = b_derivedkey[:key_length]
    b_key2 = b_derivedkey[key_length:key_length * 2]

    return b_key1, b_key2, b_iv

  @staticmethod
  def _encrypt(b_plaintext, b_key1, b_key2, b_iv):
    cipher = Cipher(algorithms.AES(b_key1), modes.CTR(b_iv),
                    CRYPTOGRAPHY_BACKEND)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    b_ciphertext = encryptor.update(padder.update(b_plaintext) +
                                    padder.finalize())
    b_ciphertext += encryptor.finalize()

    # COMBINE SALT, DIGEST AND DATA
    hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
    hmac.update(b_ciphertext)
    b_hmac = hmac.finalize()

    return (to_bytes(binascii.hexlify(b_hmac), errors='surrogateescape'),
            binascii.hexlify(b_ciphertext))

  @classmethod
  def encrypt(cls, b_plaintext, secret):
    if secret is None:
      raise AnsibleVaultError('The secret passed to encrypt() was None')
    b_salt = os.urandom(32)
    b_password = secret.bytes
    b_key1, b_key2, b_iv = cls._gen_key_initctr(b_password, b_salt)

    b_hmac, b_ciphertext = cls._encrypt(b_plaintext, b_key1, b_key2, b_iv)

    b_vaulttext = b'\n'.join([binascii.hexlify(b_salt), b_hmac, b_ciphertext])
    # Unnecessary but getting rid of it is a backwards incompatible vault
    # format change
    b_vaulttext = binascii.hexlify(b_vaulttext)
    return b_vaulttext

  @classmethod
  def _decrypt(cls, b_ciphertext, b_crypted_hmac, b_key1, b_key2, b_iv):
    # b_key1, b_key2, b_iv = self._gen_key_initctr(b_password, b_salt)
    # EXIT EARLY IF DIGEST DOESN'T MATCH
    hmac = HMAC(b_key2, hashes.SHA256(), CRYPTOGRAPHY_BACKEND)
    hmac.update(b_ciphertext)
    try:
      hmac.verify(_unhexlify(b_crypted_hmac))
    except InvalidSignature as exc:
      raise AnsibleVaultError(f'HMAC verification failed: {exc}')

    cipher = Cipher(algorithms.AES(b_key1), modes.CTR(b_iv),
                    CRYPTOGRAPHY_BACKEND)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    b_plaintext = unpadder.update(decryptor.update(b_ciphertext) +
                                  decryptor.finalize()) + unpadder.finalize()
    return b_plaintext

  @classmethod
  def decrypt(cls, b_vaulttext, secret):
    b_ciphertext, b_salt, b_crypted_hmac = parse_vaulttext(b_vaulttext)

    b_password = secret.bytes

    b_key1, b_key2, b_iv = cls._gen_key_initctr(b_password, b_salt)

    b_plaintext = cls._decrypt(b_ciphertext, b_crypted_hmac, b_key1, b_key2,
                               b_iv)
    return b_plaintext


CIPHERS = {
    'AES256': CipherAES256,
}
