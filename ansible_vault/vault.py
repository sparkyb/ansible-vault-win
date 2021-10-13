import logging
import os
import os.path
import platform
import shlex
import shutil
import subprocess
import tempfile

from .ciphers import CIPHERS
from .constants import DEFAULT_VAULT_IDENTITY
from .exceptions import AnsibleVaultError, AnsibleVaultFormatError
from .utils import to_bytes, to_text


__all__ = ['VaultLib', 'VaultEditor']


LOGGER = logging.getLogger(__name__)


if platform.system() == 'Windows':
  DEFAULT_EDITOR = 'notepad'
else:
  DEFAULT_EDITOR = 'nano'


b_HEADER = b'$ANSIBLE_VAULT'


def is_encrypted(data):
  """Tests if this is a vault encrypted data blob.

  Args:
    data: A byte or text string to test whether it is recognized as vault
      encrypted data.
  Returns:
    True if it is recognized. Otherwise, False.
  """
  try:
    b_data = to_bytes(data, encoding='ascii', errors='strict')
  except (UnicodeError, TypeError):
    return False

  return b_data.startswith(b_HEADER)


def format_vaulttext_envelope(b_ciphertext, cipher_name, version=None,
                              vault_id=None):
  """Adds header and format to 80 columns.

  Args:
    b_ciphertext: The encrypted and hexlified data as a byte string.
    cipher_name: Cipher name (for ex, 'AES256').
    version: Vault version (for ex, '1.2'). Optional ('1.1' is default).
    vault_id: Vault identifier. If provided, the version will be bumped to 1.2.
  Returns:
    A byte str that should be dumped into a file. It's formatted to 80 char
    columns and has the header prepended.
  """

  if not cipher_name:
    raise AnsibleVaultError('The cipher must be set before adding a header')

  version = version or '1.1'

  # If we specify a vault_id, use format version 1.2.
  if vault_id and vault_id != 'default':
    version = '1.2'

  b_version = to_bytes(version, 'utf-8', errors='strict')
  b_vault_id = to_bytes(vault_id, 'utf-8', errors='strict')
  b_cipher_name = to_bytes(cipher_name, 'utf-8', errors='strict')

  header_parts = [b_HEADER,
                  b_version,
                  b_cipher_name]

  if b_version == b'1.2' and b_vault_id:
    header_parts.append(b_vault_id)

  header = b';'.join(header_parts)

  b_vaulttext = [header]
  b_vaulttext += [b_ciphertext[i:i + 80]
                  for i in range(0, len(b_ciphertext), 80)]
  b_vaulttext += [b'']
  b_vaulttext = b'\n'.join(b_vaulttext)

  return b_vaulttext


def _parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id=None):
  b_tmpdata = b_vaulttext_envelope.splitlines()
  b_tmpheader = b_tmpdata[0].strip().split(b';')

  b_version = b_tmpheader[1].strip()
  cipher_name = to_text(b_tmpheader[2].strip())
  vault_id = default_vault_id

  if len(b_tmpheader) >= 4:
    vault_id = to_text(b_tmpheader[3].strip())

  b_ciphertext = b''.join(b_tmpdata[1:])

  return b_ciphertext, b_version, cipher_name, vault_id


def parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id=None,
                             filename=None):
  """Parses the vaulttext envelope.

  When data is saved, it has a header prepended and is formatted into 80
  character lines. This method extracts the information from the header
  and then removes the header and the inserted newlines. The string returned
  is suitable for processing by the Cipher classes.

  Args:
    b_vaulttext: A byte str containing the data from a save file.
    default_vault_id: The vault_id name to use if the vaulttext does not provide
        one.
    filename: The filename that the data came from. This is only
        used to make better error messages in case the data cannot be
        decrypted. This is optional.
  Returns:
    A tuple of byte str of the vaulttext suitable to pass to parse_vaultext,
      a byte str of the vault format version, the name of the cipher used, and
      the vault_id.
  """
  # used by decrypt
  default_vault_id = default_vault_id or DEFAULT_VAULT_IDENTITY

  try:
    return _parse_vaulttext_envelope(b_vaulttext_envelope, default_vault_id)
  except Exception as exc:
    msg = 'Vault envelope format error'
    if filename:
      msg += f' in {filename}'
    msg += f': {exc}'
    raise AnsibleVaultFormatError(msg)


class VaultLib:
  """Main vault class."""

  def __init__(self, secrets=None):
    self.secrets = secrets or []
    self.cipher_name = None
    self.b_version = b'1.2'

  def encrypt(self, plaintext, secret=None, vault_id=None):
    """Vault encrypt a piece of data.

    Args:
      plaintext: A text or byte string to encrypt. If the string passed in is a
          text string, it will be encoded to UTF-8 before encryption.
      secret: A secret to use to encrypt. If none, a default will be used from
          this class.
      vault_id: The vault ID to use.
    Returns:
      A utf-8 encoded byte str of encrypted data. The string contains a header
      identifying this as vault encrypted data and formatted to newline
      terminated lines of 80 characters. This is suitable for dumping as is to
      a vault file.
    """
    if secret is None:
      if self.secrets:
        _, secret = self.secrets[0]
      else:
        raise AnsibleVaultError(
            'A vault password must be specified to encrypt data')

    b_plaintext = to_bytes(plaintext)

    if is_encrypted(b_plaintext):
      raise AnsibleVaultError('input is already encrypted')

    if not self.cipher_name:
      self.cipher_name = 'AES256'

    try:
      cipher = CIPHERS[self.cipher_name]()
    except KeyError:
      raise AnsibleVaultError(f'{self.cipher_name} cipher could not be found')

    # encrypt data
    if vault_id:
      LOGGER.debug(
          f'Encrypting with vault_id \'{vault_id}\' and vault secret {secret}')
    else:
      LOGGER.debug(
        f'Encrypting without a vault_id using vault secret {secret}')

    b_ciphertext = cipher.encrypt(b_plaintext, secret)

    # format the data for output to the file
    b_vaulttext = format_vaulttext_envelope(b_ciphertext,
                                            self.cipher_name,
                                            vault_id=vault_id)
    return b_vaulttext

  def decrypt(self, vaulttext, filename=None, obj=None):
    """Decrypts a piece of vault encrypted data.

    Args:
      vaulttext: A string to decrypt. Since vault encrypted data is an
          ascii text format this can be either a byte str or unicode string.
      filename: A filename that the data came from. This is only
          used to make better error messages in case the data cannot be
          decrypted.
    Returns:
      A byte string containing the decrypted data.
    """
    plaintext, vault_id, vault_secret = self.decrypt_and_get_vault_id(
        vaulttext,
        filename=filename,
        obj=obj)
    return plaintext

  def decrypt_and_get_vault_id(self, vaulttext, filename=None, obj=None):
    """Decrypt a piece of vault encrypted data.

    Args:
      vaulttext: A string to decrypt. Since vault encrypted data is an
          ascii text format this can be either a byte str or unicode string.
      filename: A filename that the data came from. This is only
          used to make better error messages in case the data cannot be
          decrypted.
    Returns:
      A byte string containing the decrypted data, and the vault-id and
      vault-secret that were used.
    """
    b_vaulttext = to_bytes(vaulttext, errors='strict', encoding='utf-8')

    if self.secrets is None:
      raise AnsibleVaultError(
          'A vault password must be specified to decrypt data')

    if not is_encrypted(b_vaulttext):
      msg = 'input is not vault encrypted data. '
      if filename:
        msg += f'{filename} is not a vault encrypted file'
      raise AnsibleVaultError(msg)

    b_vaulttext, _, cipher_name, vault_id = parse_vaulttext_envelope(
        b_vaulttext,
        filename=filename)

    cipher = CIPHERS[cipher_name]()

    b_plaintext = None

    if not self.secrets:
      raise AnsibleVaultError(
          'Attempting to decrypt but no vault secrets found')

    vault_secrets = []
    vault_id_used = None
    vault_secret_used = None
    
    if vault_id:
      LOGGER.debug(f'Found a vault_id ({vault_id}) in the vaulttext')
      for vault_secret in self.secrets:
        if vault_id == vault_secret[0]:
          vault_secrets.append(vault_secret)
      if vault_secrets:
        LOGGER.debug(
            f'We have a secret associated with vault id ({vault_id})'
            f', will try to use to decrypt {filename}')
      else:
        LOGGER.debug(
          f'Found a vault_id ({vault_id}) in the vault text, '
          'but we do not have a associated secret.')

      # add the rest of the other secrets
      for vault_secret in self.secrets:
        if vault_id != vault_secret[0]:
          vault_secrets.append(vault_secret)
    else:
      vault_secrets = self.secrets

    for vault_secret_id, vault_secret in vault_secrets:
      LOGGER.debug(
          f'Trying to use vault secret=({vault_secret}) '
          f'id={vault_secret_id} to decrypt {filename}')

      try:
        b_plaintext = cipher.decrypt(b_vaulttext, vault_secret)
        if b_plaintext is not None:
          vault_id_used = vault_secret_id
          vault_secret_used = vault_secret
          file_slug = ''
          if filename:
            file_slug = f' of "{filename}"'
          LOGGER.debug(
              f'Decrypt{file_slug} successful with '
              f'secret={vault_secret} and '
              f'vault_id={vault_secret_id}')
          break
      except AnsibleVaultFormatError as exc:
        exc.obj = obj
        msg = 'There was a vault format error'
        if filename:
          msg += f' in {filename}'
        msg += f': {exc}'
        LOGGER.warning(msg)
        raise
      except AnsibleVaultError as exc:
        LOGGER.debug(
            f'Tried to use the vault secret ({vault_secret_id}) to '
            f'decrypt ({filename}) but it failed. Error: {exc}')
        continue
    else:
      msg = 'Decryption failed (no vault secrets were found that could decrypt)'
      if filename:
        msg += f' on {filename}'
      raise AnsibleVaultError(msg)

    if b_plaintext is None:
      msg = 'Decryption failed'
      if filename:
        msg += f' on {filename}'
      raise AnsibleVaultError(msg)

    return b_plaintext, vault_id_used, vault_secret_used


class VaultEditor:
  def __init__(self, vault=None):
    self.vault = vault or VaultLib()

  def _edit_file_helper(self, filename, secret, existing_data=None,
                        force_save=False, vault_id=None):

    # Create a tempfile
    root, ext = os.path.splitext(os.path.realpath(filename))
    fd, tmp_path = tempfile.mkstemp(suffix=ext)

    cmd = self._editor_shell_command(tmp_path)
    try:
      if existing_data:
        self.write_data(existing_data, fd)
    except Exception:
      # if an error happens, destroy the decrypted file
      os.remove(tmp_path)
      raise
    finally:
      os.close(fd)

    try:
      # drop the user into an editor on the tmp file
      subprocess.call(cmd)
    except Exception as exc:
      # if an error happens, destroy the decrypted file
      os.remove(tmp_path)
      raise AnsibleVaultError(
          f'Unable to execute the command "{" ".join(cmd)}": {exc}')

    b_tmpdata = self.read_data(tmp_path)

    # Do nothing if the content has not changed
    if force_save or existing_data != b_tmpdata:

      # encrypt new data and write out to tmp
      # An existing vaultfile will always be UTF-8,
      # so decode to unicode here
      b_ciphertext = self.vault.encrypt(b_tmpdata, secret, vault_id=vault_id)
      self.write_data(b_ciphertext, tmp_path)

      # shuffle tmp file into place
      self.shuffle_files(tmp_path, filename)
      LOGGER.debug(
          f'Saved edited file "{filename}" encrypted using {secret} and '
          f'vault id "{vault_id}"')

    if os.path.isfile(tmp_path):
      os.remove(tmp_path)

  def _real_path(self, filename):
    # '-' is special to VaultEditor, dont expand it.
    if filename == '-':
      return filename

    real_path = os.path.realpath(filename)
    return real_path

  def encrypt_bytes(self, b_plaintext, secret, vault_id=None):
    return self.vault.encrypt(b_plaintext, secret, vault_id=vault_id)

  def encrypt_file(self, filename, secret, vault_id=None, output_file=None):
    # A file to be encrypted into a vaultfile could be any encoding
    # so treat the contents as a byte string.

    filename = self._real_path(filename)

    b_plaintext = self.read_data(filename)
    b_ciphertext = self.vault.encrypt(b_plaintext, secret, vault_id=vault_id)
    self.write_data(b_ciphertext, output_file or filename)

  def decrypt_file(self, filename, output_file=None):
    filename = self._real_path(filename)

    ciphertext = self.read_data(filename)

    try:
      plaintext = self.vault.decrypt(ciphertext, filename=filename)
    except AnsibleVaultError as exc:
      raise AnsibleVaultError(f'{exc} for {filename}')
    self.write_data(plaintext, output_file or filename)

  def create_file(self, filename, secret, vault_id=None):
    """ create a new encrypted file """

    dirname = os.path.dirname(filename)
    if dirname and not os.path.exists(dirname):
      LOGGER.warning(f'{dirname} does not exist, creating...')
      os.makedirs(dirname)

    if os.path.isfile(filename):
      raise AnsibleVaultError(f'{filename} exists, please use \'edit\' instead')

    self._edit_file_helper(filename, secret, vault_id=vault_id)

  def edit_file(self, filename):
    vault_id_used = None
    vault_secret_used = None

    filename = self._real_path(filename)

    b_vaulttext = self.read_data(filename)

    # vault or yaml files are always utf8
    vaulttext = to_text(b_vaulttext)

    try:
      plaintext, vault_id_used, vault_secret_used = (
          self.vault.decrypt_and_get_vault_id(vaulttext))
    except AnsibleVaultError as exc:
      raise AnsibleVaultError(f'{exc} for {filename}')

    # Figure out the vault id from the file, to select the right secret to
    # re-encrypt it (duplicates parts of decrypt, but alas...)
    _, _, cipher_name, vault_id = parse_vaulttext_envelope(b_vaulttext,
                                                           filename=filename)

    # vault id here may not be the vault id actually used for decrypting
    # as when the edited file has no vault-id but is decrypted by non-default id
    # in secrets (vault_id=default, while a different vault-id decrypted)

    # we want to get rid of files encrypted with the AES cipher
    force_save = (cipher_name not in CIPHERS)

    # Keep the same vault-id (and version) as in the header
    self._edit_file_helper(filename, vault_secret_used, existing_data=plaintext,
                           force_save=force_save, vault_id=vault_id)

  def plaintext(self, filename):
    b_vaulttext = self.read_data(filename)
    vaulttext = to_text(b_vaulttext)

    try:
      plaintext = self.vault.decrypt(vaulttext, filename=filename)
      return plaintext
    except AnsibleVaultError as exc:
      raise AnsibleVaultError(f'{exc} for {filename}')

  def rekey_file(self, filename, new_vault_secret, new_vault_id=None):
    filename = self._real_path(filename)

    b_vaulttext = self.read_data(filename)
    vaulttext = to_text(b_vaulttext)

    LOGGER.debug(
        f'Rekeying file "{filename}" to with new vault-id "{new_vault_id}" and '
        f'vault secret {new_vault_secret}')
    try:
      plaintext, vault_id_used, _ = self.vault.decrypt_and_get_vault_id(
          vaulttext)
    except AnsibleVaultError as exc:
      raise AnsibleVaultError(f'{exc} for {filename}')

    if new_vault_secret is None:
      raise AnsibleVaultError(
          f'The value for the new_password to rekey {filename} with is not '
          'valid')

    new_vault = VaultLib()
    b_new_vaulttext = new_vault.encrypt(plaintext, new_vault_secret,
                                        vault_id=new_vault_id)

    self.write_data(b_new_vaulttext, filename)

    LOGGER.debug(
        f'Rekeyed file "{filename}" (decrypted with vault id "{vault_id_used}")'
        f' was encrypted with new vault-id "{new_vault_id}" and vault secret '
        f'{new_vault_secret}')

  def read_data(self, filename):
    try:
      if filename == '-':
        data = sys.stdin.buffer.read()
      else:
        with open(filename, 'rb') as fp:
          data = fp.read()
    except Exception as exc:
      msg = str(exc)
      if not msg:
        msg = repr(exc)
      raise AnsibleVaultError(f'Unable to read source file ({filename}): {msg}')

    return data

  def write_data(self, data, thefile):
    """Write the data bytes to given path.

    This is used to write a byte string to a file or stdout. It is used for
    writing the results of vault encryption or decryption. It is used for
    saving the ciphertext after encryption and it is also used for saving the
    plaintext after decrypting a vault. The type of the 'data' arg should be
    bytes, since in the plaintext case, the original contents can be of any text
    encoding or arbitrary binary data.

    When used to write the result of vault encryption, the val of the 'data' arg
    should be a utf-8 encoded byte string and not a text type.

    Args:
      data: The byte string (bytes) data.
      thefile: File descriptor or filename to save 'data' to.
    Returns:
      None
    """
    b_file_data = to_bytes(data, errors='strict')

    # check if we have a file descriptor instead of a path
    is_fd = isinstance(thefile, int)

    if is_fd:
      # if passed descriptor, use that to ensure secure access, otherwise it is
      # a string.
      # assumes the fd is securely opened by caller (mkstemp)
      os.ftruncate(thefile, 0)
      os.write(thefile, b_file_data)
    elif thefile == '-':
      # get a ref to sys.stdout.buffer
      # We need sys.stdout.buffer so we can write bytes to it since the
      # plaintext of the vaulted object could be anything/binary/etc
      sys.stdout.buffer.write(b_file_data)
    else:
      with open(thefile, 'wb') as fp:
        fp.write(b_file_data)

  def shuffle_files(self, src, dest):
    prev = None
    # overwrite dest with src
    if os.path.isfile(dest):
      os.remove(dest)
    shutil.move(src, dest)

  def _editor_shell_command(self, filename):
    env_editor = os.environ.get('EDITOR', DEFAULT_EDITOR)
    editor = shlex.split(env_editor)
    editor.append(filename)

    return editor
