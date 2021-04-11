import getpass
import logging
import os
import os.path
import platform
import shlex
import stat
import subprocess

from .exceptions import AnsibleVaultError
from .exceptions import AnsibleVaultPasswordError
from .utils import to_bytes


__all__ = ['PromptVaultSecret', 'get_file_vault_secret']


LOGGER = logging.getLogger(__name__)


def verify_secret_is_not_empty(secret, msg=None):
  """Check the secret against minimal requirements.

  Currently, only requirement is that the password is not None or an empty
  string.

  Raises:
    AnsibleVaultPasswordError: If the password does not meet requirements.
  """
  msg = msg or 'Invalid vault password was provided'
  if not secret:
    raise AnsibleVaultPasswordError(msg)


class VaultSecret:
  """Opaque objects for a single vault secret. i.e., a password or a key."""

  def __init__(self, _bytes=None):
    self._bytes = _bytes

  @property
  def bytes(self):
    """The secret as a bytestring.

    Sub classes that store text types will need to override to encode the text
    to bytes.
    """
    return self._bytes

  def load(self):
    return self._bytes


class PromptVaultSecret(VaultSecret):
  default_prompt_formats = ['Vault password ({vault_id}): ']

  def __init__(self, _bytes=None, vault_id=None, prompt_formats=None):
    super().__init__(_bytes)
    self.vault_id = vault_id

    if prompt_formats is None:
      self.prompt_formats = self.default_prompt_formats
    else:
      self.prompt_formats = prompt_formats

  def load(self):
    self._bytes = self.ask_vault_passwords()

  def ask_vault_passwords(self):
    b_vault_passwords = []

    for prompt_format in self.prompt_formats:
      msg = prompt_format.format(vault_id=self.vault_id)
      vault_pass = getpass.getpass(msg)

      verify_secret_is_not_empty(vault_pass)

      b_vault_pass = to_bytes(vault_pass).strip()
      b_vault_passwords.append(b_vault_pass)

    # Make sure the passwords match by comparing them all to the first password
    for b_vault_password in b_vault_passwords:
      self.confirm(b_vault_passwords[0], b_vault_password)

    if b_vault_passwords:
      return b_vault_passwords[0]

    return None

  def confirm(self, b_vault_pass_1, b_vault_pass_2):
    # enforce no newline chars at the end of passwords

    if b_vault_pass_1 != b_vault_pass_2:
      raise AnsibleVaultError('Passwords do not match')


def is_executable(filename):
  """Checks if a file is executable.

  On Windows this requires using bash and runs a test.
  """
  if platform.system() == 'Windows':
    cmd = ['test', '-x', filename]
    try:
      p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
      # Must not have test and so we can't check
      return False
    else:
      p.communicate()
      return p.returncode == 0
  else:
    return ((stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) &
            os.stat(filename)[stat.ST_MODE])


def script_is_client(filename):
  """Determine if a vault secret script is a client script"""

  # if password script is 'something-client' or 'something-client.[sh|py|rb|etc]'
  # script_name can still have '.' or could be entire filename if there is no ext
  script_name, _ = os.path.splitext(filename)

  return script_name.endswith('-client')


def get_file_vault_secret(filename=None, vault_id=None, encoding=None):
  this_path = os.path.realpath(os.path.expanduser(filename))

  if not os.path.exists(this_path):
    raise AnsibleVaultError(
        f'The vault password file {this_path} was not found')

  if is_executable(this_path):
    if script_is_client(filename):
      LOGGER.debug(
          f'The vault password file {filename} is a client script.')
      return ClientScriptVaultSecret(filename=this_path, vault_id=vault_id,
                                     encoding=encoding)
    # just a plain vault password script. No args, returns a byte array
    return ScriptVaultSecret(filename=this_path, encoding=encoding)

  return FileVaultSecret(filename=this_path, encoding=encoding)


class FileVaultSecret(VaultSecret):
  def __init__(self, filename=None, encoding=None, loader=None):
    super().__init__()
    self.filename = filename

    self.encoding = encoding or 'utf8'

    self._bytes = None
    self._text = None

  @property
  def bytes(self):
    if self._bytes:
      return self._bytes
    if self._text:
      return self._text.encode(self.encoding)
    return None

  def load(self):
    self._bytes = self._read_file()

  def _read_file(self):
    """Reads a vault password from a file."""

    try:
      with open(self.filename, 'rb') as fp:
        vault_pass = fp.read().strip()
    except OSError as exc:
      raise AnsibleVaultError(
          f'Could not read vault password file {self.filename}: {exc}')

    # TODO: support vault-encrypted vault password files
    ## b_vault_data, _ = self.loader._decrypt_if_vault_data(vault_pass, self.filename)
    ## vault_pass = b_vault_data.strip(b'\r\n')

    verify_secret_is_not_empty(
        vault_pass,
        msg=f'Invalid vault password was provided from file ({self.filename})')

    return vault_pass

  def __repr__(self):
    if self.filename:
      return f'{type(self).__name__}(filename={self.filename!r})'
    return f'{type(self).__name__}()'


class ScriptVaultSecret(FileVaultSecret):
  def _read_file(self):
    if not is_executable(self.filename):
      raise AnsibleVaultError(
          f'The vault password script {self.filename} was not executable')

    command = self._build_command()

    if platform.system() == 'Windows':
      command = ['sh', '-c', ' '.join(command)]

    stdout, stderr, p = self._run(command)

    self._check_results(stdout, stderr, p)

    vault_pass = stdout.strip(b'\r\n')

    verify_secret_is_not_empty(
        vault_pass,
        msg=('Invalid vault password was provided from script '
             f'({self.filename})'))

    return vault_pass

  def _run(self, command):
    try:
      # STDERR not captured to make it easier for users to prompt for input in
      # their scripts
      proc = subprocess.Popen(command, stdout=subprocess.PIPE)
    except OSError as exc:
      raise AnsibleVaultError(
          f'Problem running vault password script {self.filename} ({exc}). '
          'If this is not a script, remove the executable bit from the file.')

    stdout, stderr = proc.communicate()
    return stdout, stderr, proc

  def _check_results(self, stdout, stderr, proc):
    if proc.returncode != 0:
      raise AnsibleVaultError(
          f'Vault password script {self.filename} returned non-zero '
          f'({proc.returncode}): {stderr}')

  def _build_command(self):
    if platform.system() == 'Windows':
      return [f'`cygpath {shlex.quote(self.filename)}`']
    else:
      return [self.filename]


class ClientScriptVaultSecret(ScriptVaultSecret):
  VAULT_ID_UNKNOWN_RC = 2

  def __init__(self, filename=None, encoding=None, vault_id=None):
    super().__init__(filename=filename, encoding=encoding)
    self._vault_id = vault_id
    LOGGER.debug('Executing vault password client script: '
                 f'{filename} --vault-id {vault_id}')

  def _run(self, command):
    try:
      proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    except OSError as exc:
      raise AnsibleVaultError(
          f'Problem running vault password script {self.filename} ({exc}). '
          'If this is not a script, remove the executable bit from the file.')

    stdout, stderr = proc.communicate()
    return stdout, stderr, proc

  def _check_results(self, stdout, stderr, proc):
    if popen.returncode == self.VAULT_ID_UNKNOWN_RC:
      raise AnsibleVaultError(
          f'Vault password client script {self.filename} did not find a '
          f'secret for vault-id={self._vault_id}: {stderr}')

    if popen.returncode != 0:
      raise AnsibleVaultError(
          f'Vault password client script {self.filename} returned non-zero '
          f'({proc.returncode}) when getting secret for '
          f'vault-id={self._vault_id}: {stderr}')

  def _build_command(self):
    command = super()._build_command()
    if self._vault_id:
      command.extend(['--vault-id', self._vault_id])

    return command

  def __repr__(self):
    if self.filename:
      return (f'{type(self).__name__}(filename={self.filename!r}, '
              'vault_id={self._vault_id!r})')
    return f'{type(self).__name__}()'
