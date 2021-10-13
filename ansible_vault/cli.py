import argparse
import getpass
import logging
import os
import os.path
import platform
import subprocess
import sys

from ansible_vault.constants import DEFAULT_VAULT_IDENTITY
from ansible_vault.constants import DEFAULT_VAULT_ENCRYPT_IDENTITY
from ansible_vault.constants import DEFAULT_VAULT_IDENTITY_LIST
from ansible_vault.constants import DEFAULT_VAULT_PASSWORD_FILE
from ansible_vault.exceptions import AnsibleVaultError, AnsibleVaultOptionsError
from ansible_vault.secrets import PromptVaultSecret, get_file_vault_secret
from ansible_vault.utils import to_bytes, to_text
from ansible_vault.vault import VaultLib, VaultEditor


LESS_OPTS = 'FRSX'


def build_vault_ids(vault_ids, vault_password_files=None,
                    ask_vault_pass=None, create_new_password=None,
                    auto_prompt=True):
  vault_password_files = vault_password_files or []
  vault_ids = vault_ids or []

  # convert vault_password_files into vault_ids slugs
  for password_file in vault_password_files:
    vault_ids.append(f'{DEFAULT_VAULT_IDENTITY}@{password_file}')

  # if an action needs an encrypt password (create_new_password=True) and we
  # don't have other secrets setup, then automatically add a password prompt as
  # well.
  if ask_vault_pass or (not vault_ids and auto_prompt):
    vault_ids.append(f'{DEFAULT_VAULT_IDENTITY}@prompt_ask_vault_pass')

  return vault_ids


def split_vault_id(vault_id):
  # return (before_@, after_@)
  # if no @, return whole string as after_
  if '@' not in vault_id:
    return (None, vault_id)

  parts = vault_id.split('@', 1)
  ret = tuple(parts)
  return ret


def setup_vault_secrets(vault_ids, vault_password_files=None,
                        ask_vault_pass=None, create_new_password=False,
                        auto_prompt=True):
  # list of tuples
  vault_secrets = []

  vault_password_files = vault_password_files or []
  if DEFAULT_VAULT_PASSWORD_FILE:
    vault_password_files.append(DEFAULT_VAULT_PASSWORD_FILE)

  vault_ids = build_vault_ids(
      vault_ids,
      vault_password_files,
      ask_vault_pass,
      create_new_password,
      auto_prompt=auto_prompt)

  for vault_id_slug in vault_ids:
    vault_id_name, vault_id_value = split_vault_id(vault_id_slug)
    if vault_id_value in ['prompt', 'prompt_ask_vault_pass']:
      vault_id_name = vault_id_name or DEFAULT_VAULT_IDENTITY
      if create_new_password:
        prompt_formats = [
            'New vault password ({vault_id}): ',
            'Confirm new vault password ({vault_id}): ',
        ]
      else:
        prompt_formats = [
            'Vault password ({vault_id}): ',
        ]

      prompted_vault_secret = PromptVaultSecret(
          prompt_formats=prompt_formats,
          vault_id=vault_id_name)

      # a empty or invalid password from the prompt will warn and continue to
      # the next without erroring globally
      try:
        prompted_vault_secret.load()
      except AnsibleVaultError as exc:
        logging.warning(
            f'Error in vault password prompt ({vault_id_name}): {exc}')
        raise
      vault_secrets.append((vault_id_name, prompted_vault_secret))
    else:
      # assuming anything else is a password file
      logging.debug(f'Reading vault password file: {vault_id_value}')

      # read vault_pass from a file
      file_vault_secret = get_file_vault_secret(filename=vault_id_value,
                                                vault_id=vault_id_name)

      # an invalid password file will error globally
      try:
        file_vault_secret.load()
      except AnsibleVaultError as exc:
        logging.warning(
            f'Error in vault password file loading ({vault_id_name}): {exc}')
        raise

      vault_secrets.append((vault_id_name or DEFAULT_VAULT_IDENTITY,
                            file_vault_secret))

  return vault_secrets


def pager(text):
  """Finds a reasonable way to display text"""
  if not sys.stdout.isatty():
    print(text)
  elif 'PAGER' in os.environ:
    pager_pipe(text, os.environ['PAGER'])
  else:
    p = subprocess.Popen('less --version', shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.communicate()
    if p.returncode == 0:
      pager_pipe(text, 'less')
    else:
      print(text)


def pager_pipe(text, cmd):
  """Pipe text through a pager."""
  if 'LESS' not in os.environ:
    os.environ['LESS'] = LESS_OPTS
  try:
    cmd = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                           stdout=sys.stdout)
    cmd.communicate(input=to_bytes(text))
  except OSError:
    pass
  except KeyboardInterrupt:
    pass


class VaultCli:
  def __init__(self):
    self.parser = argparse.ArgumentParser(
        description='encryption/decryption utility for Ansible data files',
        epilog=(f'\nSee \'{os.path.basename(sys.argv[0])} <command> --help\' '
                'for more information on a specific command.\n\n'))

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        '--vault-id',
        action='append',
        dest='vault_ids',
        default=[],
        help='the vault identity to use')
    group = common.add_mutually_exclusive_group()
    group.add_argument(
        '--ask-vault-password',
        '--ask-vault-pass',
        action='store_true',
        dest='ask_vault_pass',
        help='ask for vault password')
    group.add_argument(
        '--vault-password-file',
        '--vault-pass-file',
        action='append',
        dest='vault_password_files',
        default=[], 
        help='vault password file')

    output = argparse.ArgumentParser(add_help=False)
    output.add_argument(
        '--output',
        dest='output_file',
        default=None,
        help='output file name for encrypt or decrypt; use - for stdout')

    vault_id = argparse.ArgumentParser(add_help=False)
    vault_id.add_argument(
        '--encrypt-vault-id',
        default=[],
        help=('the vault id used to encrypt (required if more than one vault-id '
              'is provided)'))

    subparsers = self.parser.add_subparsers(dest='action')
    subparsers.required = True

    create_parser = subparsers.add_parser(
        'create',
        parents=[vault_id, common],
        help='Create new vault encrypted file')
    create_parser.add_argument('args', nargs='*', metavar='file_name',
                               help='Filename')
    create_parser.set_defaults(func=self.create)

    decrypt_parser = subparsers.add_parser(
        'decrypt',
        parents=[output, common],
        help='Decrypt vault encrypted file')
    decrypt_parser.add_argument('args', nargs='*', metavar='file_name',
                                help='Filename')
    decrypt_parser.set_defaults(func=self.decrypt)

    edit_parser = subparsers.add_parser(
        'edit',
        parents=[vault_id, common],
        help='Edit vault encrypted file')
    edit_parser.add_argument('args', nargs='*', metavar='file_name',
                             help='Filename')
    edit_parser.set_defaults(func=self.edit)

    view_parser = subparsers.add_parser(
        'view',
        parents=[common],
        help='View vault encrypted file')
    view_parser.add_argument('args', nargs='*', metavar='file_name',
                             help='Filename')
    view_parser.set_defaults(func=self.view)

    encrypt_parser = subparsers.add_parser(
        'encrypt',
        parents=[common, output, vault_id],
        help='Encrypt YAML file')
    encrypt_parser.add_argument('args', nargs='*', metavar='file_name',
                                help='Filename')
    encrypt_parser.set_defaults(func=self.encrypt)

    enc_str_parser = subparsers.add_parser(
        'encrypt_string',
        parents=[common, output, vault_id],
        help='Encrypt a string')
    enc_str_parser.add_argument('args', nargs='*', metavar='string_to_encrypt',
                                help='String to encrypt')
    enc_str_parser.add_argument(
        '-p',
        '--prompt',
        action='store_true',
        dest='encrypt_string_prompt',
        help='Prompt for the string to encrypt')
    enc_str_parser.add_argument(
        '--show-input',
        action='store_true',
        dest='show_string_input',
        help='Do not hide input when prompted for the string to encrypt')
    enc_str_parser.add_argument(
        '-n',
        '--name',
        action='append',
        dest='encrypt_string_names',
        help='Specify the variable name')
    enc_str_parser.add_argument(
        '--stdin-name',
        dest='encrypt_string_stdin_name',
        help='Specify the variable name for stdin')
    enc_str_parser.set_defaults(func=self.encrypt_string)

    rekey_parser = subparsers.add_parser(
        'rekey',
        parents=[common, vault_id],
        help='Re-key a vault encrypted file')
    rekey_new_group = rekey_parser.add_mutually_exclusive_group()
    rekey_new_group.add_argument(
        '--new-vault-password-file',
        help='new vault password file for rekey')
    rekey_new_group.add_argument(
        '--new-vault-id',
        help='the new vault identity to use for rekey')
    rekey_parser.add_argument('args', nargs='*', metavar='file_name',
                              help='Filename')
    rekey_parser.set_defaults(func=self.rekey)

  def run(self, args=None):
    self.options = self.parser.parse_args(args)
    self.args = getattr(self.options, 'args', [])
    action = self.options.action

    if self.options.vault_ids:
      for vault_id in self.options.vault_ids:
        if ';' in vault_id:
          self.parser.error(
              f'\'{vault_id}\' is not a valid vault id. The character \';\' is '
              'not allowed in vault ids')
    if (getattr(self.options, 'output_file', None) and
        len(self.args) > 1):
      self.parser.error(
          'At most one input file may be used with the --output option')
    if action == 'encrypt_string':
      self.options.encrypt_string_read_stdin = bool(
          '-' in self.args or not self.args or
          self.options.encrypt_string_stdin_name)

      # TODO: prompting from stdin and reading from stdin seem mutually exclusive,
      # but verify that.
      if (self.options.encrypt_string_prompt and
          self.options.encrypt_string_read_stdin):
        self.parser.error(
            'The --prompt option is not supported if also reading input from '
            'stdin')

    # there are 3 types of actions, those that just 'read' (decrypt, view) and
    # only need to ask for a password once, and those that 'write' (create,
    # encrypt) that ask for a new password and confirm it, and 'read/write (rekey)
    # that asks for the old password, then asks for a new one and confirms it.

    default_vault_ids = DEFAULT_VAULT_IDENTITY_LIST
    vault_ids = default_vault_ids + self.options.vault_ids

    if action in ['decrypt', 'view', 'rekey', 'edit']:
      vault_secrets = setup_vault_secrets(
          vault_ids=vault_ids,
          vault_password_files=self.options.vault_password_files,
          ask_vault_pass=self.options.ask_vault_pass)
      if not vault_secrets:
        self.parser.error('A vault password is required to use ansible-vault')
    if action in ['encrypt', 'encrypt_string', 'create']:
      encrypt_vault_id = None
      # no --encrypt-vault-id for 'edit'
      if action != 'edit':
        encrypt_vault_id = (self.options.encrypt_vault_id or
                            DEFAULT_VAULT_ENCRYPT_IDENTITY)

      vault_secrets = setup_vault_secrets(
         vault_ids=vault_ids,
         vault_password_files=self.options.vault_password_files,
         ask_vault_pass=self.options.ask_vault_pass,
         create_new_password=True)

      if len(vault_secrets) > 1 and not encrypt_vault_id:
        self.parser.error(
            'The vault-ids '
            f'{",".join(vault_id for vault_id, _ in vault_secrets)} '
            'are available to encrypt. Specify the vault-id to encrypt with '
            '--encrypt-vault-id')

      if not vault_secrets:
        self.parser.error('A vault password is required to use ansible-vault')

      if encrypt_vault_id:
        for vault_secret in vault_secrets:
          if vault_secret[0] == encrypt_vault_id:
            encrypt_secret = vault_secret
            break
        else:
          self.parser.error(
              'Did not find a match for '
              f'--encrypt-vault-id={encrypt_vault_id} in the known '
              f'vault-ids {[vault_id for vault_id, _ in vault_secrets]}')
      else:
        encrypt_secret = vault_secrets[0]

      self.encrypt_vault_id = encrypt_secret[0]
      self.encrypt_secret = encrypt_secret[1]
    if action == 'rekey':
      encrypt_vault_id = (self.options.encrypt_vault_id or
                          DEFAULT_VAULT_ENCRYPT_IDENTITY)

      new_vault_ids = []
      if encrypt_vault_id:
        new_vault_ids = default_vault_ids
      if self.options.new_vault_id:
        new_vault_ids.append(self.options.new_vault_id)

      new_vault_password_files = []
      if self.options.new_vault_password_file:
        new_vault_password_files.append(self.options.new_vault_password_file)

      new_vault_secrets = setup_vault_secrets(
         vault_ids=new_vault_ids,
         vault_password_files=new_vault_password_files,
         ask_vault_pass=self.options.ask_vault_pass,
         create_new_password=True)

      if not new_vault_secrets:
        self.parser.error(
            'A vault password is required to use ansible-vault rekey')

      if encrypt_vault_id:
        for vault_secret in new_vault_secrets:
          if vault_secret[0] == encrypt_vault_id:
            new_encrypt_secret = vault_secret
            break
        else:
          self.parser.error(
              'Did not find a match for '
              f'--encrypt-vault-id={encrypt_vault_id} in the known '
              'vault-ids '
              f'{[vault_id for vault_id, _ in new_vault_secrets]}')
      else:
        new_encrypt_secret = new_vault_secrets[0]

      self.new_encrypt_vault_id = new_encrypt_secret[0]
      self.new_encrypt_secret = new_encrypt_secret[1]

    self.vault = VaultLib(vault_secrets)
    self.editor = VaultEditor(self.vault)

    return self.options.func()

  def create(self):
    if len(self.args) != 1:
      self.parser.error(
          'ansible-vault create can take only one filename argument')

    self.editor.create_file(self.args[0], self.encrypt_secret,
                            vault_id=self.encrypt_vault_id)

  def decrypt(self):
    if not self.args and sys.stdin.isatty():
      print('Reading ciphertext input from stdin', file=sys.stderr)

    for f in self.args or ['-']:
      self.editor.decrypt_file(f, output_file=self.options.output_file)

    if sys.stdout.isatty():
      print('Decryption successful', file=sys.stderr)

  def edit(self):
    for f in self.args:
      self.editor.edit_file(f)

  def view(self):
    for f in self.args:
      plaintext = self.editor.plaintext(f)
      pager(to_text(plaintext))

  def encrypt(self):
    if not self.args and sys.stdin.isatty():
      print('Reading plaintext input from stdin', file=sys.stderr)

    for f in self.args or ['-']:
      self.editor.encrypt_file(f, self.encrypt_secret,
                               vault_id=self.encrypt_vault_id,
                               output_file=self.options.output_file)

    if sys.stdout.isatty():
      print('Encryption successful', file=sys.stderr)

  def encrypt_string(self):
    b_plaintext = None

    # Holds tuples (the_text, the_source_of_the_string, the variable name if its
    # provided).
    b_plaintext_list = []

    # We can prompt and read input, or read from stdin, but not both.
    if self.options.encrypt_string_prompt:
      msg = 'String to encrypt: '

      name = input('Variable name (enter for no name): ') or None

      # TODO: could prompt for which vault_id to use for each plaintext string
      #       currently, it will just be the default
      if self.options.show_string_input:
          prompt_response = input('String to encrypt: ')
      else:
          prompt_response = getpass.getpass('String to encrypt (hidden): ')

      if prompt_response == '':
        raise AnsibleVaultOptionsError(
            'The plaintext provided from the prompt was empty, not encrypting')

      b_plaintext = to_bytes(prompt_response)
      b_plaintext_list.append((b_plaintext, 'the interactive prompt', name))

    # read from stdin
    if self.options.encrypt_string_read_stdin:
      if sys.stdout.isatty():
        if platform.system() == 'Windows':
          eof_str = 'ctrl-z'
        else:
          eof_str = 'ctrl-d'
        print(
            f'Reading plaintext input from stdin. ({eof_str} to end input, twice '
            'if your content does not already have a newline)',
            file=sys.stderr)

      stdin_text = sys.stdin.read()
      if stdin_text == '':
        raise AnsibleVaultOptionsError('stdin was empty, not encrypting')

      if sys.stdout.isatty() and not stdin_text.endswith('\n'):
        print()

      b_plaintext = to_bytes(stdin_text)

      # defaults to None
      name = self.options.encrypt_string_stdin_name
      b_plaintext_list.append((b_plaintext, 'stdin', name))

    # remove the non-option '-' arg (used to indicate 'read from stdin') from
    # the candidate args so we don't add it to the plaintext list
    args = [x for x in self.args if x != '-']

    # use any leftover args as strings to encrypt
    # Try to match args up to --name options
    if self.options.encrypt_string_names:
      name_and_text_list = list(zip(self.options.encrypt_string_names, args))

      # Some but not enough --name's to name each var
      if len(args) > len(name_and_text_list):
        # Trying to avoid ever showing the plaintext in the output, so this
        # warning is vague to avoid that.
        print('The number of --name options do not match the number of args.',
              file=sys.stderr)
        print(
            f'The last named variable will be "{encrypt_string_names[-1]}". '
            'The rest will not have names.',
            file=sys.stderr)

      # Add the rest of the args without specifying a name
      for extra_arg in args[len(name_and_text_list):]:
        name_and_text_list.append((None, extra_arg))

    # if no --names are provided, just use the args without a name.
    else:
      name_and_text_list = [(None, x) for x in args]

    # Convert the plaintext text objects to bytestrings and collect
    for name_and_text in name_and_text_list:
      name, plaintext = name_and_text

      if plaintext == '':
        raise AnsibleVaultOptionsError(
            'The plaintext provided from the command line args was empty, not '
            'encrypting')

      b_plaintext = to_bytes(plaintext)
      b_plaintext_list.append((b_plaintext, 'the command line args', name))

    # Format the encrypted strings and any corresponding stderr output
    outputs = self.format_output_vault_strings(b_plaintext_list,
                                               vault_id=self.encrypt_vault_id)

    for output in outputs:
      err = output.get('err', None)
      out = output.get('out', '')
      if err:
        print(err, file=sys.stderr)
      print(out)

    if sys.stdout.isatty():
      print('Encryption successful', file=sys.stderr)

  def format_output_vault_strings(self, b_plaintext_list, vault_id=None):
    # If we are only showing one item in the output, we don't need to included
    # commented delimiters in the text
    show_delimiter = len(b_plaintext_list) > 1

    # list of dicts {'out': '', 'err': ''}
    output = []

    # Encrypt the plaintext, and format it into a yaml block that can be pasted
    # into a playbook.
    # For more than one input, show some differentiating info in the stderr
    # output so we can tell them apart. If we have a var name, we include that
    # in the yaml
    for index, b_plaintext_info in enumerate(b_plaintext_list):
      # (the text itself, which input it came from, its name)
      b_plaintext, src, name = b_plaintext_info

      b_ciphertext = self.editor.encrypt_bytes(b_plaintext, self.encrypt_secret,
                                               vault_id=vault_id)

      # block formatting
      yaml_text = self.format_ciphertext_yaml(b_ciphertext, name=name)

      err_msg = None
      if show_delimiter:
        human_index = index + 1
        if name:
          err_msg = (f'# The encrypted version of variable ("{name}", the '
                     'string #{human_index} from {src}).')
        else:
          err_msg = f('# The encrypted version of the string #{human_index} '
                      'from {src}.)')
      output.append({'out': yaml_text, 'err': err_msg})

    return output

  @staticmethod
  def format_ciphertext_yaml(b_ciphertext, indent=None, name=None):
    indent = indent or 10

    block_format_var_name = ''
    if name:
      block_format_var_name = f'{name}: '

    block_format_header = f'{block_format_var_name}!vault |'
    lines = []
    vault_ciphertext = to_text(b_ciphertext)

    lines.append(block_format_header)
    for line in vault_ciphertext.splitlines():
      lines.append('{}{}'.format(' ' * indent, line))

    yaml_ciphertext = '\n'.join(lines)
    return yaml_ciphertext

  def rekey(self):
    for f in self.args:
      self.editor.rekey_file(f, self.new_encrypt_secret,
                             self.new_encrypt_vault_id)

    print('Rekey successful', file=sys.stderr)


def main(args=None):
  cli = VaultCli()
  try:
    return cli.run(args)
  except AnsibleVaultOptionsError as exc:
    print(f'ERROR! {exc}', file=sys.stderr)
    return 5
  except AnsibleVaultError as exc:
    print(f'ERROR! {exc}', file=sys.stderr)
    return 1
  except KeyboardInterrupt:
    print('ERROR! User interrupted execution', file=sys.stderr)
    return 99
  except Exception as exc:
    print(f'ERROR! Unexpected Exception, this is probably a bug: {exc}',
          file=sys.stderr)
    return 250
