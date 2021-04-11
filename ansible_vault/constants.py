import collections.abc
import configparser
import os
import os.path

from .exceptions import AnsibleVaultError


DEFS = {
    'DEFAULT_VAULT_IDENTITY': {
        'default': 'default',
        'env': ['ANSIBLE_VAULT_IDENTITY'],
        'ini': [{'key': 'vault_identity', 'section': 'defaults'}],
    },
    'DEFAULT_VAULT_ENCRYPT_IDENTITY': {
        'default': None,
        'env': ['ANSIBLE_VAULT_ENCRYPT_IDENTITY'],
        'ini': [{'key': 'vault_encrypt_identity', 'section': 'defaults'}],
    },
    'DEFAULT_VAULT_IDENTITY_LIST': {
        'default': [],
        'env': ['ANSIBLE_VAULT_IDENTITY_LIST'],
        'ini': [{'key': 'vault_identity_list', 'section': 'defaults'}],
        'type': 'list',
    },
    'DEFAULT_VAULT_PASSWORD_FILE': {
        'default': None,
        'env': ['ANSIBLE_VAULT_PASSWORD_FILE'],
        'ini': [{'key': 'vault_password_file', 'section': 'defaults'}],
        'type': 'path',
    },
}


def find_ini_config_file():
  """Load INI Config File order.

  first found is used: ENV, CWD, HOME, /etc/ansible
  """
  # A value that can never be a valid path so that we can tell if ANSIBLE_CONFIG
  # was set later
  # We can't use None because we could set path to None.
  SENTINEL = object()

  potential_paths = []

  # Environment setting
  path_from_env = os.getenv('ANSIBLE_CONFIG', SENTINEL)
  if path_from_env is not SENTINEL:
    if os.path.isdir(path_from_env):
      path_from_env = os.path.join(path_from_env, 'ansible.cfg')
    potential_paths.append(path_from_env)

  # Current working directory
  try:
    cwd = os.getcwd()
    cwd_cfg = os.path.join(cwd, 'ansible.cfg')
    potential_paths.append(cwd_cfg)
  except OSError:
    # If we can't access cwd, we'll simply skip it as a possible config source
    pass

  # Per user location
  potential_paths.append(os.path.expanduser('~/.ansible.cfg'))

  # System location
  potential_paths.append('/etc/ansible/ansible.cfg')

  for path in potential_paths:
    if os.path.exists(path) and os.access(path, os.R_OK):
      break
  else:
    path = None

  return path


def parse_config_file(cfile):
  """return flat configuration settings from file(s)"""
  kwargs = {}
  kwargs['inline_comment_prefixes'] = (';',)
  parser = configparser.ConfigParser(inline_comment_prefixes=(';',))
  try:
    with open(cfile, 'r') as fp:
      parser.read_file(fp, cfile)
  except configparser.Error as exc:
    raise AnsibleVaultError(
        f'Error reading config file ({cfile}): {exc}')
  return parser


def ensure_type(value, value_type):
  """Returns a configuration variable with casting.

  Args:
    value: The value to ensure correct typing of.
    value_type: The type of the value.  This can be any of the following
        strings:
        boolean: Sets the value to a True or False value.
        bool: Same as 'boolean'.
        integer: Sets the value to an integer or raises a ValueType error.
        int: Same as 'integer'.
        float: Sets the value to a float or raises a ValueType error.
        list: Treats the value as a comma separated list. Split the value
            and return it as a python list.
        none: Sets the value to None.
        path: Expands any environment variables and tilde's in the value.
        str: Sets the value to string types.
        string: Same as 'str'.
  """
  errmsg = None

  if value_type:
    value_type = value_type.lower()

  if value is not None:
    if value_type in ('boolean', 'bool'):
      if isinstance(value, (str, bytes)):
        value = value.lower()
      value = value.lower() in ('y', 'yes', 'on', '1', 'true', 't', 1, 1.0, True)

    elif value_type in ('integer', 'int'):
      value = int(value)

    elif value_type == 'float':
      value = float(value)

    elif value_type == 'list':
      if isinstance(value, str):
        value = [x.strip() for x in value.split(',')]
      elif not isinstance(value, collections.abc.Sequence):
        errmsg = 'list'

    elif value_type == 'none':
      if value == "None":
        value = None

      if value is not None:
        errmsg = 'None'

    elif value_type == 'path':
      if isinstance(value, str):
        value = os.path.expanduser(value)
      else:
        errmsg = 'path'

    elif value_type in ('str', 'string'):
      if isinstance(value, str):
        pass
      else:
        errmsg = 'string'

    if errmsg:
      raise ValueError(f'Invalid type provided for "{errmsg}": {value}')

  return value


def get_config_value(config, parser=None):
  """Given a config key figure out the actual value."""
  value = None

  for env_name in DEFS[config].get('env', []):
    temp_value = os.environ.get(env_name, None)
    if temp_value is not None:
      value = temp_value

  if value is None and parser:
    for entry in DEFS[config].get('ini', []):
      try:
        temp_value = parser.get(entry.get('section', 'defaults'),
                                entry.get('key', ''),
                                raw=True)
      except Exception:
        pass
      else:
        if temp_value is not None:
          value = temp_value

  if value is None:
    value = DEFS[config].get('default')

  # ensure correct type, can raise exceptions on mismatched types
  try:
    value = ensure_type(value, DEFS[config].get('type'))
  except ValueError as exc:
    raise AnsibleVaultError(
        f'Invalid type for configuration option {config}: {exc}')

  return value

cfile = find_ini_config_file()
if cfile:
  parser = parse_config_file(cfile)
else:
  parser = None

for var in DEFS:
  value = get_config_value(var, parser)
  globals()[var] = value
