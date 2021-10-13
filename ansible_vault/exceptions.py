class AnsibleVaultError(Exception):
  pass


class AnsibleVaultOptionsError(AnsibleVaultError):
  pass


class AnsibleVaultPasswordError(AnsibleVaultError):
  pass


class AnsibleVaultFormatError(AnsibleVaultError):
  pass
