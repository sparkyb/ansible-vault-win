class AnsibleVaultError(Exception):
  pass


class AnsibleVaultPasswordError(AnsibleVaultError):
  pass


class AnsibleVaultFormatError(AnsibleVaultError):
  pass
