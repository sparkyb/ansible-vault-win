Description
-----------

Although Ansible only works on POSIX, you may want to edit your inventories and
playbooks on Windows. This is a problem if you use any files or values encrypted
with Ansible Vault. It may be a pain to find a separate POSIX machine just to
run the ansible-vault CLI to encrypt/decrypt these vault files. This is an
OS-independent port of a simplified version of just the ansible-vault CLI so
that you can work with these encrypted files on Windows.

See the [ansible-vault][] docs for more info.

[ansible-vault]: https://docs.ansible.com/ansible/latest/cli/ansible-vault.html
