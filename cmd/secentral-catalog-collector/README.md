# SECentral SELinux Catalog Collector

This standalone development tool generates a distribution SELinux policy
catalog. It does not require an agent, ingestion credentials, or a running
SECentral server.

This is not yet the mechanism for collecting a company's custom SELinux
policies. Do not treat output collected from a customized host as a distribution
catalog.

## Generate a distribution catalog

Use a fresh RHEL VM with SELinux enabled and no local policy customization.
Install the required tools as root:

```sh
dnf install -y selinux-policy-targeted policycoreutils-python-utils libselinux-utils
```

The collector also requires `rpm`, `semanage`, `getsebool`, `uname`, and access
to `/sys/fs/selinux/policy`. Copy a Linux collector binary to the VM, then run:

```sh
./secentral-catalog-collector collect -output rhel-catalog.json
./secentral-catalog-collector validate rhel-catalog.json
```

Use `inspect` to diagnose why collection refuses a host with detected local
customizations. It checks local boolean, port, and file-context changes; it does
not identify every possible custom policy module or policy modification.
