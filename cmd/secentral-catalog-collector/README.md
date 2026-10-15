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
dnf install -y selinux-policy-targeted policycoreutils-python-utils libselinux-utils python3 python3-setools
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

Collection also requires Python 3 with the SETools bindings (`python3-setools` on
RHEL/AlmaLinux 9; verify package availability on other reference distributions).
The embedded helper queries effective permissive type flags from an exact private
copy of the loaded policy, not `semanage permissive -l`. The copy must match the
initial policy SHA, and the loaded-policy identity must remain unchanged through
collection. Temporary policy bytes are removed on success and failure.

Extraction is limited to 30 seconds wall/CPU, 512 MiB Python address space, and
1 MiB combined output; captured policies must be between 1 byte and 16 MiB.
Missing tools, malformed results, resource failures, or policy changes refuse
generation. A successful empty membership is recorded as `domains: []`.

New catalogs use schema 1 / collector semantics 4, requiring the complete
`effective_permissive_domains` family, extraction semantics 1, and the actual
SETools version. All family fields participate in the content digest. This is a
coordinated pre-release format change: semantics 3 catalogs must be regenerated
and importers must support semantics 4. Collector-reported inline facts are not
server-verified binary extraction or proof of untouched vendor policy.
