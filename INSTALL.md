# Install the version with descriptive device names

This is a modified copy of `bitbrute/evillimiter`, based on commit
`46d2033b022f4a51fb2f419393a5344ad3edea4a` (version 1.5.0).
These changes have not been published to the upstream GitHub repository.

## Ubuntu / Debian

Clone this private repository using a GitHub account that has access
(skip `gh auth login` if already signed in):

```sh
sudo apt update
sudo apt install git gh python3-venv python3-dev build-essential iproute2 iptables procps sudo
gh auth login
gh repo clone patrickdx/evillimiter-v1
cd evillimiter-v1
python3 -m venv .venv
.venv/bin/python -m pip install .
sudo .venv/bin/evillimiter --version
sudo .venv/bin/evillimiter
```

If you downloaded a ZIP instead, extract it and open a terminal in that
directory, then start at
`python3 -m venv .venv`. Always install from this modified checkout; installing
`evillimiter` by name from PyPI will not include these changes.

At the EvilLimiter prompt:

```text
scan
hosts
```

Use `sudo .venv/bin/evillimiter -i eth0` if you need to select an interface;
replace `eth0` with the appropriate interface name. Use the explicit executable
path above to run this copy instead of an older system installation.

## Updating

From your cloned repository directory:

```sh
git pull --ff-only
.venv/bin/python -m pip install .
sudo .venv/bin/evillimiter --version
sudo .venv/bin/evillimiter
```

If you installed from a ZIP, download the updated source and reinstall it instead.

## Still seeing blank hostnames?

Quit any running EvilLimiter session before updating. Pulling the source alone
does not update a previously installed package, and `sudo evillimiter` may still
launch the old system installation. Use the explicit `.venv` path shown above.

The version check must print:

```text
EvilLimiter v1 1.5.1 (device identification enabled)
```

Then start a new session, run `scan`, and run `hosts`. The table should have a
`Device / hostname` column. An unidentified device shows `Unknown device`, not an
empty cell. The monitor and analysis views use the same fallback.

If you want to confirm where Python loads the installed code from, run:

```sh
.venv/bin/python -m pip show evillimiter
.venv/bin/python -c 'import evillimiter; print(evillimiter.__version__); print(evillimiter.__file__)'
```

Real names depend on what devices advertise and what the router resolves. A
fallback label does not mean that the model or owner has been identified.

The new dependency is `dnspython>=2.0`, installed automatically. An unused legacy
`pkg_resources` import was also removed so startup does not require that obsolete
module in a fresh environment.

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -v
```

The tests use synthetic device responses and require no root access or LAN
devices. They cover discovery, fragmented Android banners, malformed responses,
authentication refusal, label sanitization, fallback names, and scan integration.

Live verification of the identification module returned `Android-2 — TX6s`
from the home-network device used during development, in approximately 1.1 seconds.
Bandwidth limiting and ARP spoofing were not exercised during this change.
