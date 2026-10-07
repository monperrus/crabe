# crabe

Self-updating fleet agent, one file: `crabe.py`. Run hourly from cron on each machine, it

- updates itself from <https://raw.githubusercontent.com/monperrus/crabe/main/crabe.py>
  (override with `CRABE_UPDATE_URL`), only when the remote `CRABE_VERSION` is higher than
  the local one;
- installs `paramiko` if missing;
- generates its own passphrase-less signing key `~/.ssh/crabe/id_ed25519` (never touches
  the user's own keys);
- adds itself to the crontab (hourly, random minute) if not already there;
- waits 0–45 s, then posts machine-id, hostname, public IP and Python version, with an
  SSHSIG signature of the machine-id, to <https://www.monperrus.net/martin/crabe.py>.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/monperrus/crabe/main/crabe.py -o ~/crabe.py
chmod +x ~/crabe.py && ~/crabe.py
```

A successful run prints nothing, so cron mails only on warnings and errors. All activity is
logged to `~/.local/state/crabe/crabe.log` (daily rotation, 30 days kept; override with
`CRABE_LOG_FILE`). If cron wraps it in `timeout 60`, the 45 s stagger still fits.

Verify a posted signature:

```sh
printf %s "$MACHINE_ID" | ssh-keygen -Y check-novalidate -n file -s sig.txt
```

## Development

**Bump `CRABE_VERSION` in every change**, otherwise no machine picks it up.

```sh
pip install -e '.[dev]'
pytest
```

## License

MIT
