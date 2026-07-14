# Node.js development and transpiled usage

Install Node.js and npm, then clone and validate the project:

```sh
git clone https://github.com/open-abap/open-abap-ssh.git
cd open-abap-ssh
npm ci
npm test
```

`npm test` checks platform-dependency boundaries, runs abaplint, transpiles the
ABAP sources, and executes the ABAP Unit suite on Node.js. Generated files are
written to `output/`; do not edit or commit that directory.

The repository includes a Node TCP adapter and an executable example in
`integration/exec.mjs`. With an SSH server already listening, configure it via
environment variables and run:

```sh
OASSH_HOST=127.0.0.1 \
OASSH_PORT=2222 \
OASSH_USER=test \
OASSH_PASSWORD=test \
OASSH_COMMAND='printf open-abap-ssh' \
OASSH_EXPECTED='open-abap-ssh' \
npm run integration:exec
```

On PowerShell, set the same values with `$env:OASSH_HOST = '127.0.0.1'` (and
the corresponding variables) before running `npm run integration:exec`.
`OASSH_PRIVATE_SEED` can replace `OASSH_PASSWORD` and must contain the
hexadecimal Ed25519 seed. The integration adapter uses Node's secure random
generator, but its accept-all host verifier is suitable only for local tests.

Additional live checks are available as `npm run integration:transport` and
`npm run integration:auth`. `npm run integration:shell` requests a real PTY,
starts the account's default shell, sends binary stdin followed by SSH channel
EOF, and verifies raw terminal output against the pinned OpenSSH server.

`npm run integration:rebex` runs all three scenarios against the public
[Rebex test server](https://test.rebex.net) (`demo`/`password`), an
independent non-OpenSSH implementation, with no local setup required. It
needs internet access and depends on third-party uptime, so CI runs it as a
non-blocking job.
