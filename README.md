# passh

Run the 1Password CLI from a remote machine, and get the Touch ID prompt on the
machine you are actually sitting at.

## The problem

You SSH into a dev box and run `op read op://...`. Nothing happens.

If the remote machine has the 1Password desktop app installed, it is worse than
nothing: the app throws its authorization dialog onto a GUI session on the
*remote* machine, where no human will ever see it. Your command hangs, or fails
with `cannot connect to 1Password app`, and the prompt you needed is sitting on
a screen in another room.

1Password's answer to this is a service account token. That works, but it puts
a bearer credential on the remote box — no second factor, not bound to an IP,
valid from anywhere until you revoke it. On a machine running coding agents
that read untrusted repositories, that token is one prompt injection away from
being exfiltrated.

## What passh does instead

`passh` never authenticates on the remote machine. It sends the `op` invocation
back to your laptop, runs it there, and returns the result.

```
remote:  passh run --env-file=... -- cmd
             |
             v  HTTP to 127.0.0.1:18340
         [ RemoteForward, carried by the SSH session you already opened ]
             |
             v
laptop:  passhd  ->  op  ->  Touch ID prompt, in front of you
```

The transport is a `RemoteForward` on the SSH session *you* opened, going the
opposite direction from the connection. Consequences:

- Nothing listens on your laptop's network interfaces. No sshd, no open port,
  no `authorized_keys` entry for the server.
- **Vault access exists only while your SSH session is open.** Close the
  session, or let the laptop sleep, and the remote machine loses access. There
  is no window in which a compromised server can reach your vaults while you
  are away.
- No long-lived 1Password credential is ever stored on the remote machine.

The same command works on your laptop too, where it just calls the local `op`,
so scripts and docs do not need to know which machine they are on.

## Install

On the laptop (macOS, where the biometrics are):

```bash
./install.sh
```

That installs `passh` and `passhd` to `~/.local/bin`, generates a token,
and loads a launchd agent that keeps the daemon running.

Then add the forward to your SSH config for the remote host:

```
Host myserver
  RemoteForward 18340 127.0.0.1:18340
```

On the remote machine, install the client and copy the token over:

```bash
./install.sh --client-only
scp ~/.config/passh/token myserver:.config/passh/token   # run this from the laptop
```

Check it:

```bash
ssh myserver
passh doctor
```

## Usage

Prefer `passh run`. It resolves `op://` references and hands them to the child
process through `execve`, so values never touch disk, shell history, or any
process's argv:

```bash
passh run --env-file=<(echo 'MY_TOKEN=op://Vault/item/field') -- some-command
```

Everything else is forwarded to `op` verbatim:

```bash
passh read op://Vault/item/field
passh item list --vault Dev
passh inject -i template.env -o resolved.env
passh doctor
```

Use `--account NAME` for a non-default 1Password account.

## Security model

**What it protects against.** A compromised remote machine cannot reach your
vaults while you are disconnected, and has no credential to steal and use
elsewhere. Compare a service account token, which is valid from anywhere,
forever, for whoever reads the file.

**What it does not protect against.** While your session is open and 1Password
is unlocked, anything running as your user on the remote machine can use the
tunnel. Authorization is *not* per-command: `op` caches it until the 1Password
app relocks, so one Touch ID approval covers subsequent calls. Set a short
auto-lock in 1Password if that window matters to you.

The bearer token in `~/.config/passh/token` gates the tunnel endpoint, but on a
single-user box anything running as you can read it. It is hygiene, not a
boundary.

**Blocked subcommands.** `service-account`, `signin`, `signout`, `account add`,
`account forget`, `update`, `completion`. These would let someone with shell
access on the remote machine mint a durable credential or repoint the CLI at
another account — exactly the property this design exists to avoid.

`passhd` enforces this list itself. The client enforces it too on the tunnel
path, but that check is only a convenience: the client runs on the machine
being protected against, so nothing it claims can be trusted.

**Audit.** `passhd` logs every invocation's arguments to
`~/.local/state/passh/passhd.log`. It never logs stdin or stdout — those carry
the `op://` templates and the resolved secrets.

## When there is no tunnel

Sometimes the forward is not there: you are on a phone SSH client, the laptop
is asleep, you forgot the `RemoteForward`, or — easy to miss — a `tmux` session
on the remote machine has outlived the SSH session that carried the tunnel.

passh does not try to identify the client. It attempts the tunnel, and if the
connection fails it falls back to running `op` on the remote machine itself,
saying so on stderr. That path authenticates with your 1Password *password*
rather than Touch ID, so it asks for one:

```bash
eval $(op signin)     # 30-minute session, then passh stops asking
```

On a headless box passh sets `OP_BIOMETRIC_UNLOCK_ENABLED=false` for the
fallback, otherwise `op` would try to reach a desktop app that cannot prompt
anyone and fail with `cannot connect to 1Password app`.

`PASSH_NO_FALLBACK=1` turns this off and makes a missing tunnel a hard error.
`PASSH_MODE=local|remote` forces one path.

Note that the blocklist below applies to the tunnel, not to the fallback: once
`op` is running locally there is nothing to protect, since anyone who could run
`passh` could run `op` directly.

## Limits

- The tunnel requires an open SSH session from the laptop. Without one you get
  the password fallback above, which needs a terminal to type into — so cron
  and unattended jobs still cannot use passh unless an `OP_SESSION_*` is
  already exported.
- `op run` cannot be forwarded as-is — it would launch your command on the
  laptop. `passh run` resolves the env-file remotely and execs the command
  locally instead. Same contract, split across the hop.
- Env values containing newlines are not supported by `passh run`'s parser.
- One tunnel per port. A second concurrent SSH session logs a port-in-use
  warning and reuses the first tunnel, which is harmless.

## Prior art

[op-forward](https://github.com/ekovshilovsky/op-forward) solves the same
problem with the same daemon-plus-tunnel shape.
