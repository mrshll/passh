#!/usr/bin/env bash
# Install passh. Run on the laptop (full install) or the remote host
# (--client-only).
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
PORT="${PASSH_PORT:-18340}"
LABEL="com.passh.passhd"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
CLIENT_ONLY=0

[[ "${1:-}" == "--client-only" ]] && CLIENT_ONLY=1
if [[ "$(uname -s)" != Darwin ]]; then
    CLIENT_ONLY=1   # the daemon belongs on the machine with the biometrics
fi

cd "$(dirname "$0")"
mkdir -p "$BIN_DIR"
install -m 0755 passh "$BIN_DIR/passh"
echo "installed $BIN_DIR/passh"

if [[ $CLIENT_ONLY -eq 1 ]]; then
    mkdir -p "$HOME/.config/passh" && chmod 700 "$HOME/.config/passh"
    cat <<MSG

Client installed. On the laptop, copy the token over and add the forward:

    scp ~/.config/passh/token $(hostname -s):.config/passh/token

    Host $(hostname -s)
      RemoteForward $PORT 127.0.0.1:$PORT

Then run: passh doctor
MSG
    exit 0
fi

install -m 0755 passhd "$BIN_DIR/passhd"
echo "installed $BIN_DIR/passhd"

mkdir -p "$HOME/.local/state/passh" "$HOME/Library/LaunchAgents"

# Skip this if you already manage the launch agent elsewhere (chezmoi, etc) —
# two agents would fight over the port.
if [[ -n "${PASSH_NO_LAUNCHD:-}" ]]; then
    echo "PASSH_NO_LAUNCHD set — not installing the launch agent"
else
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DIR/passhd</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.local/state/passh/passhd.out.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.local/state/passh/passhd.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
PLIST_EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    echo "loaded $LABEL"
fi

sleep 2
if command -v lsof >/dev/null && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "passhd is listening on 127.0.0.1:$PORT"
else
    echo "WARNING: nothing listening on $PORT — check ~/.local/state/passh/passhd.err.log" >&2
fi

cat <<MSG

Next, for each remote host:

    Host REMOTE
      RemoteForward $PORT 127.0.0.1:$PORT

    scp ~/.config/passh/token REMOTE:.config/passh/token

Then on REMOTE: passh doctor
MSG
