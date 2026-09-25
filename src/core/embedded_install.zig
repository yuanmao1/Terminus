//! The remote half of installing a binary this CLI embeds (the helper, tmux)
//! into `$HOME/.terminus/bin`. `cmd_server.zig` runs it; the black-box gates
//! run the same text through a real shell on a real Linux kernel.

/// The remote half of an embedded-binary install, for the binary at
/// `$HOME/.terminus/bin/<file>`. The bytes arrive on stdin and their expected
/// digest in `$TERMINUS_INSTALL_SHA256`.
///
/// Exit codes are the contract callers report on: 78 wrong architecture, 77
/// install directory mounted noexec, 74 the uploaded bytes are not the ones
/// sent, 69 a tool the checks need is missing.
pub fn script(comptime file: []const u8) []const u8 {
    return
    \\set -eu
    \\[ "$(uname -m)" = x86_64 ] || { echo "unsupported architecture: $(uname -m)" >&2; exit 78; }
    \\command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 69; }
    \\command -v findmnt >/dev/null 2>&1 || { echo "findmnt is required" >&2; exit 69; }
    \\base="$HOME/.terminus/bin"
    \\
    ++ "final=\"$base/" ++ file ++ "\"\n" ++
        \\umask 077
        \\mkdir -p "$base"
        \\chmod 700 "$HOME/.terminus" "$base" 2>/dev/null || true
        \\mount_opts=$(findmnt -n -o OPTIONS -T "$base")
        \\case ",$mount_opts," in *,noexec,*) echo "install directory filesystem is mounted noexec" >&2; exit 77;; esac
        \\
    ++ "tmp=$(mktemp \"$base/." ++ file ++ ".new.XXXXXX\")\n" ++
        \\trap 'rm -f "$tmp"' EXIT HUP INT TERM
        \\cat >"$tmp"
        \\actual=$(sha256sum "$tmp" | awk '{print $1}')
        \\[ "$actual" = "$TERMINUS_INSTALL_SHA256" ] || { echo "uploaded binary digest mismatch" >&2; exit 74; }
        \\chmod 700 "$tmp"
        \\
    ++ "if [ -e \"$final\" ]; then cp -p \"$final\" \"$base/" ++ file ++ ".previous\"; fi\n" ++
        \\mv -f "$tmp" "$final"
        \\trap - EXIT HUP INT TERM
        \\[ "$(sha256sum "$final" | awk '{print $1}')" = "$TERMINUS_INSTALL_SHA256" ]
        \\printf '%s\n' "$actual"
    ;
}
