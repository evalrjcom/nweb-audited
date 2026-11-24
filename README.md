# nweb-audited

Hardened version of Nigel Griffiths' tiny static-file web server (nweb) from the nmon project, plus a Rust port of the original.

## Files

- `nweb25.c` — Original version 25 (July 2016) from SourceForge.
- `nweb.c` — Audited and hardened version (v26). Fixes privilege drop, path traversal/encoding checks, HTTP compliance, proper SIGCHLD reaping, safer parsing, and daemonization.
- `nweb25.rs` — Rust port of the original nweb25.c (std only, threads instead of fork, portable).

## Build and run

### C (hardened)
```bash
cc -O2 -Wall -o nweb nweb.c
# For ports < 1024 or to use chroot, start as root; it drops to nobody (65534) immediately after chroot.
./nweb 8181 /path/to/webroot &
```

### Rust
```bash
rustc -O nweb25.rs -o nweb
./nweb 8181 /path/to/webroot
```

## Audit summary (key fixes in nweb.c)

- Drop privileges after `chroot` if running as root.
- Reject `%` encodings and enforce leading `/` + no `..`.
- Correct `Content-Length` and use `\r\n` in responses.
- Proper `setsid` + `waitpid` reaper; handle `EINTR`.
- Safer string handling and MIME types.

Original project: http://nmon.sourceforge.net/pmwiki.php?n=Site.Nweb  
Source of original: https://sourceforge.net/projects/nmon/files/nweb25.c

This remains a teaching example, not a production web server.
