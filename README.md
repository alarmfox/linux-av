# Summy - A Linux malware detection program

**WARNING**: the following program is not production ready.

A basic malware scanner written in Rust for desktop Linux users.

The application has a server that manages rules, signatures and
updates and communicates with clients through UNIX sockets.

## Features

- [x] Signature based scanning (importing a database)
- [x] Rule based scanning (using yara rules)
- [ ] Sandboxing
- [ ] Concurrent server
- [ ] Support persistent connections with live updates



