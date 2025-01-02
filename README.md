# linux-av: A malware detection program for Linux

**WARNING**: this project is not production ready.

A basic malware scanner written in Rust for Linux desktop users.

## Features

- [x] Signature based scanning (importing a database)
- [x] Rule based scanning (using yara rules)
- [ ] Sandboxing
- [ ] Concurrent server
- [ ] Support persistent connections with live updates

## Sandboxing
Client can request the execution of a program in a sandboxed environment.
The sandbox will be realized with namespaces and mount points.
When the process starts a program (maybe an eBPF will be attached) will monitor the execution and provide a report
on what has been done.
