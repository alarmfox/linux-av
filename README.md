# Summy - A Linux malware detection program 
**WARNING**: the following program is not production ready.

A basic malware scanner written in Rust for desktop Linux users.

The application has a server that manages rules, signatures and 
updates and communicates with clients through UNIX sockets.

## Features
* [ ] Signature based scanning (importing a database)
* [ ] Rule based scanning (using sigma rules)
* [ ] Executing a program in a "sandbox" with namespaces and cgroups
* [ ] Kernel level protection using eBPF (can be deactivated)
* [ ] GUI and systray
