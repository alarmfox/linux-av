# Summy - A Linux malware detection program

**WARNING**: the following program is not production ready.

A basic malware scanner written in Rust for desktop Linux users.

The application has a server that manages rules, signatures and
updates and communicates with clients through UNIX sockets.

## Features

- [ ] Signature based scanning (importing a database)
- [ ] Rule based scanning (using sigma rules)

## Goals

- Introduce a kernel module to inspect system call using eBPF
- Implement a systray and a GUI to control the application
- Merge different signatures and rule sources
