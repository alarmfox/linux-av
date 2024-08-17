# Summy - A Linux antivirus
** WARNING **: the following program is not production ready.

A basic malware scanner written in Rust for desktop Linux users.

The application has a server that manages rules, signatures and 
updates and communicates with clients through UNIX sockets.

## Features
[] Signature based scanning (importing a database)
[] Rule based scanning (using sigma rules)

## Goals
* Implement some sort of real-time protection 
* Introduce a kernel module to inspect both network traffic and programs using eBPF
* Implement a systray GUI to control the application
* Allow users to specify





