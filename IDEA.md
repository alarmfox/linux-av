# Roadmap
**WARNING**: these are ideas. Implementation is not assured

## Sandboxing
Client can request the execution of a program in a sandboxed environment.
The sandbox will be realized with namespaces and mount points.
When the process starts a program (maybe an eBPF will be attached) will monitor the execution and provide a report 
on what has been done.

* Users can request the execution to run for a certain amount of time;
* Users can send signals to the process;

## Types of client
Support 2 types of connection
* Single requests: a client (simple) will ask for a scan.
* Persistent connections: a client (advanced) will be listening for keep alive and updates.
    * a client can subscribe to certain type of events
    * a client 

## Installation/Deploy
* Support installation script for different init system (runit, systemd)
* Configure accurately permission on the socket
