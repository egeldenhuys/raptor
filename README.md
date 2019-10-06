# Raptor
Rogue access point detector - detect evil twin attacks using beacon frames

## Introduction

Raptor is a tool for detecting rogue Access Points (APs) that use the same SSID
as the legitimate network, also known as the Evil Twin attack.
The goal of the evil twin attack is to imitate a legitimate AP in order
to get devices to connect to it instead if the legitimate network. The rogue AP
can then intercept and modify the client's communications.

It is assumed the legitimate network will be using MSCHAPv2 for authentication.
The MSCHAPv2 protocol only allows a client to connect to the network if
the access point can prove knowledge of the user's password.
Therefore the detection methods are limited since the rogue AP will
only be used for capturing authentication handshakes.
The scope of detection will limited to only using information present in
the beacon frame.

## Detection Method
Usually the MAC address of an AP can be used to uniquely identify it.
However the rogue AP can use an arbitrary MAC address.
Therefore simply comparing MAC addresses to a whitelist is not sufficient.

[**TODO**: Insert beacon frame format diagram]

The beacon frame contains information about the network as well as hardware and vendor
specific fields. [**TODO**: Give examples of such fields and test it.]
It is assumed that most [**TODO**: Provide references to software APs] tools
do not provide functionality to imitate the legitimate beacon frame.
They only provide the function to set the SSID, MAC address and encryption used.
[**TODO**: Is is possible to transmit raw frames of a cloned beacon frame?]

An efficient method of detecting rogue APs is to compare the size of
the beacon frames. If an AP generates a beacon frame that differs in size
the the known legitimate size, it is most likely a rogue AP.
While this method is efficient it is not the most reliable.

Raptor will collect beacon frames while hopping WiFi channels.

TODO:
- [ ] discuss BFS
- [ ] discuss hashing
