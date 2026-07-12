# Cyber Attack Detection and Defense System

A Python-based cybersecurity project for analyzing captured network traffic and detecting suspicious activity.

## Features

- Reads PCAP files using Scapy
- Detects TCP, UDP and ICMP traffic
- Generates traffic statistics
- Tracks source and destination hosts
- Tracks destination ports
- Detects possible port scanning attacks

## Technologies

- Python
- Scapy
- Wireshark
- Git

## Project Structure

```
Packet Capture (.pcap)
        │
        ▼
Packet Reader
        │
        ▼
Threat Detector
        │
 ┌──────┼─────────┐
 ▼      ▼         ▼
Statistics HostTracker PortTracker
```

## Future Work

- SQLite Database
- Flask Dashboard
- Snort Integration
- SYN Flood Detection
- ICMP Flood Detection
- SSH Brute Force Detection
- Automatic Firewall Blocking
