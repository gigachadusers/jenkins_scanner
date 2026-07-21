# Jenkins & SSH Network Scanner Framework

![C++](https://img.shields.io/badge/Language-C%2B%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Purpose](https://img.shields.io/badge/Purpose-Security%20Research-orange)
![Status](https://img.shields.io/badge/Status-Beta-yellow)

A lightweight C++ network scanning framework 


- **SSH (Port 22)**
- **Jenkins/Web Services (Port 8080)**


---

# How It Works

The scanner follows a simple workflow:

```
User Input
     |
     v
IP Range Selection
     |
     v
Scan Every IP
     |
     v
Check Port 22 (SSH)
     |
     v
Check Port 8080 (Jenkins/Web)
     |
     v
Report Open Services
     |
     v
Optional Server Callback
```

---

# Features

## IP Range Scanning

The user provides:

```
Start IP:
192.168.1.1

End IP:
192.168.1.254
```

The scanner then iterates through every address inside that range.

Example:

```
192.168.1.1
192.168.1.2
192.168.1.3
...
192.168.1.254
```

---

## Port Detection

Each discovered IP is tested for:

### SSH

```
Port: 22
Purpose:
Remote administration service
```

### Jenkins / Web Services

```
Port: 8080
Purpose:
Common Jenkins default web interface port
```

The scanner determines whether the port is:

```
OPEN
CLOSED
TIMEOUT
ERROR
```

---

#  Technical Overview

## Language

Written entirely in:

```
C++
```

using Windows native networking APIs.

Libraries used:

```
Winsock2
IP Helper API
Windows API
```

Linked libraries:

```
ws2_32.lib
iphlpapi.lib
```

---

# Scanner Logic

For each IP address:

1. Create a TCP socket

2. Attempt connection to:

```
192.168.x.x:22
```

3. Attempt connection to:

```
192.168.x.x:8080
```

4. Log the result

Example output:

```
[21:32:15.002] Checking port 22 on 192.168.1.50...
[21:32:15.120] Port 22: OPEN

[21:32:15.121] Checking port 8080 on 192.168.1.50...
[21:32:15.250] Port 8080: OPEN
```

---

#  Callback / Research Connection

If both services are detected:

```
SSH  +  Jenkins
```

the framework can attempt a connection back to a configured server.

Example:

```cpp
#define SERVER_IP "127.0.0.1"
```

--

Example:

```
Port 22 OPEN
≠
SSH access obtained
```

```
Port 8080 OPEN
≠
Jenkins compromised
```

A successful connection depends on the service configuration and security controls.

---

# ⚙️ Building

Requirements:

- Windows
- Visual Studio
- Windows SDK

Build:

```
Open project in Visual Studio

Build Solution

Run executable
```

---

# ⭐ About

A simple C++ network scanning framework built to explore how automated service discovery works and provide a base for future security research projects.
