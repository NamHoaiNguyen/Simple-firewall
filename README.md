# Simple-Firewall

This project is used to controll the socket system call by hijacking the system call table. All IP(of website) and port listed in configure file black.json will be blocked. Configure file is defined in users-space and can be transferred into kernel
 by netlink.

This project works well on ubuntu-16.04.1-desktop-i386, systemkernel info 

```4.15.0-123-generic```

## Usage

Compile firewall.c(folder "user")
```gcc - o firewall firewall.c -lpthread -lm```

Compile kernel module(folder "kernel")
```make```
 
Install kernel module
```sudo insmod CCModule.ko```

Run firewall
```./CCModule black.json "path that contain this "black.json"```

# Note
Only run this on a virtual machine(note that maybe this project maybe can't run on x64 platform).
