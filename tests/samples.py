IPCONFIG = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : LAPTOP-1
   Primary Dns Suffix  . . . . . . . :

Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   Physical Address. . . . . . . . . : 11-22-33-44-55-66
   DHCP Enabled. . . . . . . . . . . : Yes

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : coffee.lan
   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201 160MHz
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-01
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::1c2d:3e4f:5a6b:7c8d%12(Preferred)
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Thursday, October 15, 2026 9:00:00 AM
   Default Gateway . . . . . . . . . : fe80::1%12
                                       192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DHCPv6 IAID . . . . . . . . . . . : 123456789
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2A-BB-CC-DD-AA-BB-CC-DD-EE-01
   DNS Servers . . . . . . . . . . . : 192.168.1.1
                                       8.8.8.8
                                       fec0:0:0:ffff::1%1
   NetBIOS over Tcpip. . . . . . . . : Enabled
"""

WLAN_IF = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 1234
    Physical address       : aa:bb:cc:dd:ee:01
    Interface type         : Primary
    State                  : connected
    SSID                   : CoffeeShop
    AP BSSID               : 00:1a:1e:11:22:33
    Band                   : 5 GHz
    Channel                : 36
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Signal                 : 90%
    Profile                : CoffeeShop
"""

WLAN_NETS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:1a:1e:11:22:33
         Signal             : 90%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 36
    BSSID 2                 : 00:1a:1e:11:22:44
         Signal             : 60%
         Channel            : 1

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 00:13:37:aa:bb:cc
         Signal             : 95%
         Channel            : 6

SSID 3 : Neighbor
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : f0:9f:c2:00:00:01
         Signal             : 20%
"""

WLAN_LOCATION = """Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings."""

ARP_A = """
Interface: 192.168.1.50 --- 0xc
  Internet Address      Physical Address      Type
  192.168.1.1           00-1a-1e-aa-bb-cc     dynamic
  192.168.1.77          00-1a-1e-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""
