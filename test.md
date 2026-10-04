# Remote ID Receiver Debug Test

Given that packets sent from the same system/interface are received, the app and parser path are likely working. That local test does not prove the receiver is hearing packets over the air, because Linux/Scapy can observe packets injected by the local host.

The most likely issue is receiver-side RF setup:

- Receiver interface is on the wrong Wi-Fi channel.
- Receiver interface is not actually in monitor mode.
- NetworkManager or wpa_supplicant reclaims or retunes the interface.
- Adapter/driver can inject or echo local frames but cannot reliably receive monitor-mode management frames.
- Regulatory domain or hardware support blocks the chosen channel, especially channel 149.
- Spoofer transport is not Wi-Fi beacon mode.

The spoofer defaults to Wi-Fi channel 6. Run this on the receiver machine while transmitting from the other system:

```bash
sudo ip link set <rx_iface> down
sudo iw dev <rx_iface> set type monitor
sudo ip link set <rx_iface> up
sudo iw dev <rx_iface> set channel 6
iw dev <rx_iface> info
sudo tcpdump -i <rx_iface> -e -s 0 type mgt subtype beacon
```

Expected interpretation:

- If `tcpdump` sees the spoofed beacons but the app does not, inspect app filtering/parser behavior.
- If `tcpdump` sees nothing while other receivers do, the problem is monitor mode, channel tuning, driver support, regulatory domain, selected interface, or RF hardware.

