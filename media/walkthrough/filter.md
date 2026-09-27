# Filter packets

The filter bar above the packet list takes Wireshark **display filters**:

| Filter                           | Shows                             |
| -------------------------------- | --------------------------------- |
| `dns`                            | DNS packets                       |
| `ip.addr == 10.0.0.5`            | packets from or to 10.0.0.5       |
| `tcp.port == 443 && tcp.len > 0` | TLS data segments                 |
| `http.request.method == "GET"`   | HTTP GET requests                 |
| `tcp.analysis.flags`             | retransmissions, lost segments, … |
| `!(arp or icmp)`                 | everything except ARP and ICMP    |

- Fields and operators are **completed as you type** (`Tab` takes the first
  suggestion), and the bar turns red with tshark's message while a filter is
  invalid.
- `Enter` applies it; big captures show matches as they are found.
- **★** keeps saved and recent filters.
- Right-click a field in the protocol tree for **Apply as Filter** or **Apply
  as Column**.
- **Find** (`Ctrl+F`) jumps to a string, hex bytes or a filter without
  hiding the other packets.
