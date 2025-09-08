# VXLAN Driver Documentation

## Overview

The VXLAN driver enables multi-host container networking by creating VXLAN tunnels between hosts. This allows containers running on different physical hosts to communicate as if they were on the same network segment.

## Features

- **Multi-host networking**: Containers on different hosts can communicate directly
- **Layer 2 connectivity**: VXLAN provides transparent Layer 2 connectivity over Layer 3 networks
- **Configurable VNI**: Support for custom VXLAN Network Identifiers
- **Multiple remote endpoints**: Support for multiple remote hosts
- **Custom ports**: Configurable VXLAN destination port (default: 4789)
- **Bridge integration**: Automatic bridge creation and veth pair management

## Configuration

### Required Options

The VXLAN driver requires the following configuration options:

- `vni`: VXLAN Network Identifier (1-16777215)
- `local_ip`: Local IP address for VXLAN tunnel
- `remote_ips`: Comma-separated list of remote IP addresses
- `physical_interface`: Physical network interface to use for VXLAN

### Optional Options

- `vxlan_port`: VXLAN destination port (default: 4789)
- `mtu`: Maximum Transmission Unit for interfaces
- `metric`: Route metric for default routes
- `no_default_route`: Disable default route creation

### Example Configuration

```json
{
    "name": "vxlan-network",
    "driver": "vxlan",
    "network_interface": "br-vxlan-network",
    "options": {
        "vni": "100",
        "local_ip": "192.168.1.10",
        "remote_ips": "192.168.1.11,192.168.1.12",
        "physical_interface": "eth0",
        "vxlan_port": "4789"
    },
    "subnets": [
        {
            "subnet": "10.0.0.0/24",
            "gateway": "10.0.0.1"
        }
    ],
    "dns_enabled": true,
    "internal": false,
    "ipv6_enabled": false
}
```

## Network Architecture

The VXLAN driver creates the following network topology:

1. **Bridge Interface**: `br-vxlan-<network-name>` - Connects VXLAN and container interfaces
2. **VXLAN Interface**: `vxlan-<network-name>` - Handles VXLAN encapsulation
3. **Container veth pairs**: Connect containers to the bridge

```
Host A                    Host B
┌─────────────────┐      ┌─────────────────┐
│ Container A     │      │ Container B     │
│ ┌─────────────┐ │      │ ┌─────────────┐ │
│ │ eth0        │ │      │ │ eth0        │ │
│ └─────────────┘ │      │ └─────────────┘ │
└─────────┬───────┘      └─────────┬───────┘
          │                        │
          │ veth pair              │ veth pair
          │                        │
┌─────────▼───────┐      ┌─────────▼───────┐
│ br-vxlan-net   │      │ br-vxlan-net   │
│ ┌─────────────┐ │      │ ┌─────────────┐ │
│ │ vxlan-net   │ │◄─────┤ │ vxlan-net   │ │
│ └─────────────┘ │      │ └─────────────┘ │
└─────────────────┘      └─────────────────┘
          │                        │
          │ eth0                   │ eth0
          │                        │
    ┌─────▼─────┐              ┌───▼─────┐
    │ Physical  │              │Physical │
    │ Network   │              │Network  │
    └───────────┘              └─────────┘
```

## Usage with Podman

### Creating a VXLAN Network

```bash
# Create VXLAN network
podman network create \
  --driver vxlan \
  --opt vni=100 \
  --opt local_ip=192.168.1.10 \
  --opt remote_ips=192.168.1.11,192.168.1.12 \
  --opt physical_interface=eth0 \
  --subnet 10.0.0.0/24 \
  vxlan-network
```

### Running Containers

```bash
# Run container on host A
podman run -d --name container-a --network vxlan-network nginx

# Run container on host B
podman run -d --name container-b --network vxlan-network nginx

# Containers can now communicate directly using their IP addresses
```

## Requirements

### System Requirements

- Linux kernel with VXLAN support (3.7+)
- VXLAN kernel module loaded
- Physical network connectivity between hosts
- Firewall rules allowing VXLAN traffic (UDP port 4789 by default)

### Network Requirements

- All hosts must have reachable IP addresses
- VXLAN traffic must not be blocked by firewalls
- Physical network must support the required MTU (VXLAN adds 50 bytes overhead)

## Limitations

### Phase 1 Limitations

- **Static Configuration**: Remote IP addresses must be configured statically
- **No Dynamic Discovery**: No automatic discovery of remote hosts
- **Basic VXLAN**: Limited to point-to-point and point-to-multipoint configurations
- **No Multicast**: Multicast VXLAN is not supported in Phase 1

### Future Enhancements (Planned)

- Dynamic remote host discovery
- Multicast VXLAN support
- Learning bridge functionality
- Advanced VXLAN features (learning, proxy, etc.)

## Troubleshooting

### Common Issues

1. **VXLAN interface creation fails**
   - Check if VXLAN kernel module is loaded: `lsmod | grep vxlan`
   - Verify physical interface exists and is up
   - Check for conflicting interface names

2. **Containers cannot communicate**
   - Verify VXLAN tunnel is established: `ip link show vxlan-<network-name>`
   - Check firewall rules allow VXLAN traffic
   - Verify remote IP addresses are reachable

3. **Performance issues**
   - Check MTU settings (VXLAN adds 50 bytes overhead)
   - Verify physical network performance
   - Consider using hardware offloading if available

### Debugging Commands

```bash
# Check VXLAN interface status
ip link show vxlan-<network-name>

# Check bridge status
ip link show br-vxlan-<network-name>

# Check VXLAN forwarding table
bridge fdb show dev vxlan-<network-name>

# Monitor VXLAN traffic
tcpdump -i vxlan-<network-name>

# Check firewall rules
iptables -L -n | grep 4789
```

## Security Considerations

- VXLAN traffic is not encrypted by default
- Consider using IPsec or other encryption for sensitive traffic
- Ensure proper firewall rules are in place
- Monitor VXLAN traffic for security issues
- Use strong VNI values to avoid conflicts

## Performance Considerations

- VXLAN adds 50 bytes of overhead per packet
- Consider MTU settings to avoid fragmentation
- Hardware offloading can improve performance
- Monitor network utilization and latency
- Consider using dedicated network interfaces for VXLAN traffic
