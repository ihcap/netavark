use std::{collections::HashMap, net::IpAddr, os::fd::BorrowedFd};

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::{
        constants::{
            DEFAULT_VXLAN_PORT, OPTION_LOCAL_IP, OPTION_PHYSICAL_INTERFACE, OPTION_REMOTE_IPS,
            OPTION_VNI, OPTION_VXLAN_PORT,
        },
        core_utils::{get_ipam_addresses, parse_option, CoreUtils},
        driver::{self, DriverInfo},
        internal_types::IPAMAddresses,
        netlink,
        types::StatusBlock,
    },
};

use super::{
    constants::{OPTION_HOST_INTERFACE_NAME, OPTION_METRIC, OPTION_MTU, OPTION_NO_DEFAULT_ROUTE},
};

const NO_BRIDGE_NAME_ERROR: &str = "no bridge interface name given";
const NO_CONTAINER_INTERFACE_ERROR: &str = "no container interface name given";

struct VxlanInternalData {
    /// VXLAN Network Identifier
    vni: u32,
    /// Local IP address for VXLAN
    local_ip: IpAddr,
    /// Remote IP addresses for VXLAN
    remote_ips: Vec<IpAddr>,
    /// Physical interface to use for VXLAN
    physical_interface: String,
    /// VXLAN port (default 4789)
    vxlan_port: u16,
    /// Bridge interface name
    bridge_interface_name: String,
    /// VXLAN interface name
    vxlan_interface_name: String,
    /// Container interface name
    container_interface_name: String,
    /// Host interface name
    host_interface_name: String,
    /// IPAM addresses
    ipam: IPAMAddresses,
    /// MTU for interfaces
    mtu: u32,
    /// Route metric
    metric: Option<u32>,
    /// No default route flag
    no_default_route: bool,
}

pub struct Vxlan<'a> {
    info: DriverInfo<'a>,
    data: Option<VxlanInternalData>,
}

impl<'a> Vxlan<'a> {
    pub fn new(info: DriverInfo<'a>) -> Self {
        Vxlan { info, data: None }
    }
}

impl driver::NetworkDriver for Vxlan<'_> {
    fn network_name(&self) -> String {
        self.info.network.name.clone()
    }

    fn validate(&mut self) -> NetavarkResult<()> {
        let _bridge_name = get_interface_name(self.info.network.network_interface.clone())?;
        
        if self.info.per_network_opts.interface_name.is_empty() {
            return Err(NetavarkError::msg(NO_CONTAINER_INTERFACE_ERROR));
        }

        let ipam = get_ipam_addresses(self.info.per_network_opts, self.info.network)?;

        // Parse VXLAN-specific options
        let vni: u32 = parse_option(&self.info.network.options, OPTION_VNI)?
            .ok_or_else(|| NetavarkError::msg("VNI is required for VXLAN driver"))?;
        
        if vni == 0 || vni > 16777215 {
            return Err(NetavarkError::msg("VNI must be between 1 and 16777215"));
        }

        let local_ip_str: String = parse_option(&self.info.network.options, OPTION_LOCAL_IP)?
            .ok_or_else(|| NetavarkError::msg("local_ip is required for VXLAN driver"))?;
        let local_ip: IpAddr = local_ip_str.parse()
            .map_err(|_| NetavarkError::msg("Invalid local_ip format"))?;

        let remote_ips_str: String = parse_option(&self.info.network.options, OPTION_REMOTE_IPS)?
            .ok_or_else(|| NetavarkError::msg("remote_ips is required for VXLAN driver"))?;
        let remote_ips: Vec<IpAddr> = remote_ips_str
            .split(',')
            .map(|ip| ip.trim().parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| NetavarkError::msg("Invalid remote_ips format"))?;

        let physical_interface: String = parse_option(&self.info.network.options, OPTION_PHYSICAL_INTERFACE)?
            .ok_or_else(|| NetavarkError::msg("physical_interface is required for VXLAN driver"))?;

        let vxlan_port: u16 = parse_option(&self.info.network.options, OPTION_VXLAN_PORT)?
            .unwrap_or(DEFAULT_VXLAN_PORT);

        let mtu: u32 = parse_option(&self.info.network.options, OPTION_MTU)?.unwrap_or(0);
        let metric: u32 = parse_option(&self.info.network.options, OPTION_METRIC)?.unwrap_or(100);
        let no_default_route: bool = parse_option(&self.info.network.options, OPTION_NO_DEFAULT_ROUTE)?
            .unwrap_or(false);

        let host_interface_name = parse_option(
            &self.info.per_network_opts.options,
            OPTION_HOST_INTERFACE_NAME,
        )?
        .unwrap_or_else(|| "".to_string());

        // Generate interface names
        let vxlan_interface_name = format!("vxlan-{}", self.info.network.name);
        let bridge_interface_name = format!("br-vxlan-{}", self.info.network.name);

        self.data = Some(VxlanInternalData {
            vni,
            local_ip,
            remote_ips,
            physical_interface,
            vxlan_port,
            bridge_interface_name,
            vxlan_interface_name,
            container_interface_name: self.info.per_network_opts.interface_name.clone(),
            host_interface_name,
            ipam,
            mtu,
            metric: Some(metric),
            no_default_route,
        });

        Ok(())
    }

    fn setup(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<(StatusBlock, Option<AardvarkEntry<'_>>)> {
        let data = match &self.data {
            Some(d) => d,
            None => return Err(NetavarkError::msg("must call validate() before setup()")),
        };

        log::debug!("Setup VXLAN network {}", self.info.network.name);
        log::debug!("VNI: {}, Local IP: {}, Remote IPs: {:?}", 
                   data.vni, data.local_ip, data.remote_ips);

        let (host_sock, netns_sock) = netlink_sockets;

        // For now, we'll implement a basic setup that creates the bridge
        // and veth pair, but skip VXLAN interface creation until we have
        // proper netlink support
        let mac_address = create_basic_interfaces(
            host_sock,
            netns_sock,
            data,
            self.info.network.internal,
            self.info.rootless,
            self.info.netns_host,
            self.info.netns_container,
        )?;

        // Create status block response
        let mut response = StatusBlock {
            dns_server_ips: Some(Vec::<IpAddr>::new()),
            dns_search_domains: Some(Vec::<String>::new()),
            interfaces: Some(HashMap::new()),
        };

        let mut interfaces: HashMap<String, crate::network::types::NetInterface> = HashMap::new();
        let interface = crate::network::types::NetInterface {
            mac_address: mac_address.clone(),
            subnets: Some(data.ipam.net_addresses.clone()),
        };
        interfaces.insert(data.container_interface_name.clone(), interface);
        let _ = response.interfaces.insert(interfaces);

        // TODO: Add aardvark entry support
        let aardvark_entry = None;

        Ok((response, aardvark_entry))
    }

    fn teardown(
        &self,
        netlink_sockets: (&mut netlink::Socket, &mut netlink::Socket),
    ) -> NetavarkResult<()> {
        let data = match &self.data {
            Some(d) => d,
            None => return Err(NetavarkError::msg("must call validate() before teardown()")),
        };

        let (host_sock, netns_sock) = netlink_sockets;

        log::debug!("Teardown VXLAN network {}", self.info.network.name);

        // Remove container veth
        netns_sock
            .del_link(netlink::LinkID::Name(data.container_interface_name.clone()))
            .wrap("failed to delete container veth")?;

        // Remove host veth
        host_sock
            .del_link(netlink::LinkID::Name(data.host_interface_name.clone()))
            .wrap("failed to delete host veth")?;

        // TODO: Implement proper cleanup logic to check if other containers are using the VXLAN
        // For now, we'll leave the bridge and VXLAN interface in place to avoid breaking other containers
        // In a production implementation, you would:
        // 1. Check if any other containers are using this VXLAN network
        // 2. Only remove the VXLAN interface and bridge if no containers are using them
        // 3. Use reference counting or similar mechanism

        log::debug!("VXLAN network {} teardown completed", self.info.network.name);

        Ok(())
    }
}

fn get_interface_name(name: Option<String>) -> NetavarkResult<String> {
    let name = match name {
        None => return Err(NetavarkError::msg(NO_BRIDGE_NAME_ERROR)),
        Some(n) => {
            if n.is_empty() {
                return Err(NetavarkError::msg(NO_BRIDGE_NAME_ERROR));
            }
            n
        }
    };
    Ok(name)
}

fn create_basic_interfaces(
    host: &mut netlink::Socket,
    netns: &mut netlink::Socket,
    data: &VxlanInternalData,
    internal: bool,
    _rootless: bool,
    _hostns_fd: BorrowedFd<'_>,
    netns_fd: BorrowedFd<'_>,
) -> NetavarkResult<String> {
    log::debug!("Creating VXLAN interfaces for network: {}", data.vxlan_interface_name);
    
    // Get the physical interface index
    let physical_if = host.get_link(netlink::LinkID::Name(data.physical_interface.clone()))
        .map_err(|_| NetavarkError::msg(format!("Physical interface {} not found", data.physical_interface)))?;
    let _physical_if_index = physical_if.header.index;
    
    // Create or get bridge
    let bridge_index = match host.get_link(netlink::LinkID::Name(data.bridge_interface_name.clone())) {
        Ok(bridge) => bridge.header.index,
        Err(_) => {
            // Create bridge
            let opts = netlink::CreateLinkOptions::new(
                data.bridge_interface_name.clone(),
                netlink_packet_route::link::InfoKind::Bridge,
            );
            host.create_link(opts)?;
            
            let bridge = host.get_link(netlink::LinkID::Name(data.bridge_interface_name.clone()))?;
            host.set_up(netlink::LinkID::ID(bridge.header.index))?;
            bridge.header.index
        }
    };

    // Create VXLAN interface
    let _vxlan_index = match host.get_link(netlink::LinkID::Name(data.vxlan_interface_name.clone())) {
        Ok(vxlan) => vxlan.header.index,
        Err(_) => {
            // Create VXLAN interface using system command for now
            // TODO: Implement proper netlink VXLAN creation
            log::debug!("Creating VXLAN interface: {}", data.vxlan_interface_name);
            
            // Use ip command to create VXLAN interface
            let mut cmd = std::process::Command::new("ip");
            cmd.args([
                "link", "add", "dev", &data.vxlan_interface_name,
                "type", "vxlan",
                "id", &data.vni.to_string(),
                "local", &data.local_ip.to_string(),
                "dstport", &data.vxlan_port.to_string(),
                "dev", &data.physical_interface
            ]);
            
            // Add remote IPs
            for remote_ip in &data.remote_ips {
                cmd.args(["remote", &remote_ip.to_string()]);
            }
            
            let output = cmd.output()
                .map_err(|e| NetavarkError::msg(format!("Failed to execute ip command: {}", e)))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(NetavarkError::msg(format!("Failed to create VXLAN interface: {}", stderr)));
            }
            
            // Get the created VXLAN interface
            let vxlan = host.get_link(netlink::LinkID::Name(data.vxlan_interface_name.clone()))?;
            host.set_up(netlink::LinkID::ID(vxlan.header.index))?;
            vxlan.header.index
        }
    };

    // Connect VXLAN to bridge
    let mut cmd = std::process::Command::new("ip");
    cmd.args([
        "link", "set", "dev", &data.vxlan_interface_name,
        "master", &data.bridge_interface_name
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to connect VXLAN to bridge: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to connect VXLAN to bridge (may already be connected): {}", stderr);
    }

    // Create veth pair
    let mut peer_opts = netlink::CreateLinkOptions::new(
        data.container_interface_name.clone(),
        netlink_packet_route::link::InfoKind::Veth,
    );
    peer_opts.mtu = data.mtu;
    peer_opts.netns = Some(netns_fd);

    let mut peer = netlink_packet_route::link::LinkMessage::default();
    netlink::parse_create_link_options(&mut peer, peer_opts);

    let mut host_veth = netlink::CreateLinkOptions::new(
        data.host_interface_name.clone(),
        netlink_packet_route::link::InfoKind::Veth,
    );
    host_veth.mtu = data.mtu;
    host_veth.primary_index = bridge_index;
    host_veth.info_data = Some(netlink_packet_route::link::InfoData::Veth(
        netlink_packet_route::link::InfoVeth::Peer(peer),
    ));

    host.create_link(host_veth)?;

    let veth = netns.get_link(netlink::LinkID::Name(data.container_interface_name.clone()))?;

    // Get MAC address
    let mut mac = String::new();
    for nla in veth.attributes.iter() {
        if let netlink_packet_route::link::LinkAttribute::Address(ref addr) = nla {
            mac = CoreUtils::encode_address_to_hex(addr);
            break;
        }
    }

    if mac.is_empty() {
        return Err(NetavarkError::msg("failed to get MAC address from container veth"));
    }

    // Configure container interface
    for addr in &data.ipam.container_addresses {
        netns.add_addr(veth.header.index, addr)?;
    }

    netns.set_up(netlink::LinkID::ID(veth.header.index))?;

    if !internal && !data.no_default_route {
        crate::network::core_utils::add_default_routes(netns, &data.ipam.gateway_addresses, data.metric)?;
    }

    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Network, PerNetworkOptions, Subnet};
    use std::collections::HashMap;

    fn create_test_network() -> Network {
        let mut options = HashMap::new();
        options.insert("vni".to_string(), "100".to_string());
        options.insert("local_ip".to_string(), "192.168.1.10".to_string());
        options.insert("remote_ips".to_string(), "192.168.1.11,192.168.1.12".to_string());
        options.insert("physical_interface".to_string(), "eth0".to_string());
        options.insert("vxlan_port".to_string(), "4789".to_string());

        Network {
            dns_enabled: true,
            driver: "vxlan".to_string(),
            id: "test-network-id".to_string(),
            internal: false,
            ipv6_enabled: false,
            name: "test-vxlan".to_string(),
            network_interface: Some("br-vxlan-test".to_string()),
            options: Some(options),
            ipam_options: None,
            subnets: Some(vec![Subnet {
                subnet: "10.0.0.0/24".parse().unwrap(),
                gateway: Some("10.0.0.1".parse().unwrap()),
                lease_range: None,
            }]),
            routes: None,
            network_dns_servers: None,
        }
    }

    fn create_test_per_network_options() -> PerNetworkOptions {
        PerNetworkOptions {
            interface_name: "eth0".to_string(),
            static_ips: Some(vec!["10.0.0.100".parse().unwrap()]),
            static_mac: None,
            aliases: None,
            options: None,
        }
    }

    #[test]
    fn test_vxlan_validation_success() {
        let network = create_test_network();
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_ok());
        
        // Check that data was populated
        assert!(vxlan.data.is_some());
        let data = vxlan.data.unwrap();
        assert_eq!(data.vni, 100);
        assert_eq!(data.local_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(data.remote_ips.len(), 2);
        assert_eq!(data.physical_interface, "eth0");
        assert_eq!(data.vxlan_port, 4789);
    }

    #[test]
    fn test_vxlan_validation_missing_vni() {
        let mut network = create_test_network();
        network.options.as_mut().unwrap().remove("vni");
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("VNI is required"));
    }

    #[test]
    fn test_vxlan_validation_invalid_vni() {
        let mut network = create_test_network();
        network.options.as_mut().unwrap().insert("vni".to_string(), "0".to_string());
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("VNI must be between 1 and 16777215"));
    }

    #[test]
    fn test_vxlan_validation_invalid_local_ip() {
        let mut network = create_test_network();
        network.options.as_mut().unwrap().insert("local_ip".to_string(), "invalid-ip".to_string());
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid local_ip format"));
    }

    #[test]
    fn test_vxlan_validation_invalid_remote_ips() {
        let mut network = create_test_network();
        network.options.as_mut().unwrap().insert("remote_ips".to_string(), "192.168.1.11,invalid-ip".to_string());
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid remote_ips format"));
    }

    #[test]
    fn test_vxlan_validation_default_port() {
        let mut network = create_test_network();
        network.options.as_mut().unwrap().remove("vxlan_port");
        let per_network_opts = create_test_per_network_options();
        
        let driver_info = DriverInfo {
            firewall: &crate::firewall::fwnone::FwNone,
            container_id: &"test-container".to_string(),
            container_name: &"test-container".to_string(),
            container_dns_servers: &None,
            netns_host: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_container: unsafe { std::os::fd::BorrowedFd::borrow_raw(0) },
            netns_path: "/proc/self/ns/net",
            network: &network,
            per_network_opts: &per_network_opts,
            port_mappings: &None,
            dns_port: 53,
            config_dir: std::path::Path::new("/tmp"),
            rootless: false,
            container_hostname: &None,
        };

        let mut vxlan = Vxlan::new(driver_info);
        let result = vxlan.validate();
        assert!(result.is_ok());
        
        let data = vxlan.data.unwrap();
        assert_eq!(data.vxlan_port, DEFAULT_VXLAN_PORT);
    }
}
