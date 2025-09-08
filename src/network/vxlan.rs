use std::{collections::HashMap, net::IpAddr, os::fd::BorrowedFd};

use crate::{
    dns::aardvark::AardvarkEntry,
    error::{ErrorWrap, NetavarkError, NetavarkResult},
    network::{
        constants::{
            DEFAULT_VXLAN_PORT, OPTION_LOCAL_IP, OPTION_PHYSICAL_INTERFACE, OPTION_REMOTE_IPS,
            OPTION_VNI, OPTION_VXLAN_PORT,
        },
        core_utils::{get_ipam_addresses, parse_option},
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
    #[allow(dead_code)]
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
        .unwrap_or_else(|| {
            // Generate a default host interface name based on container interface name
            format!("veth-{}", &self.info.per_network_opts.interface_name)
        });

        // Generate interface names
        let vxlan_interface_name = format!("vx{}", self.info.network.name);
        let bridge_interface_name = format!("brvx-{}", self.info.network.name);

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
            self.info.netns_path,
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
    _host: &mut netlink::Socket,
    _netns: &mut netlink::Socket,
    data: &VxlanInternalData,
    internal: bool,
    _rootless: bool,
    _hostns_fd: BorrowedFd<'_>,
    _netns_fd: BorrowedFd<'_>,
    netns_path: &str,
) -> NetavarkResult<String> {
    log::debug!("Creating VXLAN interfaces for network: {}", data.vxlan_interface_name);
    
    // Validate physical interface exists using system command instead of netlink
    // This avoids the netlink version compatibility issues
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["link", "show", &data.physical_interface]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to check physical interface: {}", e)))?;
    
    if !output.status.success() {
        return Err(NetavarkError::msg(format!("Physical interface {} not found", data.physical_interface)));
    }
    
    log::debug!("Physical interface {} validated", data.physical_interface);
    
    // Create or get bridge using system commands to avoid netlink issues
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["link", "show", &data.bridge_interface_name]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to check bridge interface: {}", e)))?;
    
    if !output.status.success() {
        // Create bridge using ip command
        log::debug!("Creating bridge interface: {}", data.bridge_interface_name);
        let mut cmd = std::process::Command::new("ip");
        cmd.args(["link", "add", "name", &data.bridge_interface_name, "type", "bridge"]);
        
        let output = cmd.output()
            .map_err(|e| NetavarkError::msg(format!("Failed to create bridge: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetavarkError::msg(format!("Failed to create bridge interface: {}", stderr)));
        }
        
        // Bring bridge up
        let mut cmd = std::process::Command::new("ip");
        cmd.args(["link", "set", "dev", &data.bridge_interface_name, "up"]);
        
        let output = cmd.output()
            .map_err(|e| NetavarkError::msg(format!("Failed to bring bridge up: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to bring bridge up: {}", stderr);
        }
        
        log::debug!("Bridge interface {} created and brought up", data.bridge_interface_name);
    } else {
        log::debug!("Bridge interface {} already exists", data.bridge_interface_name);
    }

    // Create VXLAN interface
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["link", "show", &data.vxlan_interface_name]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to check VXLAN interface: {}", e)))?;
    
    let _vxlan_index = if output.status.success() {
        log::debug!("VXLAN interface {} already exists", data.vxlan_interface_name);
        0 // Dummy index
    } else {
        // Create VXLAN interface using system command for now
        // TODO: Implement proper netlink VXLAN creation
        log::debug!("Creating VXLAN interface: {}", data.vxlan_interface_name);
        
        // Use ip command to create VXLAN interface
        let mut cmd = std::process::Command::new("ip");
        cmd.args([
            "link", "add", "name", &data.vxlan_interface_name,
            "type", "vxlan",
            "id", &data.vni.to_string(),
            "local", &data.local_ip.to_string(),
            "dstport", &data.vxlan_port.to_string()
        ]);
        
        // Add remote IPs (for unicast VXLAN)
        for remote_ip in &data.remote_ips {
            cmd.args(["remote", &remote_ip.to_string()]);
        }
        
        log::debug!("Executing VXLAN creation command: {:?}", cmd);
        
        let output = cmd.output()
            .map_err(|e| NetavarkError::msg(format!("Failed to execute ip command: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            log::error!("VXLAN creation failed - stderr: {}, stdout: {}", stderr, stdout);
            return Err(NetavarkError::msg(format!("Failed to create VXLAN interface: {}", stderr)));
        }
        
        log::debug!("VXLAN interface {} created successfully", data.vxlan_interface_name);
        
        // Bring VXLAN interface up using ip command
        let mut cmd = std::process::Command::new("ip");
        cmd.args(["link", "set", "dev", &data.vxlan_interface_name, "up"]);
        
        let output = cmd.output()
            .map_err(|e| NetavarkError::msg(format!("Failed to bring VXLAN up: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to bring VXLAN up: {}", stderr);
        }
        
        // Return a dummy index since we're not using netlink anymore
        0
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

    // Create veth pair using system commands
    log::debug!("Creating veth pair: {} <-> {}", data.host_interface_name, data.container_interface_name);
    
    // Clean up existing veth interfaces if they exist
    log::debug!("Cleaning up existing veth interfaces if they exist");
    
    // Check what interfaces exist and log them
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["link", "show"]);
    let output = cmd.output();
    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        log::debug!("Existing interfaces: {}", stdout);
    }
    
    // Try multiple cleanup strategies
    let cleanup_commands = vec![
        vec!["link", "del", "dev", &data.host_interface_name],
        vec!["link", "del", "dev", &data.container_interface_name],
        vec!["link", "del", &data.host_interface_name],
        vec!["link", "del", &data.container_interface_name],
    ];
    
    for cmd_args in cleanup_commands {
        let mut cmd = std::process::Command::new("ip");
        cmd.args(&cmd_args);
        let output = cmd.output();
        if let Ok(output) = output {
            if output.status.success() {
                log::debug!("Successfully removed interface with command: ip {}", cmd_args.join(" "));
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::debug!("Cleanup command failed (expected): ip {} - {}", cmd_args.join(" "), stderr);
            }
        }
    }
    
    // Also try to remove from container namespace
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["netns", "exec", "/proc/self/ns/net", "ip", "link", "del", "dev", &data.container_interface_name]);
    let output = cmd.output();
    if let Ok(output) = output {
        if output.status.success() {
            log::debug!("Removed existing container veth from container namespace: {}", data.container_interface_name);
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::debug!("Container namespace cleanup failed (expected): {}", stderr);
        }
    }
    
    // Create veth pair with temporary names first, then rename
    let temp_container_name = format!("{}_tmp", data.container_interface_name);
    
    let mut cmd = std::process::Command::new("ip");
    cmd.args([
        "link", "add", "name", &data.host_interface_name,
        "type", "veth", "peer", "name", &temp_container_name
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to create veth pair: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetavarkError::msg(format!("Failed to create veth pair: {}", stderr)));
    }
    
    // Move container veth to target container namespace using PID parsed from netns_path
    log::debug!("Attempting to parse netns path: {}", netns_path);
    let target_pid = extract_pid_from_netns_path(netns_path)
        .ok_or_else(|| NetavarkError::msg(format!("failed to parse target netns PID from path: {}", netns_path)))?;
    log::debug!("Extracted target PID: {}", target_pid);

    let mut cmd = std::process::Command::new("ip");
    if target_pid.starts_with("/run/netns/") || target_pid.starts_with("/var/run/netns/") {
        // Named namespace
        cmd.args([
            "link", "set", "dev", &temp_container_name,
            "netns", &target_pid
        ]);
    } else {
        // PID-based namespace
        cmd.args([
            "link", "set", "dev", &temp_container_name,
            "netns", &target_pid
        ]);
    }
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to move veth to container namespace: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetavarkError::msg(format!("Failed to move veth to container namespace: {}", stderr)));
    }
    
    // Rename the container veth to the desired name within the container namespace
    let mut cmd = create_namespace_cmd(&target_pid, "ip", &[
        "link", "set", "dev", &temp_container_name, "name", &data.container_interface_name
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to rename container veth: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to rename container veth (may already have correct name): {}", stderr);
    }
    
    // Connect host veth to bridge
    let mut cmd = std::process::Command::new("ip");
    cmd.args([
        "link", "set", "dev", &data.host_interface_name,
        "master", &data.bridge_interface_name
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to connect veth to bridge: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to connect veth to bridge: {}", stderr);
    }
    
    // Bring host veth up
    let mut cmd = std::process::Command::new("ip");
    cmd.args(["link", "set", "dev", &data.host_interface_name, "up"]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to bring host veth up: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to bring host veth up: {}", stderr);
    }

    // Configure container interface using system commands
    log::debug!("Configuring container interface: {}", data.container_interface_name);
    
    // Get MAC address using ip command inside container namespace
    let mut cmd = create_namespace_cmd(&target_pid, "ip", &[
        "link", "show", &data.container_interface_name
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to get container interface info: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NetavarkError::msg(format!("Failed to get container interface info: {}", stderr)));
    }
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mac = extract_mac_from_ip_output(&output_str)
        .ok_or_else(|| NetavarkError::msg("Failed to extract MAC address from ip output"))?;
    
    log::debug!("Container interface MAC: {}", mac);
    
    // Configure container interface IP addresses
    for addr in &data.ipam.container_addresses {
        let mut cmd = create_namespace_cmd(&target_pid, "ip", &[
            "addr", "add", &addr.to_string(), "dev", &data.container_interface_name
        ]);
        
        let output = cmd.output()
            .map_err(|e| NetavarkError::msg(format!("Failed to add IP to container interface: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to add IP {} to container interface: {}", addr, stderr);
        }
    }
    
    // Bring container interface up
    let mut cmd = create_namespace_cmd(&target_pid, "ip", &[
        "link", "set", "dev", &data.container_interface_name, "up"
    ]);
    
    let output = cmd.output()
        .map_err(|e| NetavarkError::msg(format!("Failed to bring container interface up: {}", e)))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to bring container interface up: {}", stderr);
    }

    // Add default routes using system commands
    if !internal && !data.no_default_route {
        for gateway in &data.ipam.gateway_addresses {
            // Ensure gateway string has no CIDR suffix
            let gw_str = gateway.to_string();
            let gw_no_cidr = gw_str.split('/').next().unwrap_or(&gw_str);

            let mut cmd = create_namespace_cmd(&target_pid, "ip", &[
                "route", "add", "default", "via", gw_no_cidr
            ]);
            
            if let Some(metric) = data.metric {
                cmd.args(["metric", &metric.to_string()]);
            }
            
            let output = cmd.output()
                .map_err(|e| NetavarkError::msg(format!("Failed to add default route: {}", e)))?;
            
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to add default route via {}: {}", gateway, stderr);
            }
        }
    }

    Ok(mac)
}

// Helper function to extract MAC address from ip link show output
fn extract_mac_from_ip_output(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("link/ether") {
            // Extract MAC address from line like: "    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff"
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, part) in parts.iter().enumerate() {
                if part == &"link/ether" && i + 1 < parts.len() {
                    return Some(parts[i + 1].to_string());
                }
            }
        }
    }
    None
}

// Helper function to create namespace-aware command
fn create_namespace_cmd(target_pid: &str, base_cmd: &str, args: &[&str]) -> std::process::Command {
    if target_pid.starts_with("/run/netns/") || target_pid.starts_with("/var/run/netns/") {
        // Named namespace - use ip netns exec
        let mut cmd = std::process::Command::new("ip");
        let namespace_name = if target_pid.starts_with("/run/netns/") {
            target_pid.strip_prefix("/run/netns/").unwrap_or(target_pid)
        } else {
            target_pid.strip_prefix("/var/run/netns/").unwrap_or(target_pid)
        };
        let mut cmd_args = vec!["netns", "exec", namespace_name, base_cmd];
        cmd_args.extend(args);
        cmd.args(cmd_args);
        cmd
    } else {
        // PID-based namespace - use nsenter
        let mut cmd = std::process::Command::new("nsenter");
        let mut cmd_args = vec!["-t", target_pid, "-n", base_cmd];
        cmd_args.extend(args);
        cmd.args(cmd_args);
        cmd
    }
}

// Extract PID from typical netns path formats used by podman/netavark
// Examples:
//  - /proc/<pid>/ns/net
//  - /proc/self/ns/net -> resolve to actual PID
//  - /var/run/netns/<name> -> handle named namespaces
fn extract_pid_from_netns_path(path: &str) -> Option<String> {
    log::debug!("Parsing netns path: {}", path);
    
    // Handle /proc/self/ns/net by resolving to actual PID
    if path == "/proc/self/ns/net" {
        // Read /proc/self to get the actual PID
        if let Ok(link) = std::fs::read_link("/proc/self") {
            if let Some(pid_str) = link.to_str() {
                log::debug!("Resolved /proc/self to PID: {}", pid_str);
                return Some(pid_str.to_string());
            }
        }
        log::debug!("Failed to resolve /proc/self");
        return None;
    }
    
    // Handle /proc/<pid>/ns/net
    if path.starts_with("/proc/") && path.ends_with("/ns/net") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 {
            let pid_part = parts[2]; // index 0:"", 1:"proc", 2:"<pid>"
            // If it's a number, return it
            if pid_part.chars().all(|c| c.is_ascii_digit()) {
                log::debug!("Extracted PID from /proc/<pid>/ns/net: {}", pid_part);
                return Some(pid_part.to_string());
            }
        }
    }
    
    // Handle named namespaces like /run/netns/<name> or /var/run/netns/<name>
    if path.starts_with("/run/netns/") || path.starts_with("/var/run/netns/") {
        log::debug!("Named namespace detected: {}", path);
        // For named namespaces, we can use the path directly with ip netns
        return Some(path.to_string());
    }
    
    log::debug!("Could not parse netns path: {}", path);
    None
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
            network_interface: Some("brvx-test".to_string()),
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
