import pandas as pd
import getpass
import re
import subprocess
from netmiko import ConnectHandler
import uuid
import logging
import xml.etree.ElementTree as ET
import os
import html

# Enable detailed logging
logging.basicConfig(
    filename='netmiko_debug.log',
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s: %(message)s'
)
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)

# Function to convert interface name
def convert_interface_name(interface):
    logging.debug(f"Converting interface name: {interface}")
    interface_map = {
        r'^GigabitEthernet': 'Gi',
        r'^Ethernet': 'Eth',
        r'^FastEthernet': 'Fa',
        r'^TenGigabitEthernet': 'Te',
        r'^TwentyFiveGigE': 'Tw',
        r'^FortyGigE': 'Fo',
        r'^HundredGigE': 'Hu',
        r'^Serial': 'Se',
        r'^Port-channel': 'Po',
        r'^Vlan': 'Vl',
        r'^Loopback': 'Lo',
    }
    # Loop through interface_map keys to make them case-insensitive
    for pattern, short_form in interface_map.items():
        if re.match(pattern, interface, re.IGNORECASE):
            return re.sub(pattern, short_form, interface, flags=re.IGNORECASE)
    return interface


def parse_cdp_table(output):
    """Parse table-style 'show cdp neighbors' output."""
    logging.debug("Parsing CDP table output (non-detail).")
    rows = []
    table_re = re.compile(r"^(?P<device>\S+)\s+(?P<local>[A-Za-z0-9\/\.\-]+)\s+\d+\s+.+?\s+(?P<remote>[A-Za-z0-9\/\.\-]+),?$")
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith('capability codes') or line.lower().startswith('device-id'):
            continue
        m = table_re.match(line)
        if m:
            rows.append((m.group('device').strip(), None, m.group('local').strip().rstrip(','), m.group('remote').strip().rstrip(',')))
    return rows


def parse_cdp_detail(output):
    """Parse 'show cdp neighbors detail' output."""
    logging.debug("Parsing CDP detail output.")
    neighbors = []
    for block in re.split(r"-------------------------[\s\r\n]*", output):
        if 'Device ID' not in block:
            continue
        dev_id_match = re.search(r'Device ID:\s*(.+)', block)
        ip_match = re.search(r'IP address:\s*([\d\.]+)', block, re.IGNORECASE)
        if_match = re.search(r'Interface:\s*(.+?),\s*Port ID \(outgoing port\):\s*(.+)', block, re.IGNORECASE)
        if dev_id_match and if_match:
            neighbors.append((dev_id_match.group(1).strip(), ip_match.group(1).strip() if ip_match else None, if_match.group(1).strip(), if_match.group(2).strip()))
    return neighbors

def parse_lldp_detail(output):
    """Parse LLDP 'show lldp neighbors detail' blocks."""
    logging.debug("Parsing LLDP detail output.")
    rows = []
    for blk in re.split(r"\n-{2,}\n|\n\s*\n", output):
        if not blk.strip(): continue
        sys_m = re.search(r"System Name:\s*(.+)", blk)
        if not sys_m: continue
        local_m = re.search(r"Local\s+(?:Port\s+id|Intf):\s*([A-Za-z0-9\/\.\-]+)", blk)
        port_m = re.search(r"Port\s+id:\s*([A-Za-z0-9\/\.\-]+)", blk)
        ip_m = re.search(r"Management\s+Address.*?IP:\s*([\d\.]+)", blk, re.DOTALL)
        if local_m and port_m:
            rows.append((sys_m.group(1).strip(), ip_m.group(1).strip() if ip_m else None, local_m.group(1).strip(), port_m.group(1).strip()))
    return rows

def parse_etherchannel_summary(output):
    """Parses 'show etherchannel summary' to map member ports to port-channels."""
    logging.debug("Parsing etherchannel summary.")
    member_map = {}
    port_re = re.compile(r"([A-Za-z0-9\/\.\-]+)\(P\)")
    for line in output.strip().splitlines():
        if not line.strip() or not line.strip()[0].isdigit():
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        po_name_raw = parts[1].split('(')[0]
        logical_interface = convert_interface_name(po_name_raw)
        members = port_re.findall(line)
        for member in members:
            member_name = convert_interface_name(member)
            member_map[member_name] = logical_interface
            logging.debug(f"Mapped member {member_name} to {logical_interface}")
    return member_map

def parse_switchport_info(switchport_output):
    """Parses 'show interface switchport' output."""
    logging.debug("Parsing switchport info.")
    interface_vlan_map = {}
    current_interface = None
    interface_info = {}

    def process_interface_info():
        if not current_interface or not interface_info: return
        mode_line = interface_info.get("Operational Mode") or interface_info.get("Administrative Mode")
        if not mode_line: return
        if "access" in mode_line:
            vlan_id = interface_info.get("Access Mode VLAN", "N/A").split()[0]
            interface_vlan_map[current_interface] = {'mode': 'access', 'vlan': vlan_id}
        elif "trunk" in mode_line or "dynamic" in mode_line:
            native_id = interface_info.get("Trunking Native Mode VLAN", "N/A").split()[0]
            allowed = interface_info.get("Trunking VLANs Enabled") or interface_info.get("Trunking VLANs Allowed") or "N/A"
            interface_vlan_map[current_interface] = {'mode': 'trunk', 'native_vlan': native_id, 'allowed': allowed}

    for line in switchport_output.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            process_interface_info()
            current_interface = convert_interface_name(line.split(":", 1)[1].strip())
            interface_info = {}
        elif current_interface and ":" in line:
            key, value = [x.strip() for x in line.split(":", 1)]
            interface_info[key] = value
    process_interface_info()
    return interface_vlan_map

def parse_all_interface_ips(brief_output):
    """Parses 'show ip interface brief' output."""
    logging.debug("Parsing all interface IPs.")
    ip_map = {}
    ip_re = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    for line in brief_output.strip().splitlines():
        parts = line.split()
        if not parts or parts[0].lower() in ("interface", "ip"): continue
        ip_match = ip_re.search(line)
        if ip_match:
            ip_map[convert_interface_name(parts[0])] = ip_match.group(1)
    return ip_map

def parse_nxos_trunk(trunk_output):
    """Parses the specific 'show interface trunk' format provided by the user."""
    logging.debug("Parsing custom NX-OS trunk info from 'show interface trunk'.")
    port_vlan_map = {}
    if not trunk_output: return {}

    # Split by the '----' separator lines, which frames the data tables.
    sections = re.split(r'-{20,}', trunk_output)
    if len(sections) < 5:
        logging.warning(f"Could not find enough sections in 'show interface trunk' output. Found {len(sections)} sections.")
        return {}

    # --- Section 1: Native VLANs and Status (Data is in sections[2]) ---
    native_vlan_map = {}
    try:
        table1_lines = sections[2].strip().splitlines()
        for line in table1_lines:
            parts = line.split()
            if len(parts) < 3:
                logging.warning(f"Skipping line in native VLAN section due to insufficient parts: '{line}'")
                continue
            if not (parts[2] == 'trunking' or parts[2] == 'trnk-bndl'):
                logging.warning(f"Skipping line in native VLAN section due to non-trunk status: '{line}'")
                continue
            
            port = convert_interface_name(parts[0])
            native_vlan = parts[1]
            native_vlan_map[port] = native_vlan
    except IndexError as e:
        logging.error(f"Error parsing native VLAN section from NX-OS trunk output: {e}", exc_info=True)
        return {}

    # --- Section 2: Allowed VLANs (Data is in sections[4]) ---
    try:
        table2_lines = sections[4].strip().splitlines()
        for line in table2_lines:
            parts = line.split()
            if len(parts) < 2:
                logging.warning(f"Skipping line in allowed VLAN section due to insufficient parts: '{line}'")
                continue
            
            port = convert_interface_name(parts[0])
            if port not in native_vlan_map:
                logging.warning(f"Skipping line in allowed VLAN section, port '{port}' not found in native_vlan_map: '{line}'")
                continue
            
            allowed_vlans = " ".join(parts[1:])
            port_vlan_map[port] = {
                'mode': 'trunk',
                'native_vlan': native_vlan_map[port],
                'allowed': allowed_vlans
            }
    except IndexError as e:
        logging.error(f"Error parsing allowed VLANs section from NX-OS trunk output: {e}", exc_info=True)
    
    logging.info(f"Parsed {len(port_vlan_map)} trunks from custom 'show interface trunk' parser: {list(port_vlan_map.keys())}")
    return port_vlan_map


def update_interface_descriptions(device_info, update_desc):
    """Connects to a single device, gathers information, and returns it."""
    try:
        logging.info(f"Connecting to {device_info['host']}...")
        net_connect = ConnectHandler(**device_info)
        net_connect.enable()
        hostname = re.search(r'^([a-zA-Z0-9_.-]+)', net_connect.find_prompt()).group(1)
        logging.info(f"Connected to {hostname}.")

        is_router = 'router' in device_info.get('device_type', '')

        port_channel_map = {}
        if not is_router:
            etherchannel_cmd = "show etherchannel summary"
            if device_info['device_type'] == 'cisco_nxos':
                etherchannel_cmd = "show port-channel summary"
            try:
                logging.info(f"[{hostname}] Gathering port-channel info...")
                etherchannel_output = net_connect.send_command(etherchannel_cmd, delay_factor=2)
                port_channel_map = parse_etherchannel_summary(etherchannel_output)
                logging.info(f"[{hostname}] Found {len(port_channel_map)} port-channel member interfaces.")
            except Exception as e:
                logging.warning(f"Could not get port-channel info from {hostname}: {e}")
                port_channel_map = {}
        else:
            logging.info(f"[{hostname}] Skipping port-channel info gathering for router.")

        logging.info(f"[{hostname}] Step 1: Gathering IP interfaces...")
        ip_brief_cmd = "show ip interface brief vrf all" if device_info['device_type'] == 'cisco_nxos' else "show ip interface brief"
        all_ips_map = parse_all_interface_ips(net_connect.send_command(ip_brief_cmd, delay_factor=2))
        logging.info(f"[{hostname}] Found {len(all_ips_map)} IP addresses.")

        logging.info(f"[{hostname}] Step 2: Gathering switchport information...")
        port_vlan_map = {}
        if not is_router:
            try:
                if device_info['device_type'] == 'cisco_nxos':
                    logging.info(f"[{hostname}] NX-OS: Getting switchport info...")
                    sw_output = net_connect.send_command("show interface switchport", delay_factor=3)
                    if sw_output:
                        # Use the general parser, which should handle access ports and some trunks.
                        port_vlan_map = parse_switchport_info(sw_output)
                    
                    logging.info(f"[{hostname}] NX-OS: Getting definitive trunk info from 'show interface trunk'.")
                    trunk_output = net_connect.send_command("show interface trunk", delay_factor=3)
                    if trunk_output:
                        trunk_map = parse_nxos_trunk(trunk_output)
                        # Merge, with trunk_map taking precedence for trunk ports.
                        port_vlan_map.update(trunk_map)
                else:  # For IOS and others
                    logging.info(f"[{hostname}] IOS/other: Getting all switchports from 'show interface switchport'.")
                    sw_output = net_connect.send_command("show interface switchport", delay_factor=3)
                    if sw_output and "Invalid input" not in sw_output:
                        port_vlan_map = parse_switchport_info(sw_output)

                logging.info(f"[{hostname}] Parsed info for {len(port_vlan_map)} switchports.")
                
                # --- START DEBUG PRINTS ---
                print(f"\n--- DEBUG for {hostname} ---")
                print(f"Port-Channel Map (keys): {list(port_channel_map.keys())}")
                print(f"Port-VLAN Map (keys): {list(port_vlan_map.keys())}")
                # --- END DEBUG PRINTS ---

            except Exception as e:
                logging.error(f"[{hostname}] Failed to gather switchport info: {e}", exc_info=True)
                port_vlan_map = {}
        else:
            logging.info(f"[{hostname}] Skipping switchport info gathering for router.")
        
        logging.info(f"[{hostname}] Step 3: Gathering neighbor information using CDP and LLDP...")
        neighbors = []
        processed_local_interfaces = set()

        # Try CDP first
        try:
            logging.info(f"[{hostname}] Trying CDP to gather neighbors...")
            detail_output = net_connect.send_command('show cdp neighbors detail', delay_factor=2)
            cdp_neighbors = parse_cdp_detail(detail_output)
            if not cdp_neighbors:
                logging.info(f"[{hostname}] No CDP detail found, falling back to non-detail command.")
                table_output = net_connect.send_command('show cdp neighbor', delay_factor=2)
                cdp_neighbors = parse_cdp_table(table_output)

            for neighbor in cdp_neighbors:
                # neighbor format: (dev_id, neighbor_ip, local_if, remote_if)
                local_if = neighbor[2]
                local_if_short = convert_interface_name(local_if)
                if local_if_short not in processed_local_interfaces:
                    neighbors.append(neighbor)
                    processed_local_interfaces.add(local_if_short)
            logging.info(f"[{hostname}] Found {len(neighbors)} neighbors via CDP.")
        except Exception as e:
            logging.warning(f"[{hostname}] Could not gather CDP neighbors (command may not be supported): {e}")

        # Then try LLDP for interfaces not already covered by CDP
        try:
            logging.info(f"[{hostname}] Trying LLDP to gather additional neighbors...")
            lldp_detail_output = net_connect.send_command('show lldp neighbors detail', delay_factor=2)
            lldp_neighbors = parse_lldp_detail(lldp_detail_output)
            
            new_lldp_neighbors_count = 0
            for neighbor in lldp_neighbors:
                local_if = neighbor[2]
                local_if_short = convert_interface_name(local_if)
                if local_if_short not in processed_local_interfaces:
                    neighbors.append(neighbor)
                    processed_local_interfaces.add(local_if_short)
                    new_lldp_neighbors_count += 1
            if new_lldp_neighbors_count > 0:
                logging.info(f"[{hostname}] Found {new_lldp_neighbors_count} new neighbors via LLDP.")
        except Exception as e:
            logging.warning(f"[{hostname}] Could not gather LLDP neighbors (command may not be supported): {e}")

        logging.info(f"[{hostname}] Found a total of {len(neighbors)} unique neighbors.")

        logging.info(f"[{hostname}] Step 4: Processing connections...")
        connections = []
        for dev_id, neighbor_ip, local_if, remote_if in neighbors:
            local_if_short = convert_interface_name(local_if)
            remote_if_short = convert_interface_name(remote_if)
            
            effective_interface = port_channel_map.get(local_if_short, local_if_short)
            port_channel_info = "N/A"
            if effective_interface != local_if_short:
                logging.info(f"[{hostname}] Interface {local_if_short} is part of {effective_interface}.")
                port_channel_info = effective_interface
            
            # --- START DEBUG PRINTS ---
            print(f"Processing interface: {local_if_short} -> Effective: {effective_interface}")
            port_details = port_vlan_map.get(effective_interface)
            print(f"Effective Interface '{effective_interface}' found in port_vlan_map: {effective_interface in port_vlan_map}")
            if port_details:
                print(f"Port Details for {effective_interface}: mode={port_details.get('mode')}, native_vlan={port_details.get('native_vlan')}, allowed={port_details.get('allowed')}")
            else:
                print(f"No port details found for {effective_interface}")
            # --- END DEBUG PRINTS ---

            ip_addr, vlan_info, trunk_info = "N/A", "N/A", "N/A"
            if port_details: # Check if port_details is not None
                if port_details.get('mode') == 'access':
                    vlan_info = port_details.get('vlan', 'N/A')
                    ip_addr = all_ips_map.get(convert_interface_name(f"Vlan{vlan_info}"), "N/A")
                else:  # trunk
                    vlan_info = port_details.get('native_vlan', 'N/A')
                    trunk_info = f"Allowed: {port_details.get('allowed', 'N/A')}"
                    ip_addr = all_ips_map.get(convert_interface_name(f"Vlan{vlan_info}"), "N/A")
            if ip_addr == "N/A": ip_addr = all_ips_map.get(effective_interface, "N/A")
            
            if update_desc == 'y':
                try:
                    logging.info(f"[{hostname}] Setting description for {local_if_short}")
                    config_commands = [f"interface {local_if_short}", f"description Connected to {dev_id} - {remote_if_short}"]
                    net_connect.send_config_set(config_commands)
                except Exception as e:
                    logging.warning(f"[{hostname}] Failed to set description for {local_if_short}: {e}")

            connections.append({'data': [hostname, local_if_short, port_channel_info, vlan_info, trunk_info, ip_addr, dev_id, remote_if_short], 'neighbor_ip': neighbor_ip})
        if not connections:
            connections.append({'data': [hostname, 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'], 'neighbor_ip': None})
        
        if update_desc == 'y':
            try:
                logging.info(f"[{hostname}] Saving configuration...")
                net_connect.save_config()
            except Exception as e:
                logging.warning(f"[{hostname}] Failed to save configuration: {e}")

        net_connect.disconnect()
        return hostname, all_ips_map, connections
    except Exception as e:
        logging.error(f"Error on device {device_info['host']}: {e}", exc_info=True)
        return None, None, []
def is_ip_reachable(ip):
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "1", ip], check=True, capture_output=True).returncode == 0
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def generate_drawio_topology(df, all_processed_hosts, all_device_ips=None):
    """
    Generates a Draw.io XML topology.
    - Aggregates parallel links between devices.
    - Displays SVI IPs on device nodes.
    - Removes arrows from links.
    """
    def generate_unique_id(): return str(uuid.uuid4())
    def canonical_name(name, all_names):
        if not isinstance(name, str) or not name: return name
        n = name.strip().split('.')[0]
        m = re.match(r"^(.+?)\((.+?)\)", n)
        if m:
            prefix, inner = m.group(1).strip(), m.group(2).strip()
            candidates = [o.split('.')[0] for o in all_names if isinstance(o, str) and inner in o]
            blacklist = {'switch', 'kernel', 'interface', 'local', 'remote', 'platform', 'ipv4', 'address'}
            best = min([c for c in candidates if c.lower() not in blacklist] or [prefix], key=len)
            return best
        return n

    def generate_drawio_xml_elements(df):
        elements = []
        unique_ids = {}
        x_pos, y_pos = 100, 100

        df = df[df['Hostname-B'] != 'N/A'].copy()

        all_raw_hostnames = set(pd.concat([df['Hostname-A'], df['Hostname-B']]).dropna().unique()) | all_processed_hosts
        all_canon_names = {canonical_name(h, all_raw_hostnames) for h in all_raw_hostnames}
        
        ip_map, vlan_map, trunk_map = {}, {}, {}
        for _, row in df.iterrows():
            host_a_cn = canonical_name(row['Hostname-A'], all_raw_hostnames)
            iface_a = str(row['Interface-A'])
            if iface_a == 'N/A': continue
            iface_a_cn = convert_interface_name(iface_a)
            if row.get('IP-A') and row['IP-A'] != 'N/A': ip_map[(host_a_cn, iface_a_cn)] = row['IP-A']
            if row.get('VLAN-A') and row['VLAN-A'] != 'N/A': vlan_map[(host_a_cn, iface_a_cn)] = row['VLAN-A']
            if row.get('Trunk-A') and row['Trunk-A'] != 'N/A': trunk_map[(host_a_cn, iface_a_cn)] = True

        interface_to_po_map = {}
        for _, row in df.iterrows():
            if row.get('Port-Channel-A') and row['Port-Channel-A'] != 'N/A':
                host_cn = canonical_name(row['Hostname-A'], all_raw_hostnames)
                iface_cn = convert_interface_name(row['Interface-A'])
                po_cn = convert_interface_name(row['Port-Channel-A'])
                interface_to_po_map[(host_cn, iface_cn)] = po_cn

        svi_map = {cn: set() for cn in all_canon_names}
        if all_device_ips:
            for raw_host, device_ip_map in all_device_ips.items():
                cn = canonical_name(raw_host, all_raw_hostnames)
                if cn in svi_map and device_ip_map:
                    for iface, ip in device_ip_map.items():
                        if iface.lower().startswith('vl'): svi_map[cn].add(f"{iface}: {ip}")

        edges_map = {}
        for _, row in df[df['Hostname-B'].notna()].iterrows():
            cn_a = canonical_name(row['Hostname-A'], all_raw_hostnames)
            cn_b = canonical_name(row['Hostname-B'], all_raw_hostnames)
            key = tuple(sorted([cn_a, cn_b]))
            edges_map.setdefault(key, []).append(row)

        for cn in sorted(list(all_canon_names)):
            unique_ids[cn] = generate_unique_id()
            label_parts = [cn] + sorted(list(svi_map.get(cn, [])))
            label = '<br>'.join(html.escape(p) for p in label_parts)
            style = 'shape=ellipse;whiteSpace=wrap;html=1;align=center;'
            node_el = ET.Element('mxCell', {'id': unique_ids[cn], 'value': label, 'style': style, 'vertex': '1', 'parent': '1'})
            ET.SubElement(node_el, 'mxGeometry', {'x': str(x_pos), 'y': str(y_pos), 'width': '160', 'height': '120', 'as': 'geometry'})
            elements.append(node_el)
            x_pos += 200

        def create_label(iface_name, host_name_cn):
            ip = ip_map.get((host_name_cn, iface_name))
            vlan = vlan_map.get((host_name_cn, iface_name))
            is_trunk = trunk_map.get((host_name_cn, iface_name))
            label = str(iface_name)
            vlan_label = ""
            if is_trunk:
                vlan_label = ":T"
            elif vlan:  # Access
                vlan_label = f" [VLAN {vlan}]"
            label += vlan_label
            if ip and ip != "N/A":
                label += f" ({ip})"
            return label

        for (host_a_cn, host_b_cn), rows in edges_map.items():
            src_id, tgt_id = unique_ids.get(host_a_cn), unique_ids.get(host_b_cn)
            if not src_id or not tgt_id: continue

            interface_pairs = set()
            for row in rows:
                if_a_host = canonical_name(row['Hostname-A'], all_raw_hostnames)
                if_b_host = canonical_name(row['Hostname-B'], all_raw_hostnames)
                if_a = convert_interface_name(str(row['Interface-A']))
                if_b = convert_interface_name(str(row['Interface-B']))
                if {if_a_host, if_b_host} == {host_a_cn, host_b_cn}:
                    if if_a_host == host_a_cn:
                        interface_pairs.add((if_a, if_b))
                    else:
                        interface_pairs.add((if_b, if_a))

            edge_label = str(len(interface_pairs))
            edge_id = generate_unique_id()
            edge_style = "edgeStyle=orthogonalEdgeStyle;startArrow=none;endArrow=none;align=center;verticalAlign=middle;"
            edge_el = ET.Element('mxCell', {'id': edge_id, 'value': edge_label, 'style': edge_style, 'edge': '1', 'parent': '1', 'source': src_id, 'target': tgt_id})
            ET.SubElement(edge_el, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
            elements.append(edge_el)

            po_groups_a, standalone_if_a = {}, set()
            for iface, _ in interface_pairs:
                po = interface_to_po_map.get((host_a_cn, iface))
                if po: po_groups_a.setdefault(po, set()).add(iface)
                else: standalone_if_a.add(iface)

            po_groups_b, standalone_if_b = {}, set()
            for _, iface in interface_pairs:
                po = interface_to_po_map.get((host_b_cn, iface))
                if po: po_groups_b.setdefault(po, set()).add(iface)
                else: standalone_if_b.add(iface)

            final_labels_a = []
            for po, members in sorted(po_groups_a.items()):
                # A member interface's trunk status represents the PO's status
                is_trunk = any(trunk_map.get((host_a_cn, m)) for m in members)
                trunk_info = ":T" if is_trunk else ""
                final_labels_a.append(f"{po}{trunk_info}:{','.join(sorted(list(members)))}")
            for iface in sorted(list(standalone_if_a)):
                final_labels_a.append(create_label(iface, host_a_cn))

            final_labels_b = []
            for po, members in sorted(po_groups_b.items()):
                # A member interface's trunk status represents the PO's status
                is_trunk = any(trunk_map.get((host_b_cn, m)) for m in members)
                trunk_info = ":T" if is_trunk else ""
                final_labels_b.append(f"{po}{trunk_info}:{','.join(sorted(list(members)))}")
            for iface in sorted(list(standalone_if_b)):
                final_labels_b.append(create_label(iface, host_b_cn))
            
            for lbls, x_pos_rel in [(final_labels_a, -0.8), (final_labels_b, 0.8)]:
                if not lbls: continue
                label_el = ET.Element('mxCell', {'value': ", ".join(lbls), 'style': 'text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];', 'vertex': '1', 'connectable': '0', 'parent': edge_id})
                geo = ET.SubElement(label_el, 'mxGeometry', {'x': str(x_pos_rel), 'y': '10', 'relative': '1', 'as': 'geometry'})
                ET.SubElement(geo, 'mxPoint', {'as': 'offset'})
                elements.append(label_el)
        return elements

    # UnboundLocalError 방지를 위해 변수들을 명시적으로 초기화
    mxfile = None
    diagram = None
    mxGraphModel = None
    root = None

    try:
        mxfile = ET.Element('mxfile')
        diagram = ET.SubElement(mxfile, 'diagram')
        mxGraphModel = ET.SubElement(diagram, 'mxGraphModel') # This is line 540 in my file
        root = ET.SubElement(mxGraphModel, 'root')
        ET.SubElement(root, 'mxCell', {'id': '0'})
        ET.SubElement(root, 'mxCell', {'id': '1', 'parent': '0'})
        for el in generate_drawio_xml_elements(df):
            root.append(el)

        output_file = "network_topology_filtered.xml"
        with open(output_file, "w") as file:
            file.write(ET.tostring(mxfile, encoding='unicode'))
        print(f"Draw.io-compatible topology XML file saved as {output_file}")

    except Exception as e:
        logging.error(f"Error generating Draw.io topology: {e}", exc_info=True)
        print("Error generating Draw.io topology. Check log for details.")


def read_device_list(filename="device_list.txt"):
    """Reads a list of device IPs from a file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    if not os.path.exists(file_path):
        print(f"Error: Device list file not found at {file_path}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

if __name__ == "__main__":
    logging.info("--- Script execution started ---")
    update_desc = input("Do you want to update interface descriptions? (y/n): ").lower()
    recursive_choice = input("Automatically discover and process all neighbors recursively? (y/n): ").lower()
    device_info_template = {
        "device_type": "cisco_ios",
        "username": input("Enter username: "),
        "password": getpass.getpass("Enter password: "),
        "secret": getpass.getpass("Enter enable password (press Enter if none): "),
        "session_log": "netmiko_session.log",
    }
    
    main_hosts = read_device_list()
    if not main_hosts:
        print("Device list is empty or 'device_list.txt' not found. Exiting.")
        exit()

    neighbor_data, processed_hostnames, all_device_ips = [], set(), {}
    print("\nStarting network discovery...")
    
    hosts_to_process = list(main_hosts)
    processed_ips = set()

    if recursive_choice != 'y':
        logging.info("--- Recursive discovery DISABLED ---")
        hosts_to_process = main_hosts
    else:
        logging.info("--- Recursive discovery ENABLED ---")

    while hosts_to_process:
        host_ip = hosts_to_process.pop(0)
        if host_ip in processed_ips: continue
        
        logging.info(f"--- Processing device: {host_ip} ---")
        print(f"--- Processing device: {host_ip} ---")
        processed_ips.add(host_ip)

        device_info = device_info_template.copy()
        device_info['host'] = host_ip
        try:
            logging.info(f"Probing device type for {host_ip}...")
            with ConnectHandler(**device_info) as probe_conn:
                version_out = probe_conn.send_command('show version', delay_factor=2)
                if 'nx-os' in version_out.lower() or 'nexus' in version_out.lower():
                    device_info['device_type'] = 'cisco_nxos'
                elif 'router' in version_out.lower():
                    device_info['device_type'] = 'cisco_ios_router'
            logging.info(f"Device {host_ip} identified as {device_info['device_type']}.")
        except Exception as e:
            logging.warning(f"Could not probe device type for {host_ip}: {e}. Assuming 'cisco_ios'.")

        hostname, ip_map, conns = update_interface_descriptions(device_info, update_desc)
        if hostname:
            processed_hostnames.add(hostname)
            if ip_map: all_device_ips[hostname] = ip_map
            for conn in conns:
                neighbor_data.append(conn['data'])
                if recursive_choice == 'y' and conn.get('neighbor_ip') and conn.get('neighbor_ip') not in processed_ips:
                    logging.info(f"Discovered new neighbor: {conn['data'][4]} ({conn['neighbor_ip']}). Adding to queue.")
                    hosts_to_process.append(conn['neighbor_ip'])
        else:
            logging.error(f"Skipping host {host_ip} due to error.")
    
    logging.info("--- Discovery process complete ---")
    excel_file = 'cdp_neighbors_auto.xlsx'
    df = pd.DataFrame(neighbor_data, columns=['Hostname-A', 'Interface-A', 'Port-Channel-A', 'VLAN-A', 'Trunk-A', 'IP-A', 'Hostname-B', 'Interface-B'])
    df.to_excel(excel_file, index=False)
    logging.info(f"Data saved to {excel_file}")
    print(f"\nDiscovery process complete. All data saved to {excel_file}")

    logging.info("--- Generating Draw.io XML topology file ---")
    generate_drawio_topology(df, processed_hostnames, all_device_ips)
    logging.info("--- Script execution finished ---")
