import pandas as pd
import getpass
import re
import subprocess
from netmiko import ConnectHandler
import uuid
import logging
import xml.etree.ElementTree as ET
import os

# Enable detailed logging for Netmiko/Paramiko to help debugging session issues
logging.basicConfig(
    filename='netmiko_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s %(name)s %(levelname)s: %(message)s'
)
logging.getLogger('netmiko').setLevel(logging.DEBUG)
logging.getLogger('paramiko').setLevel(logging.DEBUG)

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
    for pattern, short_form in interface_map.items():
        if re.match(pattern, interface):
            return re.sub(pattern, short_form, interface)
    return interface


def parse_cdp_table(output):
    """Parse table-style 'show cdp neighbors' output.
    Returns list of tuples: (device, local_interface, remote_interface)
    """
    logging.debug("Parsing CDP table output.")
    rows = []
    # Example table line formats to match (Device-ID, Local Intrfce, Holdtime, Capability, Platform, Port ID)
    # R1.hooni.mooo.com   Eth1/1         142    R B                     Gig0/3
    table_re = re.compile(r"^(?P<device>\S+)\s+(?P<local>[A-Za-z0-9\/\.\-]+)\s+\d+\s+.+?\s+(?P<remote>[A-Za-z0-9\/\.\-]+),?$")
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # skip obvious non-table lines
        low = line.lower()
        if low.startswith('capability codes') or low.startswith('device-id') or low.startswith('-----') or low.startswith('platform'):
            continue
        m = table_re.match(line)
        if m:
            device = m.group('device').strip()
            local = m.group('local').strip().rstrip(',')
            remote = m.group('remote').strip().rstrip(',')
            rows.append((device, local, remote))
    return rows


def parse_cdp_detail(output):
    """Parse 'show cdp neighbors detail' output.
    Returns list of tuples: (device, local_interface, remote_interface)
    """
    logging.debug("Parsing CDP detail output.")
    neighbors = []
    # Regular expression to find Device ID, Interface, and Port ID from the detailed output
    cdp_detail_pattern = re.compile(
        r'Device ID:\s*(?P<device>.+?)\n'
        r'(?:[\s\S]*?)?' # Non-capturing group for any text in between (e.g., IP addresses, Platform)
        r'Interface:\s*(?P<local>.+?),\s*Port ID \(outgoing port\):\s*(?P<remote>.+?)\n',
        re.DOTALL # Allows . to match newlines
    )
    
    for match in cdp_detail_pattern.finditer(output):
        device_id = match.group('device').strip()
        local_interface = match.group('local').strip()
        remote_interface = match.group('remote').strip()
        neighbors.append((device_id, local_interface, remote_interface))
    return neighbors


def parse_lldp_detail(output):
    """Parse LLDP 'show lldp neighbors detail' blocks into (system_name, local_iface, port_id).
    Works with NX-OS LLDP output variants that include 'Local Port id' and 'Port id'.
    """
    logging.debug("Parsing LLDP detail output.")
    rows = []
    # split into blocks separated by a line of dashes or two+ newlines
    blocks = re.split(r"\n-{2,}\n|\n\s*\n", output)
    for blk in blocks:
        blk = blk.strip()
        if not blk:
            continue
        # find system name
        sys_m = re.search(r"System Name:\s*(.+)", blk)
        if not sys_m:
            # sometimes System Name follows Port Description; still try to find any 'System Name'
            continue
        system = sys_m.group(1).strip()
        # local interface can be 'Local Port id:' or 'Local Intf:'
        local_m = re.search(r"Local\s+(?:Port\s+id|Intf):\s*([A-Za-z0-9\/\.\-]+)", blk)
        # remote port id is 'Port id:' or 'Port id' earlier
        port_m = re.search(r"Port\s+id:\s*([A-Za-z0-9\/\.\-]+)", blk)
        if local_m and port_m:
            local = local_m.group(1).strip()
            port = port_m.group(1).strip()
            rows.append((system, local, port))
    return rows

def parse_switchport_info(switchport_output):
    """
    Parses the output of 'show interface switchport' to extract VLAN information.
    Handles both access and trunk ports and returns a structured dictionary.
    """
    logging.debug("Parsing switchport info.")
    interface_vlan_map = {}
    current_interface = None
    interface_info = {}

    def process_interface_info():
        if not current_interface or not interface_info:
            return

        mode_line = interface_info.get("Operational Mode")
        if not mode_line:
            return

        if "access" in mode_line:
            access_vlan_line = interface_info.get("Access Mode VLAN", "N/A")
            vlan_id = access_vlan_line.split()[0]
            interface_vlan_map[current_interface] = {'mode': 'access', 'vlan': vlan_id}
        elif "trunk" in mode_line:
            native_vlan_line = interface_info.get("Trunking Native Mode VLAN", "N/A")
            native_id = native_vlan_line.split()[0]
            allowed_vlans_line = interface_info.get("Trunking VLANs Enabled", "N/A")
            interface_vlan_map[current_interface] = {'mode': 'trunk', 'native_vlan': native_id, 'allowed': allowed_vlans_line}

    for line in switchport_output.splitlines():
        line = line.strip()
        if line.startswith("Name:"):
            process_interface_info() # Process the previously collected interface data
            current_interface = convert_interface_name(line.split(":", 1)[1].strip())
            interface_info = {}
        elif current_interface and ":" in line:
            key, value = [x.strip() for x in line.split(":", 1)]
            interface_info[key] = value
    
    process_interface_info() # Process the last interface in the output

    return interface_vlan_map

def parse_all_interface_ips(brief_output):
    """
    Parses the entire 'show ip interface brief' output (for IOS or NX-OS)
    and returns a dictionary mapping every interface to its IP address.
    """
    logging.debug("Parsing all interface IPs.")
    ip_map = {}
    lines = brief_output.strip().splitlines()
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        
        # Basic check if the first part looks like an interface and second looks like an IP
        # IOS: GigabitEthernet0/0     10.1.12.2
        # NX-OS: Vlan10               10.1.100.2
        if len(parts) > 1 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parts[1]):
            interface_name = convert_interface_name(parts[0])
            ip_address = parts[1]
            ip_map[interface_name] = ip_address
    return ip_map

def update_interface_descriptions(device_info, neighbor_data, update_desc, protocol):
    try:
        logging.info(f"Starting interface description update for {device_info['host']}")
        net_connect = ConnectHandler(**device_info)
        net_connect.enable()

        # 1. Get all interface IPs and create a map of ALL interface IPs
        ip_brief_command = "show ip interface brief"
        if device_info['device_type'] == 'cisco_nxos':
            ip_brief_command = "show ip interface brief vrf all"
        ip_brief_output = net_connect.send_command(ip_brief_command, delay_factor=2)
        all_ips_map = parse_all_interface_ips(ip_brief_output)

        # 2. Get switchport details
        try:
            switchport_output = net_connect.send_command("show interface switchport", delay_factor=2)
            port_vlan_map = parse_switchport_info(switchport_output)
        except Exception as e:
            logging.warning(f"Could not get vlan information from {device_info['host']}: {e}")
            print(f"Could not get vlan information from {device_info['host']}: {e}")
            port_vlan_map = {}

        # 3. Get neighbor details
        neighbors = []
        if protocol == 'cdp':
            print(f"Running CDP on {device_info['host']}...")
            cdp_output = net_connect.send_command('show cdp neighbors detail', delay_factor=2)
            neighbors = parse_cdp_detail(cdp_output) # Use the dedicated CDP detail parser
        elif protocol == 'lldp':
            print(f"Running LLDP on {device_info['host']}...")
            lldp_output = net_connect.send_command('show lldp neighbors detail', delay_factor=2)
            neighbors = parse_lldp_detail(lldp_output)

        if not neighbors:
            print(f"No neighbors found on {device_info['host']} with the selected protocol.")
            logging.info(f"No neighbors found on {device_info['host']} with {protocol}.")

        # 4. Get device hostname
        version_out = net_connect.send_command('show version')
        hostname = device_info.get('host')
        m = re.search(r'Device name:\s*(\S+)', version_out, re.IGNORECASE)
        if m:
            hostname = m.group(1)
        else:
            m2 = re.search(r'System Name:\s*(\S+)', version_out, re.IGNORECASE)
            if m2:
                hostname = m2.group(1)
            else:
                m3 = re.search(r'(\S+)\s+uptime', version_out)
                if m3 and m3.group(1).lower() != 'kernel':
                    hostname = m3.group(1)
        logging.info(f"Determined hostname for {device_info['host']}: {hostname}")

        # 5. Process each neighbor
        for neighbor in neighbors:
            device_id, local_interface, remote_interface = neighbor
            local_interface_short = convert_interface_name(local_interface)
            remote_interface_short = convert_interface_name(remote_interface)
            
            ip_addr = "N/A"
            vlan_display = "N/A"

            port_details = port_vlan_map.get(local_interface_short)
            if port_details:
                if port_details['mode'] == 'access':
                    vlan_id = port_details['vlan']
                    vlan_display = vlan_id # Only show the VLAN ID
                    svi_name = convert_interface_name(f"Vlan{vlan_id}")
                    ip_addr = all_ips_map.get(svi_name, "N/A")
                elif port_details['mode'] == 'trunk':
                    vlan_display = f"Trunk (Native: {port_details['native_vlan']})"
                    native_vlan_id = port_details['native_vlan']
                    svi_name = convert_interface_name(f"Vlan{native_vlan_id}")
                    ip_addr = all_ips_map.get(svi_name, "N/A")

            # Fallback for routed ports or if SVI IP not found
            if ip_addr == "N/A":
                ip_addr = all_ips_map.get(local_interface_short, "N/A")
            logging.debug(f"Processing neighbor: Device {device_id}, Local IF {local_interface_short}, Remote IF {remote_interface_short}, IP {ip_addr}, VLAN {vlan_display}")

            description = f"Connected to {device_id} - {remote_interface_short}"

            if update_desc == 'y':
                logging.info(f"Updating description for {local_interface_short} on {hostname}")
                old_description = net_connect.send_command(f"show running-config interface {local_interface_short} | include description")
                config_commands = [
                    f"interface {local_interface_short}",
                    f"description {description}"
                ]
                net_connect.send_config_set(config_commands)
                print(f"Description for interface {local_interface_short} on {hostname} has been updated.")
                print(f"Old description: {old_description}")
                print(f"New description: {description}")
                logging.info(f"Description updated for {local_interface_short}. Old: {old_description.strip()}, New: {description}")

            neighbor_data.append([hostname, local_interface_short, ip_addr, device_id, remote_interface_short, vlan_display])

        if update_desc == 'y':
            net_connect.save_config()

        net_connect.disconnect()

        print(f"Process on {device_info['host']} completed.")
        logging.info(f"Process on {device_info['host']} completed.")
    except Exception as e:
        print(f"Error on device {device_info['host']}: {e}")
        logging.error(f"Error on device {device_info['host']}: {e}")

# Function to check whether an IP responds to ping
def is_ip_reachable(ip):
    logging.debug(f"Checking IP reachability for {ip}")
    logging.debug(f"Checking IP reachability for {ip}")
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return "1 packets transmitted, 1 received" in output
    except subprocess.CalledProcessError:
        return False

# Function to generate a draw.io-compatible topology XML file
def generate_drawio_topology(df):
    # The dataframe now contains IP addresses for Host-A interfaces.
    # This function and its sub-functions will build the XML topology.

    def generate_unique_id():
        return str(uuid.uuid4())

    def canonical_name(name, all_names):
        if not isinstance(name, str) or not name:
            return name
        n = name.strip()
        # prefer text before first dot
        if '.' in n:
            n = n.split('.')[0]
        # if name contains parentheses like Prefix(inner), try to unify by inner token
        m = re.match(r"^(.+?)\((.+?)\)", n)
        if m:
            prefix = m.group(1).strip()
            inner = m.group(2).strip()
            # find other names containing the inner token
            candidates = [o for o in all_names if isinstance(o, str) and inner in o]
            # choose a short descriptive candidate (not generic like 'switch' or 'kernel')
            blacklist = {'switch', 'kernel', 'interface', 'local', 'remote', 'platform', 'ipv4', 'address'}
            best = None
            for c in candidates:
                p = c.split('(')[0].strip()
                low = p.lower()
                if low in blacklist:
                    continue
                if best is None or len(p) < len(best):
                    best = p
            if best:
                return best
            # otherwise fall back to prefix (before paren)
            return prefix
        return n

    def generate_drawio_xml_elements(df):
        elements = []
        unique_ids = {}
        x_pos, y_pos = 100, 100

        # build list of all host strings to help canonicalization
        all_names = list(pd.concat([df['Hostname-A'], df['Hostname-B']]).dropna().unique())
        
        # Create mappings from (host, interface) to IP and VLAN
        ip_map = {}
        vlan_map = {}
        for _, row in df.iterrows():
            host_a_canon = canonical_name(row['Hostname-A'], all_names)
            iface_a_canon = convert_interface_name(row['Interface-A'])
            
            ip_a = row.get('IP-A')
            if ip_a and ip_a != 'N/A':
                ip_map[(host_a_canon, iface_a_canon)] = ip_a
            
            vlan_a = row.get('VLAN-A')
            if vlan_a and vlan_a != 'N/A':
                vlan_map[(host_a_canon, iface_a_canon)] = vlan_a

        # build edges grouped by unordered host pair so duplicate links are collated
        edges_map = {}
        for index, row in df.iterrows():
            raw_a = row['Hostname-A']
            raw_b = row['Hostname-B']
            hostname_a = canonical_name(raw_a, all_names)
            hostname_b = canonical_name(raw_b, all_names)
            interface_a = convert_interface_name(str(row['Interface-A']))
            interface_b = convert_interface_name(str(row['Interface-B']))
            key = tuple(sorted([hostname_a, hostname_b]))
            edges_map.setdefault(key, []).append((hostname_a, hostname_b, interface_a, interface_b))

        # create nodes first (order deterministic by all_names)
        for n in all_names:
            cn = canonical_name(n, all_names)
            if cn not in unique_ids:
                unique_ids[cn] = generate_unique_id()
                label = cn
                node_el = ET.Element('mxCell', {'id': unique_ids[cn], 'value': label, 'style': 'shape=ellipse;', 'vertex': '1', 'parent': '1'})
                ET.SubElement(node_el, 'mxGeometry', {'x': str(x_pos), 'y': str(y_pos), 'width': '80', 'height': '80', 'as': 'geometry'})
                elements.append(node_el)
                x_pos += 120

        # Helper to create label string
        def create_label(iface_name, host_name):
            ip = ip_map.get((host_name, iface_name))
            vlan = vlan_map.get((host_name, iface_name))
            label = str(iface_name)
            if vlan:
                vlan_str = str(vlan)
                if 'Trunk' in vlan_str:
                    label += "[T]"  # Abbreviate Trunk for cleaner look
                else:
                    label += f"[V{vlan_str}]"
            if ip:
                label += f"({ip})"
            return label

        # now create a single edge per host-pair
        for key, links in edges_map.items():
            host_a, host_b = key[0], key[1] # These are the canonical names
            src_id = unique_ids.get(host_a)
            tgt_id = unique_ids.get(host_b)
            if not src_id or not tgt_id:
                continue
            
            pairs = []
            seen_pairs = set()
            for (ha, hb, ia, ib) in links:
                pair = tuple(sorted((ia, ib)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                # Determine which interface belongs to which host for this specific link
                if ha == host_a:
                    pairs.append({'left_if': ia, 'right_if': ib})
                else:
                    pairs.append({'left_if': ib, 'right_if': ia})

            left_ifaces = sorted([p['left_if'] for p in pairs])
            right_ifaces = sorted([p['right_if'] for p in pairs])
            count = len(pairs)
            edge_label = str(count)

            edge_id = generate_unique_id()
            edge_style = "edgeStyle=orthogonalEdgeStyle;startArrow=none;endArrow=none;align=center;verticalAlign=middle;"
            edge_el = ET.Element('mxCell', {'id': edge_id, 'value': edge_label, 'style': edge_style, 'edge': '1', 'parent': '1', 'source': src_id, 'target': tgt_id})
            ET.SubElement(edge_el, 'mxGeometry', {'relative': '1', 'as': 'geometry'})
            elements.append(edge_el)

            # Source label
            if left_ifaces:
                label_parts = [create_label(iface, host_a) for iface in left_ifaces]
                left_label_id = generate_unique_id()
                left_label_el = ET.Element('mxCell', {'id': left_label_id, 'value': ", ".join(label_parts), 'style': 'text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];', 'vertex': '1', 'connectable': '0', 'parent': edge_id})
                geo = ET.SubElement(left_label_el, 'mxGeometry', {'x': '-0.8', 'y': '10', 'relative': '1', 'as': 'geometry'})
                ET.SubElement(geo, 'mxPoint', {'as': 'offset'})
                elements.append(left_label_el)

            # Target label
            if right_ifaces:
                label_parts = [create_label(iface, host_b) for iface in right_ifaces]
                right_label_id = generate_unique_id()
                right_label_el = ET.Element('mxCell', {'id': right_label_id, 'value': ", ".join(label_parts), 'style': 'text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];', 'vertex': '1', 'connectable': '0', 'parent': edge_id})
                geo = ET.SubElement(right_label_el, 'mxGeometry', {'x': '0.8', 'y': '10', 'relative': '1', 'as': 'geometry'})
                ET.SubElement(geo, 'mxPoint', {'as': 'offset'})
                elements.append(right_label_el)
        return elements

    xml_elements = generate_drawio_xml_elements(df)
    
    mxfile = ET.Element('mxfile')
    diagram = ET.SubElement(mxfile, 'diagram')
    mxGraphModel = ET.SubElement(diagram, 'mxGraphModel')
    root = ET.SubElement(mxGraphModel, 'root')
    ET.SubElement(root, 'mxCell', {'id': '0'})
    ET.SubElement(root, 'mxCell', {'id': '1', 'parent': '0'})
    for el in xml_elements:
        root.append(el)

    xml_string = ET.tostring(mxfile, encoding='unicode')

    output_file = "network_topology_filtered.xml"
    with open(output_file, "w") as file:
        file.write(xml_string)
    print(f"Draw.io-compatible topology XML file saved as {output_file}")

def read_device_list(filename="device_list.txt"):
    """Reads a list of device IPs from a file in the same directory as the script."""
    devices = []
    # Build the full path to the device list file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, filename)
    
    if not os.path.exists(file_path):
        print(f"Error: Device list file not found at {file_path}")
        return devices

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Ignore empty lines and comments
            if line and not line.startswith('#'):
                devices.append(line)
    return devices

# Option whether to update interface descriptions
update_desc = input("Do you want to update interface descriptions? (y/n): ").lower()

device_info_template = {
    "device_type": "cisco_ios",
    "username": input("Enter username: "),
    "password": getpass.getpass("Enter password: "),
    "secret": getpass.getpass("Enter enable password (press Enter if none): "),
    # Enable Netmiko session logging for debugging (writes raw session to file)
    "session_log": "netmiko_session.log",
}

print("Netmiko session log will be written to netmiko_session.log")

main_hosts = read_device_list()
if not main_hosts:
    print("Device list is empty or 'device_list.txt' not found. Exiting.")
    exit()

protocol_choice = ""
while protocol_choice not in ['cdp', 'lldp']:
    protocol_choice = input("Select discovery protocol (cdp or lldp): ").lower()

neighbor_data = []
processed_switches = set()

for main_host in main_hosts:
    if is_ip_reachable(main_host):
        print(f"Device with IP {main_host} is reachable by ping.")
    else:
        print(f"Device with IP {main_host} is unreachable by ping; attempting SSH access...")

    device_info = device_info_template.copy()
    device_info['host'] = main_host

    # Probe device to detect NX-OS and adjust device_type accordingly
    try:
        probe_conn = ConnectHandler(**device_info)
        version_out = probe_conn.send_command('show version', delay_factor=2)
        probe_conn.disconnect()
        vlow = version_out.lower()
        if 'nx-os' in vlow or 'nexus' in vlow or 'nxos' in vlow:
            device_info['device_type'] = 'cisco_nxos'
            print(f"Detected NX-OS on {main_host}; using cisco_nxos device_type")
    except Exception as e:
        print(f"Could not probe device type for {main_host}: {e}")

    update_interface_descriptions(device_info, neighbor_data, update_desc, protocol_choice)
    processed_switches.add(main_host)

excel_file = 'cdp_neighbors_auto.xlsx'
df = pd.DataFrame(neighbor_data, columns=['Hostname-A', 'Interface-A', 'IP-A', 'Hostname-B', 'Interface-B', 'VLAN-A'])
df.to_excel(excel_file, index=False)

print("The CDP process is complete. Neighbor device data has been saved to an Excel file.")

generate_drawio_topology(df)
