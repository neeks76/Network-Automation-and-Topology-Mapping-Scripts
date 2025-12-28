import pandas as pd
import getpass
import re
import subprocess
from netmiko import ConnectHandler
import uuid
import logging

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
    interface_map = {
        r'^GigabitEthernet': 'Gi',
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


def parse_lldp_detail(output):
    """Parse LLDP 'show lldp neighbors detail' blocks into (system_name, local_iface, port_id).
    Works with NX-OS LLDP output variants that include 'Local Port id' and 'Port id'.
    """
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

# Function to update interface descriptions with clearer logs
def update_interface_descriptions(device_info, neighbor_data, update_desc):
    try:
        net_connect = ConnectHandler(**device_info)
        net_connect.enable()

        # determine whether device is NX-OS (LLDP) or IOS (CDP)
        dev_type = device_info.get('device_type', '')
        if dev_type == 'cisco_nxos':
            # Try CDP first on NX-OS (some NX devices still provide CDP)
            cdp_output = net_connect.send_command('show cdp neighbors detail', delay_factor=2)
            # allow optional whitespace after colon (Device ID:R1... vs Device ID: R1...)
            cdp_neighbors = re.findall(r'Device ID:\s*(.+?)\n[\s\S]*?Interface:\s*(.+?),\s*Port ID \(outgoing port\):\s*(.+?)\n', cdp_output, re.DOTALL)
            if cdp_neighbors:
                neighbors = cdp_neighbors
            else:
                # try CDP table format (non-detail)
                table_neighbors = parse_cdp_table(cdp_output)
                if table_neighbors:
                    neighbors = table_neighbors
                else:
                    # fallback to LLDP if CDP not present
                    nbr_output = net_connect.send_command('show lldp neighbors detail', delay_factor=2)
                    lldp_neighbors = parse_lldp_detail(nbr_output)
                    neighbors = lldp_neighbors
        else:
            cdp_output = net_connect.send_command('show cdp neighbors detail', delay_factor=2)
            cdp_neighbors = re.findall(r'Device ID:\s*(.+?)\n[\s\S]*?Interface:\s*(.+?),\s*Port ID \(outgoing port\):\s*(.+?)\n', cdp_output, re.DOTALL)
            if cdp_neighbors:
                neighbors = cdp_neighbors
            else:
                # fallback to table parser when detail output not present
                neighbors = parse_cdp_table(cdp_output)

        version_out = net_connect.send_command('show version')
        # Prefer explicit device name fields commonly present on NX-OS/IOS
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

        for neighbor in neighbors:
            device_id, local_interface, remote_interface = neighbor
            # normalize both local and remote interface names to short form
            local_interface = convert_interface_name(local_interface)
            remote_interface = convert_interface_name(remote_interface)
            description = f"Connected to {device_id} - {remote_interface}"

            if update_desc == 'y':
                old_description = net_connect.send_command(f"show running-config interface {local_interface} | include description")
                config_commands = [
                    f"interface {local_interface}",
                    f"description {description}"
                ]
                net_connect.send_config_set(config_commands)
                print(f"Description for interface {local_interface} on {hostname} has been updated.")
                print(f"Old description: {old_description}")
                print(f"New description: {description}")

            neighbor_data.append([hostname, local_interface, remote_interface, device_id])

        if update_desc == 'y':
            net_connect.save_config()

        net_connect.disconnect()

        print(f"Process on {device_info['host']} completed.")
    except Exception as e:
        print(f"Error on device {device_info['host']}: {e}")

# Function to check whether an IP responds to ping
def is_ip_reachable(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return "1 packets transmitted, 1 received" in output
    except subprocess.CalledProcessError:
        return False

# Function to generate a draw.io-compatible topology XML file
def generate_drawio_topology(file_path):
    df = pd.read_excel(file_path)

    # Step 1: Identify and remove duplicate/stacked connections
    df_reversed = df.copy()
    df_reversed.columns = ['Hostname-B', 'Interface-B', 'Interface-A', 'Hostname-A']
    combined_df = pd.concat([df, df_reversed])
    df_cleaned = combined_df.drop_duplicates(subset=['Hostname-A', 'Interface-A', 'Hostname-B', 'Interface-B'], keep='first')

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

    def generate_drawio_xml(df):
        xml_elements = []
        unique_ids = {}
        x_pos, y_pos = 100, 100

        # build list of all host strings to help canonicalization
        all_names = list(pd.concat([df['Hostname-A'], df['Hostname-B']]).dropna().unique())

        # build edges grouped by unordered host pair so duplicate links are collated
        edges_map = {}
        # maps host -> set of interfaces seen on that side
        host_ifaces = {}
        for index, row in df.iterrows():
            raw_a = row['Hostname-A']
            raw_b = row['Hostname-B']
            hostname_a = canonical_name(raw_a, all_names)
            hostname_b = canonical_name(raw_b, all_names)
            # use short interface names for labels (e.g., Gi0/1)
            interface_a = convert_interface_name(str(row['Interface-A']))
            interface_b = convert_interface_name(str(row['Interface-B']))
            # normalized key (undirected)
            key = tuple(sorted([hostname_a, hostname_b]))
            edges_map.setdefault(key, []).append((hostname_a, hostname_b, interface_a, interface_b))
            host_ifaces.setdefault(hostname_a, set()).add(interface_a)
            host_ifaces.setdefault(hostname_b, set()).add(interface_b)

        # create nodes first (order deterministic by all_names)
        for n in all_names:
            cn = canonical_name(n, all_names)
            if cn not in unique_ids:
                unique_ids[cn] = generate_unique_id()
                # node label: only hostname (do not include interface lists)
                label = cn
                xml_elements.append(
                    f'<mxCell id="{unique_ids[cn]}" value="{label}" style="shape=ellipse;" vertex="1" parent="1">'
                    f'<mxGeometry x="{x_pos}" y="{y_pos}" width="80" height="80" as="geometry"/></mxCell>'
                )
                x_pos += 120

        # now create a single edge per host-pair; label midpoint with connection count
        for key, links in edges_map.items():
            host_a, host_b = key[0], key[1]
            src_id = unique_ids.get(host_a)
            tgt_id = unique_ids.get(host_b)
            if not src_id or not tgt_id:
                continue
            # collect unique interface mappings for display
            pairs = []
            seen_pairs = set()
            for (ha, hb, ia, ib) in links:
                # normalize direction so ia belongs to host_a when possible
                if ha == host_a and hb == host_b:
                    pair = (ia, ib)
                elif ha == host_b and hb == host_a:
                    pair = (ib, ia)
                else:
                    pair = (ia, ib)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                pairs.append(pair)
            # build side interface lists
            left_ifaces = sorted({p[0] for p in pairs})
            right_ifaces = sorted({p[1] for p in pairs})
            count = len(pairs)
            # edge label = count displayed at middle
            edge_label = str(count)
            # also set tooltip-like composite label (not displayed) with interface lists
            # use style to place label above the line
            style = "edgeStyle=orthogonalEdgeStyle;verticalLabelPosition=top;align=center;labelBackgroundColor=none"
            edge_id = generate_unique_id()
            xml_elements.append(
                f'<mxCell id="{edge_id}" value="{edge_label}" style="{style}" edge="1" source="{src_id}" target="{tgt_id}" parent="1">'
                f'<mxGeometry relative="1" as="geometry"/></mxCell>'
            )
            # create small label vertices near ends to show interface lists
            if left_ifaces:
                nid = generate_unique_id()
                xml_elements.append(f'<mxCell id="{nid}" value="{", ".join(left_ifaces)}" style="text;html=1;align=left;verticalAlign=middle;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="120" height="20" as="geometry"/></mxCell>')
                # connect this label to source with invisible edge (helps positioning in some viewers)
                lid = generate_unique_id()
                xml_elements.append(f'<mxCell id="{lid}" value="" style="edgeStyle=none;strokeColor=none;" edge="1" source="{src_id}" target="{nid}" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>')
            if right_ifaces:
                nid2 = generate_unique_id()
                xml_elements.append(f'<mxCell id="{nid2}" value="{", ".join(right_ifaces)}" style="text;html=1;align=right;verticalAlign=middle;" vertex="1" parent="1"><mxGeometry x="0" y="0" width="120" height="20" as="geometry"/></mxCell>')
                lid2 = generate_unique_id()
                xml_elements.append(f'<mxCell id="{lid2}" value="" style="edgeStyle=none;strokeColor=none;" edge="1" source="{tgt_id}" target="{nid2}" parent="1"><mxGeometry relative="1" as="geometry"/></mxCell>')
        return xml_elements

    xml_elements = generate_drawio_xml(df_cleaned)
    xml_structure = f"""
    <mxfile>
      <diagram>
        <mxGraphModel>
          <root>
            <mxCell id="0"/>
            <mxCell id="1" parent="0"/>
            {''.join(xml_elements)}
          </root>
        </mxGraphModel>
      </diagram>
    </mxfile>
    """
    output_file = "network_topology_filtered.xml"
    with open(output_file, "w") as file:
        file.write(xml_structure)
    print(f"Draw.io-compatible topology XML file saved as {output_file}")

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

main_hosts = []
while True:
    host = input("Enter device IP address: ")
    main_hosts.append(host)
    add_more = input("Do you want to add another device IP address? (y/n): ")
    if add_more.lower() != 'y':
        break

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

    update_interface_descriptions(device_info, neighbor_data, update_desc)
    processed_switches.add(main_host)

excel_file = 'cdp_neighbors_auto.xlsx'
df = pd.DataFrame(neighbor_data, columns=['Hostname-A', 'Interface-A', 'Interface-B', 'Hostname-B'])
df.to_excel(excel_file, index=False)

print("Proses CDP selesai. Data perangkat tetangga telah disimpan ke file Excel.")

generate_drawio_topology(excel_file)
