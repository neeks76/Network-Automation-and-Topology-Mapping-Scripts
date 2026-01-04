# Network Automation and Topology Mapping Script

## Overview

This script, written in Python, uses the Netmiko library to automatically connect to network devices and collect information. Based on the collected data, it generates an Excel report and a network topology map compatible with Draw.io, enhancing network visibility and automating documentation.

## Key Features

- **Automated Information Gathering**: Connects to Cisco IOS and NX-OS devices via SSH to collect CDP (Cisco Discovery Protocol) and LLDP (Link Layer Discovery Protocol) neighbor information.
- **Detailed Information Retrieval**: Parses detailed information for each interface, including IP addresses, VLANs (Access/Trunk), and Port-Channel members.
- **Recursive Discovery**: Can recursively discover all connected neighbors starting from an initial device list (`device_list.txt`) to gather information on the entire network topology.
- **Automatic Interface Description Updates**: Provides an option to automatically set interface descriptions on each device based on the collected neighbor information, in the format "Connected to [Neighbor Device] - [Neighbor Interface]".
- **Result Report Generation**: Saves all collected connection data into a `cdp_neighbors_auto.xlsx` file for systematic management.
- **Topology Map Generation**: Creates a `network_topology_filtered.xml` file that can be directly imported into Draw.io (app.diagrams.net) to visualize the network diagram.

## Prerequisites

### 1. Python Installation

Python 3 must be installed to run the script.

### 2. Required Libraries Installation

Use the command below to install the necessary libraries for running the script.

```bash
pip install pandas netmiko openpyxl
```

### 3. Device List File Creation

Create a `device_list.txt` file in the same directory as the script and enter the IP addresses of the initial network devices for the script to connect to, one per line. Lines starting with `#` are treated as comments and ignored.

**Example `device_list.txt`:**
```
# --- Core Switches ---
192.168.1.1
192.168.1.2

# --- Distribution Switches ---
192.168.10.1
```

## How to Use

1.  Navigate to the directory containing the script in your terminal or command prompt.
2.  Start the script by running the command below:
    ```bash
    python network-automation-and-topology-scripts2.0.py
    ```
3.  When the script starts, enter the following information in order:
    - **Update interface descriptions? (y/n)**: Whether to use the automatic interface description update feature.
    - **Automatically discover and process all neighbors recursively? (y/n)**: Whether to use the recursive discovery feature.
    - **Username**: The username for logging into the devices.
    - **Password**: The login password.
    - **Enable password**: The password for entering enable mode (press Enter if none).
4.  The script will start connecting to each device and gathering information. The progress will be displayed in the console.

## Output Files

After the script finishes, the following files will be generated:

- **`cdp_neighbors_auto.xlsx`**: An Excel file containing all the collected device and interface connection information. Each row represents a single connection (e.g., Hostname-A, Interface-A, Hostname-B, Interface-B).
- **`network_topology_filtered.xml`**: An XML file that can be imported into Draw.io (app.diagrams.net) via the `File > Open from` or `File > Import from` menu. It allows for visual confirmation of the network topology.
- **`netmiko_debug.log`**: A file where detailed logs from the script's execution process are recorded. Useful for troubleshooting.
- **`netmiko_session.log`**: A file where SSH session-related logs from the Netmiko library are recorded.
