import subprocess
import sys
import json
import time
import socket

def list_interfaces():
    try:
        result = subprocess.run(['tshark', '-D'], capture_output=True, text=True, check=True)
        print("Available interfaces:\n")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("Error listing interfaces:", e)
        sys.exit(1)

def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def parse_and_print_packet(packet):
    layers = packet.get('layers', {})
    if 'cdp' in layers:
        cdp = layers['cdp']
        print(color("=== CDP Packet ===", "1;36"))  # Bold cyan
        if 'cdp_cdp_deviceid' in cdp:
            print(color("Device ID:", "33"), cdp['cdp_cdp_deviceid'])  # Yellow
        if 'cdp_cdp_portid' in cdp:
            print(color("Port ID:", "32"), cdp['cdp_cdp_portid'])  # Green
        if 'cdp_cdp_platform' in cdp:
            print(color("Platform:", "35"), cdp['cdp_cdp_platform'])  # Magenta
        sw_version = cdp.get('cdp_cdp_software_version', [])
        if sw_version:
            if isinstance(sw_version, list):
                sw_version = "\n".join(
                    line for line in sw_version
                    if not any(x in line for x in ["Technical Support", "Copyright", "Compiled"])
                )
            print(color("Software Version:", "36"), sw_version)  # Cyan
        if 'cdp_cdp_native_vlan' in cdp:
            print(color("Native VLAN:", "34"), cdp['cdp_cdp_native_vlan'])  # Blue
        if 'cdp_cdp_voice_vlan' in cdp:
            print(color("Voice VLAN:", "34"), cdp['cdp_cdp_voice_vlan'])
        if 'cdp_cdp_nrgyz_ip_address' in cdp:
            print(color("Mgmt IP(s):", "31"), ", ".join(cdp['cdp_cdp_nrgyz_ip_address']))  # Red
        if 'cdp_cdp_duplex' in cdp:
            print(color("Duplex:", "32"), "Full" if cdp['cdp_cdp_duplex'] else "Half")
        if 'cdp_cdp_capabilities' in cdp:
            print(color("Capabilities:", "33"), cdp['cdp_cdp_capabilities'])
        if 'cdp_cdp_power_available' in cdp:
            print(color("Power Available:", "35"), ", ".join(cdp['cdp_cdp_power_available']))
        if 'cdp_cdp_vtp_management_domain' in cdp:
            print(color("VTP Mgmt Domain:", "36"), cdp['cdp_cdp_vtp_management_domain'])
        print()
    elif 'lldp' in layers:
        lldp = layers['lldp']
        print(color("=== LLDP Packet ===", "1;36"))
        if 'lldp_lldp_chassis_id_mac' in lldp:
            print(color("Chassis MAC:", "33"), lldp['lldp_lldp_chassis_id_mac'])
        if 'lldp_lldp_port_id' in lldp:
            print(color("Port ID:", "32"), lldp['lldp_lldp_port_id'])
        if 'lldp_lldp_port_desc' in lldp:
            print(color("Port Description:", "35"), lldp['lldp_lldp_port_desc'])
        if 'lldp_lldp_tlv_system_name' in lldp:
            print(color("System Name:", "33"), lldp['lldp_lldp_tlv_system_name'])
        if 'lldp_lldp_tlv_system_desc' in lldp:
            desc = lldp['lldp_lldp_tlv_system_desc']
            if isinstance(desc, str):
                desc_lines = desc.splitlines()
                desc = "\n".join(
                    line for line in desc_lines
                    if not any(x in line for x in ["Technical Support", "Copyright", "Compiled"])
                )
            print(color("System Description:", "36"), desc)
        if 'lldp_lldp_ieee_802_1_port_vlan_id' in lldp:
            print(color("VLAN:", "34"), lldp['lldp_lldp_ieee_802_1_port_vlan_id'])
        if 'lldp_lldp_mgn_addr_ip4' in lldp:
            print(color("Mgmt IP:", "31"), lldp['lldp_lldp_mgn_addr_ip4'])
        if 'lldp_lldp_tlv_system_cap' in lldp:
            print(color("Capabilities:", "33"), lldp['lldp_lldp_tlv_system_cap'])
        print()

def autodetect_active_interface():
    result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    current_adapter = None
    adapters = []
    info = {}
    for line in lines:
        if line.strip().startswith("Ethernet adapter") or line.strip().startswith("Wireless LAN adapter"):
            current_adapter = line.split("adapter")[-1].strip(" :")
            info = {"name": current_adapter, "ip": None, "gateway": None}
        elif current_adapter:
            if "IPv4 Address" in line or "IPv4-adress" in line:
                info["ip"] = line.split(":")[-1].strip()
            elif "Default Gateway" in line:
                gw = line.split(":")[-1].strip()
                if gw and gw != "0.0.0.0":
                    info["gateway"] = gw
            elif line.strip() == "" and info.get("ip"):
                # End of adapter section, save if it has IP
                adapters.append(info)
                current_adapter = None
    # Add last adapter if needed
    if current_adapter and info.get("ip"):
        adapters.append(info)
    # Prefer Ethernet adapters with gateway
    for adapter in adapters:
        if adapter["gateway"] and adapter["name"].lower().startswith("ethernet"):
            return adapter["name"]
    # Fallback: any Ethernet adapter with IP
    for adapter in adapters:
        if adapter["ip"] and adapter["name"].lower().startswith("ethernet"):
            return adapter["name"]
    # Fallback: any adapter with gateway
    for adapter in adapters:
        if adapter["gateway"]:
            return adapter["name"]
    # Fallback: any adapter with IP
    for adapter in adapters:
        if adapter["ip"]:
            return adapter["name"]
    return None

def main_autodetect():
    adapter_name = autodetect_active_interface()
    if not adapter_name:
        print("No active interface with an IPv4 address found.")
        sys.exit(1)
    print(color(f"\nAuto-detected active interface: {adapter_name}", "1;36"))
    # Find tshark interface number for this adapter
    tshark_list = subprocess.run(['tshark', '-D'], capture_output=True, text=True)
    interface_num = None
    for line in tshark_list.stdout.splitlines():
        if adapter_name in line:
            interface_num = line.split('.')[0].strip()
            break
    if not interface_num:
        print(f"Could not find tshark interface number for {adapter_name}.")
        sys.exit(1)
    print(color(f"Using tshark interface number: {interface_num}", "1;36"))
    start_capture(interface_num, adapter_name)

def start_capture(interface, adapter_name):
    print(f"\nCapturing CDP and LLDP packets on interface {interface} ({adapter_name})... (Press Ctrl+C to stop)\n")
    seen_cdp = False
    seen_lldp = False
    start_time = time.time()
    timeout = 70  # seconds (enough for at least one CDP packet)

    try:
        tshark_proc = subprocess.Popen(
            [
                'tshark',
                '-i', interface,
                '-Y', 'cdp or lldp',
                '-T', 'ek',
                '-l'
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        for line in tshark_proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                packet = json.loads(line)
                layers = packet.get('layers', {})
                if 'cdp' in layers and not seen_cdp:
                    seen_cdp = True
                if 'lldp' in layers and not seen_lldp:
                    seen_lldp = True
                parse_and_print_packet(packet)
                if seen_cdp and seen_lldp:
                    break
                if time.time() - start_time > timeout:
                    print("\nTimeout reached, proceeding with tests.")
                    break
            except Exception:
                pass
        tshark_proc.terminate()
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except Exception as e:
        print("Error running capture:", e)

    run_network_tests(adapter_name)

def run_network_tests(adapter_name):
    connectivity_test("8.8.8.8")
    get_network_info(adapter_name)
    dns_resolution_test()

def get_network_info(interface_name="Ethernet 5"):
    print("\n" + color(f"=== Network Info for {interface_name} ===", "1;36"))
    result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    in_section = False
    info = {}
    for idx, line in enumerate(lines):
        # Detect start of a new adapter section robustly
        if line.strip().lower().startswith("ethernet adapter") or line.strip().lower().startswith("wireless lan adapter"):
            section_name = line.split("adapter", 1)[-1].strip(" :").lower()
            in_section = section_name == interface_name.lower()
            continue
        if in_section:
            # Stop if we hit the next adapter section
            if (line.strip().lower().startswith("ethernet adapter") or
                line.strip().lower().startswith("wireless lan adapter")):
                break
            if "IPv4 Address" in line or "IPv4-adress" in line:
                info["IP"] = line.split(":")[-1].strip().split("(")[0].strip()
            elif "Subnet Mask" in line:
                info["Subnet"] = line.split(":")[-1].strip()
            elif "Default Gateway" in line:
                gw = line.split(":")[-1].strip()
                if gw:
                    info["Gateway"] = gw
            elif "DHCP Server" in line:
                info["DHCP"] = line.split(":")[-1].strip()
            elif "DNS Servers" in line:
                info["DNS"] = line.split(":")[-1].strip()
                # Check for additional DNS servers on following lines
                j = idx + 1
                while j < len(lines) and lines[j].startswith(" "):
                    extra_dns = lines[j].strip()
                    if extra_dns and "." in extra_dns:
                        info["DNS"] += ", " + extra_dns
                    j += 1

    if info:
        if "IP" in info:
            print(color("IP Address:", "32"), info["IP"])
        if "Subnet" in info:
            print(color("Subnet Mask:", "33"), info["Subnet"])
        if "Gateway" in info:
            print(color("Default Gateway:", "34"), info["Gateway"])
        if "DHCP" in info:
            print(color("DHCP Server:", "35"), info["DHCP"])
        if "DNS" in info:
            print(color("DNS Servers:", "36"), info["DNS"])
    else:
        print(color("No info found for this interface.", "31"))

def dns_resolution_test(hostname="www.google.com"):
    print(color(f"\n=== DNS Resolution Test: {hostname} ===", "1;36"))
    try:
        ip = socket.gethostbyname(hostname)
        print(color(f"Resolved {hostname} to {ip}", "32"))  # Green for success
    except Exception as e:
        print(color(f"Failed to resolve {hostname}: {e}", "31"))  # Red for failure

def get_dns_servers():
    print("\nDNS Servers:")
    result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "DNS Servers" in line or line.strip().startswith("DNS Servers"):
            print(line.strip())
        elif line.startswith(" " * 12) and "." in line:
            print(line.strip())

def get_default_gateway():
    print("\nDefault Gateway:")
    result = subprocess.run(["ipconfig"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "Default Gateway" in line:
            print(line.strip())

def get_ip_address():
    print("\nIP Address:")
    result = subprocess.run(["ipconfig"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "IPv4 Address" in line or "IPv4-adress" in line:  # for some locales
            print(line.strip())

def connectivity_test(target="8.8.8.8"):
    print(color(f"\n=== Connectivity Test to {target} ===", "1;36"))
    # Ping
    ping_result = subprocess.run(["ping", "-n", "4", target], capture_output=True, text=True)
    ping_output = ping_result.stdout
    # Determine ping success
    if "Reply from" in ping_output and "Lost = 0" in ping_output:
        ping_color = "32"  # Green
    else:
        ping_color = "31"  # Red
    print(color("\n--- Ping ---", ping_color))
    print(color(ping_output, ping_color))
    # Traceroute
    print(color("\n--- Traceroute ---", "33"))
    tracert_result = subprocess.run(["tracert", target], capture_output=True, text=True)
    print(tracert_result.stdout)

def main():
    list_interfaces()
    interface = input("\nEnter the interface number (e.g., 1): ").strip()
    adapter_name = None
    # Find adapter name from tshark interface list
    tshark_list = subprocess.run(['tshark', '-D'], capture_output=True, text=True)
    for line in tshark_list.stdout.splitlines():
        if line.startswith(f"{interface}."):
            # Extract adapter name from the line
            parts = line.split('(')
            if len(parts) > 1:
                adapter_name = parts[1].rstrip(')')
            else:
                adapter_name = line
            break
    if not adapter_name:
        adapter_name = f"Interface {interface}"
    start_capture(interface, adapter_name)

if __name__ == "__main__":
    main_autodetect()
