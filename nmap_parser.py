import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    results = []

    for host in root.findall('host'):
        address = host.find('address').get('addr')
        for port in host.findall(".//port"):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            service = port.find('service')
            service_name = service.get('name') if service is not None else 'unknown'
            results.append({
                'address': address,
                'port': port_id,
                'protocol': protocol,
                'service': service_name
            })

    return results
