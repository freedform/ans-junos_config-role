import ipaddress


def raise_error(msg):
    raise Exception(msg)


def int_check(number) -> int:
    if not isinstance(number, int):
        try:
            number = int(number)
        except:
            raise Exception(f"The given {number=} must be integer")
    if number < 0:
        raise Exception(f"The given {number=} must be positive")
    return number


def str_check(string) -> str:
    if not isinstance(string, str):
        raise Exception(f"The given {string=} must be string")
    if len(string) == 0:
        raise Exception(f"The given {string=} must not be zero length")
    return string


def str_or_list(strings) -> str:
    if isinstance(strings, list):
        return f"[ {' '.join([str(str_check(x)) for x in strings])} ]"
    else:
        return str_check(strings)


def ip_check(ip, ip_type, ip_family="ip"):
    ip_dict = {
        "ip_network": ipaddress.ip_network,
        "ipv4_network": ipaddress.IPv4Network,
        "ipv6_network": ipaddress.IPv6Network,
        "ip_address": ipaddress.ip_address,
        "ipv4_address": ipaddress.IPv4Address,
        "ipv6_address": ipaddress.IPv6Address,
        "ip_interface": ipaddress.ip_interface,
        "ipv4_interface": ipaddress.IPv4Interface,
        "ipv6_interface": ipaddress.IPv6Interface,
    }
    ip_function = ip_dict.get(f"{ip_family}_{ip_type}")
    if not callable(ip_function):
        raise Exception(f"Unsupported {ip_type=} or {ip_family=}")
    ip_function(ip)
    return ip


def ip_or_list(ips, ip_type, ip_family="ip"):
    if isinstance(ips, list):
        return f"[ {' '.join([str(ip_check(x, ip_type, ip_family)) for x in ips])} ]"
    else:
        return ip_check(ips, ip_type, ip_family)


def vlan_check(vlan) -> int:
    vlan = int_check(vlan)
    if not (0 < vlan < 4096):
        raise Exception(f"The given {vlan=} must satisfy '0 <= vlan < 4096'")
    return vlan


def vlan_list(vlans: list) -> str:
    if not isinstance(vlans, list):
        raise Exception(f"The given {vlans=} must be list")
    return f"[ {' '.join([str(vlan_check(x)) for x in vlans])} ]"


def tcp_udp_check(port):
    if isinstance(port, str) and "-" in port:
        port_range = port.split("-")
        if len(port_range) != 2:
            raise Exception(f"Too many objects in port range {port_range=}")
        for item in port_range:
            item = tcp_udp_check(item)
        return port
    port = int_check(port)
    if not (0 < port <= 65535):
        raise Exception(f"The given {port=} must satisfy '0 <= port < 65535'")
    return port


def tcp_udp_or_list(ports):
    if isinstance(ports, list):
        return f"[ {' '.join([str(tcp_udp_check(x)) for x in ports])} ]"
    else:
        return tcp_udp_check(ports)


def interface_dot_format(interface: str, svi_name):
    if "." not in interface:
        interface = f"{interface}.0"
    return interface.replace("vlan", svi_name)


def is_list(input_data):
    return isinstance(input_data, list)


def family_check(family):
    family_dict = {
        "ipv4": "inet",
        "ipv6": "inet6"
    }
    if family not in family_dict.keys():
        raise Exception(f"Unsupported {family=}")
    return family_dict[family]


def protocol_check(protocol):
    protocol_list = [
        "ah",
        "dstopts",
        "egp",
        "esp",
        "fragment",
        "gre",
        "hop-by-hop",
        "icmp",
        "icmp6",
        "igmp",
        "ipip",
        "ipv6",
        "no-next-header",
        "ospf",
        "ospf3",
        "pim",
        "routing",
        "rsvp",
        "sctp",
        "tcp",
        "udp",
        "vrrp",
    ]
    if protocol not in protocol_list:
        raise Exception(f"Unsupported {protocol=}")
    return protocol


def protocol_or_list(protocols):
    if isinstance(protocols, list):
        return f"[ {' '.join([str(protocol_check(x)) for x in protocols])} ]"
    else:
        return protocol_check(protocols)


def icmp_type_check(icmp_type):
    icmp_type_list = [
        "echo-reply",
        "echo-request",
        "info-reply",
        "info-request",
        "mask-reply",
        "mask-request",
        "parameter-problem",
        "redirect",
        "router-advertisement",
        "router-solicit",
        "source-quench",
        "time-exceeded",
        "timestamp",
        "timestamp-reply",
        "unreachable",
    ]
    if icmp_type not in icmp_type_list:
        raise Exception(f"Unsupported {icmp_type=}")
    return icmp_type


def icmp_type_or_list(icmp_types):
    if isinstance(icmp_types, list):
        return f"[ {' '.join([str(icmp_type_check(x)) for x in icmp_types])} ]"
    else:
        return icmp_type_check(icmp_types)


def acl_action_check(action):
    return str_check(action)


def acl_check(direction, acls):
    if direction not in ["in", "out"]:
        raise Exception(f"Unsupported {direction=}")
    if isinstance(acls, str):
        return f"{direction}put {acls}"
    elif isinstance(acls, list):
        return f"{direction}put-list [ {' '.join([str_check(acl) for acl in acls])} ]"


def l3_vlan_check(vlans):
    return [x["id"] for x in vlans.values() if "l3" in x.keys()]


class FilterModule(object):

    def filters(self):
        return {
            "l3_vlan_check": l3_vlan_check,
            "raise_error": raise_error,
            "acl_check": acl_check,
            "acl_action_check": acl_action_check,
            "icmp_type_check": icmp_type_check,
            "icmp_type_or_list": icmp_type_or_list,
            "protocol_check": protocol_check,
            "protocol_or_list": protocol_or_list,
            "family_check": family_check,
            "ip_check": ip_check,
            "ip_or_list": ip_or_list,
            "int_check": int_check,
            "vlan_check": vlan_check,
            "vlan_list": vlan_list,
            "str_check": str_check,
            "str_or_list": str_or_list,
            "tcp_udp_check": tcp_udp_check,
            "tcp_udp_or_list": tcp_udp_or_list,
            "interface_dot_format": interface_dot_format,
            "is_list": is_list,
        }
