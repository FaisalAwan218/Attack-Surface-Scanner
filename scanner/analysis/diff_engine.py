"""
diff_engine.py
Compares two scan analyses and reports attack-surface changes over time.
"""

from typing import Any, Dict, Tuple


def _port_key(port_item: Dict[str, Any]) -> Tuple[int, str]:
	"""Build a stable key for one port entry."""

	return (int(port_item.get("port", -1)), str(port_item.get("protocol", "")))


def _index_ports(analysis: Dict[str, Any]) -> Dict[Tuple[int, str], Dict[str, Any]]:
	"""Map (port, protocol) to full port details."""

	indexed: Dict[Tuple[int, str], Dict[str, Any]] = {}
	for item in analysis.get("ports", []):
		key = _port_key(item)
		indexed[key] = item
	return indexed


def _is_open(port_item: Dict[str, Any]) -> bool:
	"""Return True when a port is reported open by Nmap."""

	return str(port_item.get("state", "")).strip().lower() == "open"


def compare_analyses(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Compare current vs previous analysis snapshots.

	Returns change details for:
	- open-port totals and signed delta
	- presence-based new ports and disappeared previously-open ports
	- changed service versions/services/products
	"""

	current_ports = _index_ports(current)
	previous_ports = _index_ports(previous)

	current_keys = set(current_ports.keys())
	previous_keys = set(previous_ports.keys())

	current_open_keys = {key for key, item in current_ports.items() if _is_open(item)}
	previous_open_keys = {key for key, item in previous_ports.items() if _is_open(item)}

	common_keys = sorted(current_keys & previous_keys)

	# Presence-based additions/removals are still useful, but the main signal is
	# the state transition between scans.
	added_keys = sorted(current_keys - previous_keys)
	removed_keys = sorted(previous_keys - current_keys)

	new_ports = [current_ports[key] for key in added_keys]
	closed_ports = [previous_ports[key] for key in removed_keys if _is_open(previous_ports[key])]

	changed_services = []

	for key in common_keys:
		curr = current_ports[key]
		prev = previous_ports[key]

		service_fields = ("service", "product", "version", "state")
		if any(curr.get(field, "") != prev.get(field, "") for field in service_fields):
			changed_services.append(
				{
					"port": curr.get("port"),
					"protocol": curr.get("protocol"),
					"previous": {
						"service": prev.get("service", ""),
						"product": prev.get("product", ""),
						"version": prev.get("version", ""),
						"state": prev.get("state", ""),
					},
					"current": {
						"service": curr.get("service", ""),
						"product": curr.get("product", ""),
						"version": curr.get("version", ""),
						"state": curr.get("state", ""),
					},
				}
			)

	return {
		"summary": {
			"current_open_ports": len(current_open_keys),
			"previous_open_ports": len(previous_open_keys),
			"new_ports_open": len(current_open_keys) - len(previous_open_keys),
			"new_ports": len(new_ports),
			"closed_ports": len(closed_ports),
			"changed_services": len(changed_services),
		},
		"current_open_ports": len(current_open_keys),
		"previous_open_ports": len(previous_open_keys),
		"new_ports_open": len(current_open_keys) - len(previous_open_keys),
		"new_ports": new_ports,
		"closed_ports": closed_ports,
		"changed_services": changed_services,
	}
