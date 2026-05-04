import networkx as nx
from networkx.algorithms import isomorphism


# ✅ 1. Basic detection (Benign vs Attack)
def detect_cicids_attacks(df):
    attack_flows = []
    benign_flows = []

    for index, row in df.iterrows():
        label = str(row["Label"]).strip()

        flow_info = {
            "flow_id": f"Flow_{index}",
            "label": label,
            "dst_port": row["Dst Port"],
            "protocol": row["Protocol"]
        }

        if label.lower() == "benign":
            benign_flows.append(flow_info)
        else:
            attack_flows.append(flow_info)

    return benign_flows, attack_flows


# ✅ 2. VF2 Subgraph Matching
def vf2_detect_ftp_bruteforce(graph):

    pattern = nx.DiGraph()

    # Pattern nodes
    pattern.add_node("flow", type="flow")
    pattern.add_node("port", type="destination_port")
    pattern.add_node("protocol", type="protocol")
    pattern.add_node("label", type="label")

    # Pattern edges
    pattern.add_edge("flow", "port", action="uses_port")
    pattern.add_edge("flow", "protocol", action="uses_protocol")
    pattern.add_edge("flow", "label", action="has_label")

    # Match conditions
    node_match = isomorphism.categorical_node_match("type", None)
    edge_match = isomorphism.categorical_edge_match("action", None)

    matcher = isomorphism.DiGraphMatcher(
        graph,
        pattern,
        node_match=node_match,
        edge_match=edge_match
    )

    matches = []

    for match in matcher.subgraph_isomorphisms_iter():
        reverse_match = {v: k for k, v in match.items()}

        flow_node = reverse_match.get("flow")
        port_node = reverse_match.get("port")
        protocol_node = reverse_match.get("protocol")
        label_node = reverse_match.get("label")

        # 🎯 Filter only FTP brute force pattern
        if (
            port_node == "Port_21" and
            protocol_node == "Protocol_6" and
            label_node == "Label_FTP-BruteForce"
        ):
            matches.append({
                "flow": flow_node,
                "port": port_node,
                "protocol": protocol_node,
                "label": label_node,
                "attack_type": "FTP-BruteForce"
            })

    return matches