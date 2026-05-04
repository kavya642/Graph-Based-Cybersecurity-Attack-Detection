import matplotlib
matplotlib.use('TkAgg')

import matplotlib.pyplot as plt
import networkx as nx
from tkinter import messagebox
import tkinter as tk
from matplotlib.patches import Patch

def visualize_cicids_sample(graph, benign_flows, attack_flows):
    sample_graph = nx.DiGraph()

    selected_benign = benign_flows[:5]
    selected_attacks = attack_flows[:10]
    selected_flows = selected_benign + selected_attacks

    attack_ids = {flow["flow_id"] for flow in selected_attacks}

    node_details = {}

    for flow in selected_flows:
        flow_id = flow["flow_id"]
        port_node = f"Port_{flow['dst_port']}"
        protocol_node = f"Protocol_{flow['protocol']}"
        label_node = f"Label_{flow['label']}"

        node_type = "Attack Flow" if flow_id in attack_ids else "Benign Flow"

        # Add nodes
        sample_graph.add_node(flow_id, type=node_type)
        sample_graph.add_node(port_node, type="Port")
        sample_graph.add_node(protocol_node, type="Protocol")
        sample_graph.add_node(label_node, type="Label")

        # Add edges
        sample_graph.add_edge(flow_id, port_node, action="uses_port")
        sample_graph.add_edge(flow_id, protocol_node, action="uses_protocol")
        sample_graph.add_edge(flow_id, label_node, action="classified_as")

        # 🎯 Node popup details (with emojis)
        if node_type == "Attack Flow":
            node_details[flow_id] = (
                f"🔍 Node: {flow_id}\n"
                f"🚨 Type: Attack Flow\n"
                f"🌐 Destination Port: {flow['dst_port']}\n"
                f"🔗 Protocol: {flow['protocol']}\n"
                f"⚠️ Label: {flow['label']}\n\n"
                f"💡 This flow indicates a potential cyber attack."
            )
        else:
            node_details[flow_id] = (
                f"🔍 Node: {flow_id}\n"
                f"✅ Type: Benign Flow\n"
                f"🌐 Destination Port: {flow['dst_port']}\n"
                f"🔗 Protocol: {flow['protocol']}\n"
                f"🟢 Label: {flow['label']}\n\n"
                f"💡 This flow represents normal activity."
            )

        node_details[port_node] = (
            f"🔌 Node: {port_node}\n"
            f"📡 Type: Destination Port\n"
            f"💡 Network service port used in communication."
        )

        node_details[protocol_node] = (
            f"🔗 Node: {protocol_node}\n"
            f"📘 Type: Protocol\n"
            f"💡 Defines how data is transmitted (TCP/UDP)."
        )

        node_details[label_node] = (
            f"🏷️ Node: {label_node}\n"
            f"📊 Type: Traffic Label\n"
            f"💡 Classification of the network flow."
        )

    # 🎨 Node colors
    color_map = []
    for node, data in sample_graph.nodes(data=True):
        t = data.get("type")

        if t == "Attack Flow":
            color_map.append("red")
        elif t == "Benign Flow":
            color_map.append("skyblue")
        elif t == "Port":
            color_map.append("orange")
        elif t == "Protocol":
            color_map.append("violet")
        else:
            color_map.append("lightgreen")

    plt.figure(figsize=(14, 9))
    pos = nx.spring_layout(sample_graph, k=1.5, seed=42)

    # Draw nodes
    nodes = nx.draw_networkx_nodes(
        sample_graph,
        pos,
        node_color=color_map,
        node_size=1000
    )

    nodes.set_picker(True)  # ✅ enable clicking

    # Draw labels & edges
    nx.draw_networkx_labels(sample_graph, pos, font_size=8)
    nx.draw_networkx_edges(sample_graph, pos, edge_color="gray", arrows=True)

    edge_labels = nx.get_edge_attributes(sample_graph, "action")
    nx.draw_networkx_edge_labels(sample_graph, pos, edge_labels=edge_labels, font_size=7)

    # 📌 Legend
    legend_items = [
        Patch(facecolor="red", label="[!] Attack Flow"),
        Patch(facecolor="skyblue", label="[OK] Benign Flow"),
        Patch(facecolor="orange", label="[P] Port"),
        Patch(facecolor="violet", label="[PR] Protocol"),
        Patch(facecolor="lightgreen", label="[L] Label")
    ]

    plt.legend(
        handles=legend_items,
        loc="lower center",
        bbox_to_anchor=(0.5, -0.15),
        ncol=5
    )

    plt.title("Cyber Security Attack Detection (Interactive Graph)")
    plt.axis("off")

    node_list = list(sample_graph.nodes())

    # 🖱️ Click event
    def on_click(event):
        if event.artist != nodes:
            return

        index = event.ind[0]
        clicked_node = node_list[index]

        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo("Node Details", node_details.get(clicked_node, "No details available"))
        root.destroy()

    plt.gcf().canvas.mpl_connect("pick_event", on_click)

    plt.tight_layout()
    plt.show()