import networkx as nx


class AttackGraphBuilder:

    def __init__(self):
        self.G = nx.DiGraph()

    def add_event(self, source, target, action, timestamp=0):
        self.G.add_node(source)
        self.G.add_node(target)
        self.G.add_edge(source, target, action=action, time=timestamp)

    def load_synthetic_data(self):
        self.add_event("Word.exe", "doc.docx", "read", 1)
        self.add_event("Word.exe", "internet.com", "connect", 50)

        self.add_event("Malware.exe", "config.ini", "read", 2)
        self.add_event("Malware.exe", "99.88.77.66", "connect", 4)

    def build_cicids_graph(self, df):
        for index, row in df.iterrows():
            flow_node = f"Flow_{index}"
            port_node = f"Port_{row['Dst Port']}"
            protocol_node = f"Protocol_{row['Protocol']}"
            label_node = f"Label_{row['Label']}"

            self.G.add_node(flow_node, type="flow")
            self.G.add_node(port_node, type="destination_port")
            self.G.add_node(protocol_node, type="protocol")
            self.G.add_node(label_node, type="label")

            self.G.add_edge(flow_node, port_node, action="uses_port")
            self.G.add_edge(flow_node, protocol_node, action="uses_protocol")
            self.G.add_edge(flow_node, label_node, action="has_label")