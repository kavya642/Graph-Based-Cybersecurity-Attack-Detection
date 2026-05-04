from data_loader import load_cicids_dataset
from detector import detect_cicids_attacks, vf2_detect_ftp_bruteforce
from graph_parser import AttackGraphBuilder
import graph_visualization


def main():
    # 📂 Load dataset
    dataset_path = "../CICIDS data set/02-14-2018.csv/02-14-2018.csv"
    df = load_cicids_dataset(dataset_path, rows=5000)

    # 🧩 Build graph
    builder = AttackGraphBuilder()
    builder.build_cicids_graph(df)
    graph = builder.G

    # 📊 Basic detection
    benign_flows, attack_flows = detect_cicids_attacks(df)

    print("\n✅ CICIDS Graph Created Successfully")
    print("Total Nodes:", graph.number_of_nodes())
    print("Total Edges:", graph.number_of_edges())

    print("\n📊 Detection Summary")
    print("Benign Flows:", len(benign_flows))
    print("Attack Flows:", len(attack_flows))

    # 🔍 VF2 detection
    vf2_matches = vf2_detect_ftp_bruteforce(graph)

    print("\n🔍 VF2 Subgraph Matching Results")
    print("FTP-BruteForce Patterns Found:", len(vf2_matches))

    print("\n🚨 Sample VF2 Matches:")
    for match in vf2_matches[:10]:
        print(match)

    # 🎨 GRAPH VISUALIZATION (IMPORTANT)
    print("\n🎨 Opening Graph Visualization...")
    graph_visualization.visualize_cicids_sample(graph, benign_flows, attack_flows)


if __name__ == "__main__":
    main()