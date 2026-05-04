import json
import streamlit as st
import pandas as pd
import streamlit.components.v1 as components

from data_loader import load_cicids_dataset

# ---------------------------
# Page Configuration
# ---------------------------
st.set_page_config(page_title="Cybersecurity Dashboard", layout="wide")

# ---------------------------
# Cyber Dark Theme
# ---------------------------
st.markdown("""
<style>
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    color: white;
}

h1, h2, h3 {
    color: #00f7ff;
    text-shadow: 0px 0px 10px #00f7ff;
}

[data-testid="stMetric"] {
    background-color: #1c1f26;
    padding: 15px;
    border-radius: 10px;
    box-shadow: 0px 0px 10px rgba(0,255,255,0.3);
}

.stDownloadButton>button {
    background-color: #00f7ff;
    color: black;
    border-radius: 8px;
    border: none;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Title
# ---------------------------
st.markdown(
    "<h1 style='text-align: center;'>🔐 CYBER ATTACK DETECTION SYSTEM</h1>",
    unsafe_allow_html=True
)
st.markdown("### Real-Time Graph-Based Cyber Attack Analysis System")

# ---------------------------
# Dataset Path
# ---------------------------
dataset_path = r"C:\Users\kavya\Desktop\APT_Graph_Mining\CICIDS data set\02-14-2018.csv\02-14-2018.csv"

# ---------------------------
# Load Dataset
# ---------------------------
@st.cache_data
def load_full_dataset(path):
    return load_cicids_dataset(path, rows=None)

df = load_full_dataset(dataset_path)
df["Label"] = df["Label"].astype(str).str.strip()

# ---------------------------
# Dataset Preview
# ---------------------------
st.write("## 📊 Dataset Preview")
st.dataframe(df.head())

# ---------------------------
# Detection Summary
# ---------------------------
total_rows = len(df)
benign_df = df[df["Label"].str.lower() == "benign"]
attack_df = df[df["Label"].str.lower() != "benign"]

benign_count = len(benign_df)
attack_count = len(attack_df)

st.write("## 🚨 Detection Summary")

col1, col2, col3 = st.columns(3)
col1.metric("Total Records", total_rows)
col2.metric("✅ Benign Flows", benign_count)
col3.metric("⚠️ Attack Flows", attack_count)

# ---------------------------
# Attack Type Distribution
# ---------------------------
st.write("## 📊 Attack Type Distribution")

if not attack_df.empty:
    attack_counts = attack_df["Label"].value_counts()
    st.bar_chart(attack_counts)
else:
    st.info("No attack records found.")

# ---------------------------
# Port-Based Attack Analysis
# ---------------------------
st.write("## 🎯 Port-Based Attack Analysis")

if not attack_df.empty:
    attack_ports = attack_df["Dst Port"].value_counts().head(10)

    st.write("### 🔝 Top 10 Attacked Destination Ports")
    st.bar_chart(attack_ports)

selected_port = st.selectbox(
    "Select Destination Port",
    sorted(df["Dst Port"].unique())
)

port_df = df[df["Dst Port"] == selected_port]

st.write(f"### 📄 Records for Port: {selected_port}")
st.dataframe(port_df.head(20))

# ---------------------------
# Attack Severity Analysis
# ---------------------------
st.write("## ⚠️ Attack Severity Analysis")

def get_severity(label):
    label = str(label).lower()

    if "bruteforce" in label or "dos" in label or "ddos" in label:
        return "High"
    elif "bot" in label or "infiltration" in label:
        return "Medium"
    elif label == "benign":
        return "Normal"
    else:
        return "Low"

df["Severity"] = df["Label"].apply(get_severity)

severity_counts = df["Severity"].value_counts()

st.write("### 📊 Severity Distribution")
st.bar_chart(severity_counts)

# ---------------------------
# Download Detected Attacks
# ---------------------------
st.write("## 📥 Download Detected Attacks")

csv_data = attack_df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="⬇️ Download Attack Records as CSV",
    data=csv_data,
    file_name="detected_attacks.csv",
    mime="text/csv"
)

# ---------------------------
# System Conclusion
# ---------------------------
st.write("## 🧠 Final System Conclusion")

if not attack_df.empty:
    top_attack = attack_df["Label"].value_counts().idxmax()
    top_port = attack_df["Dst Port"].value_counts().idxmax()
    attack_percentage = (len(attack_df) / len(df)) * 100

    st.success(
        f"""
        ✅ The system successfully analyzed **{len(df)} network flow records**.

        🚨 Out of these, **{len(attack_df)} flows** were detected as attacks, while **{benign_count} flows** were normal.

        ⚡ The most frequent attack detected is **{top_attack}**.

        🎯 The most targeted destination port is **{top_port}**.

        📊 Attack traffic percentage: **{attack_percentage:.2f}%**

        🔐 This indicates that the dataset contains suspicious activity and the graph-based detection system is able to identify attack patterns effectively.
        """
    )
else:
    st.info("✅ No attacks were detected. All analyzed flows appear to be benign.")

# ---------------------------
# Animated Graph Visualization
# ---------------------------
st.write("## 🎬 Animated Flow Visualization")

if not attack_df.empty:
    selected_attack = st.selectbox(
        "Select attack type for animation",
        attack_df["Label"].value_counts().index.tolist()
    )

    sample_size = st.slider(
        "Select number of flows for animation",
        min_value=5,
        max_value=40,
        value=20
    )

    selected_attack_df = df[df["Label"] == selected_attack].head(sample_size)
    selected_benign_df = benign_df.head(5)

    graph_df = pd.concat([selected_benign_df, selected_attack_df])

    def attack_reason(label, port, protocol):
        label_lower = str(label).lower()

        if "ftp-bruteforce" in label_lower:
            return f"This flow is marked as an attack because it matches FTP brute-force behavior. It targets FTP service port {port}, where repeated login attempts may be performed."
        elif "ssh-bruteforce" in label_lower:
            return f"This flow is marked as an attack because it matches SSH brute-force behavior. It targets SSH service port {port}, commonly used for remote login attempts."
        elif "dos" in label_lower or "ddos" in label_lower:
            return "This flow is marked as an attack because it shows denial-of-service behavior, where traffic may overload a service or network resource."
        elif "bot" in label_lower:
            return "This flow is marked as an attack because it may be generated by automated bot activity."
        else:
            return f"This flow is marked as suspicious because its dataset label is {label}, which is not benign."

    def benign_reason(port, protocol):
        return f"This flow is treated as benign because its dataset label is Benign. The traffic does not match known attack behavior in the CICIDS dataset. It uses destination port {port} and protocol {protocol} as normal network communication."

    def build_graph_data(graph_df):
        nodes = []
        edges = []
        flow_nodes = []
        feature_nodes = {}

        for idx, row in graph_df.iterrows():
            label = str(row["Label"]).strip()
            flow_type = "benign" if label.lower() == "benign" else "attack"

            flow_id = f"Flow_{idx}"
            port_id = f"Port_{row['Dst Port']}"
            protocol_id = f"Protocol_{row['Protocol']}"
            label_id = f"Label_{label}"

            reason = benign_reason(row["Dst Port"], row["Protocol"]) if flow_type == "benign" else attack_reason(label, row["Dst Port"], row["Protocol"])

            flow_nodes.append({
                "id": flow_id,
                "label": flow_id,
                "type": flow_type,
                "details": {
                    "Node": flow_id,
                    "Type": "Benign Flow" if flow_type == "benign" else "Attack Flow",
                    "Destination Port": str(row["Dst Port"]),
                    "Protocol": str(row["Protocol"]),
                    "Label": label,
                    "Reason": reason
                }
            })

            feature_nodes[port_id] = {
                "id": port_id,
                "label": port_id,
                "type": "port",
                "details": {
                    "Node": port_id,
                    "Type": "Destination Port",
                    "Reason": "This node represents the destination service port used by the network flow."
                }
            }

            feature_nodes[protocol_id] = {
                "id": protocol_id,
                "label": protocol_id,
                "type": "protocol",
                "details": {
                    "Node": protocol_id,
                    "Type": "Protocol",
                    "Reason": "This node represents the communication protocol used by the flow."
                }
            }

            feature_nodes[label_id] = {
                "id": label_id,
                "label": label_id,
                "type": "label",
                "details": {
                    "Node": label_id,
                    "Type": "Traffic Label",
                    "Reason": "This node represents the final classification label assigned to the network flow."
                }
            }

            edges.append({"source": flow_id, "target": port_id})
            edges.append({"source": flow_id, "target": protocol_id})
            edges.append({"source": flow_id, "target": label_id})

        flow_y = 570
        feature_y = 160

        for i, node in enumerate(flow_nodes):
            x = 80 + (i % 10) * 110
            y = flow_y + (i // 10) * 45
            node["x"] = x
            node["y"] = y
            node["startY"] = 720

        feature_list = list(feature_nodes.values())

        for i, node in enumerate(feature_list):
            x = 120 + (i % 8) * 135
            y = feature_y + (i // 8) * 70
            node["x"] = x
            node["y"] = y
            node["startY"] = y

        nodes = flow_nodes + feature_list
        return nodes, edges

    nodes, edges = build_graph_data(graph_df)

    def animated_graph_html(nodes, edges):
        nodes_json = json.dumps(nodes)
        edges_json = json.dumps(edges)

        return f"""
<!DOCTYPE html>
<html>
<head>
<style>
body {{
    margin: 0;
    background: #0E1117;
    color: white;
    font-family: Arial, sans-serif;
}}

#graph-container {{
    width: 100%;
    height: 760px;
    background: #0E1117;
    border-radius: 12px;
    overflow: hidden;
}}

.node {{
    cursor: pointer;
    stroke: white;
    stroke-width: 1.5px;
}}

.label {{
    font-size: 12px;
    fill: white;
    pointer-events: none;
}}

.edge {{
    stroke: #777;
    stroke-width: 1.2;
    opacity: 0.55;
}}

.legend-box {{
    cursor: pointer;
}}

.legend-text {{
    fill: white;
    font-size: 14px;
    pointer-events: none;
}}

.button {{
    cursor: pointer;
}}

.button-text {{
    fill: white;
    font-size: 14px;
    pointer-events: none;
}}

#popupOverlay {{
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.78);
    z-index: 9999;
}}

#cyberPopup {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: linear-gradient(135deg, #08111f, #0e2638);
    border: 2px solid #00f7ff;
    border-radius: 16px;
    padding: 22px;
    width: 520px;
    color: white;
    box-shadow: 0 0 30px #00f7ff;
}}

#popupTitle {{
    text-align: center;
    color: #00f7ff;
    font-size: 25px;
    font-weight: bold;
    margin-bottom: 15px;
}}

#popupContent {{
    background: #0E1117;
    border-radius: 10px;
    padding: 15px;
    font-size: 15px;
    line-height: 1.7;
    border: 1px solid #164b5f;
}}

.popup-row {{
    margin-bottom: 10px;
}}

.popup-key {{
    color: #00f7ff;
    font-weight: bold;
}}

.popup-value {{
    color: #ffffff;
}}

.reason-box {{
    margin-top: 12px;
    padding: 12px;
    border-radius: 8px;
    background: #111827;
    border-left: 4px solid #00f7ff;
    color: #ffffff;
}}

#popupClose {{
    margin-top: 18px;
    width: 100%;
    padding: 11px;
    background: #00f7ff;
    color: black;
    border: none;
    border-radius: 8px;
    font-weight: bold;
    font-size: 15px;
    cursor: pointer;
}}

#popupClose:hover {{
    background: #00c3cc;
}}
</style>
</head>

<body>
<div id="graph-container">
<svg id="graph" width="100%" height="760" viewBox="0 0 1200 760">

<defs>
<marker id="arrow" markerWidth="10" markerHeight="10" refX="10" refY="3" orient="auto">
<path d="M0,0 L0,6 L9,3 z" fill="#777"></path>
</marker>
</defs>

<g id="edges"></g>
<g id="nodes"></g>
<g id="texts"></g>

<g id="legend">
<rect class="legend-box" data-group="attack" x="20" y="20" width="190" height="35" rx="8" fill="#FF4B4B"></rect>
<text class="legend-text" x="35" y="43">Red = Attack Flow</text>

<rect class="legend-box" data-group="benign" x="230" y="20" width="190" height="35" rx="8" fill="#87CEEB"></rect>
<text class="legend-text" x="245" y="43">Blue = Benign Flow</text>

<rect class="legend-box" data-group="port" x="440" y="20" width="150" height="35" rx="8" fill="#FFA500"></rect>
<text class="legend-text" x="455" y="43">Orange = Port</text>

<rect class="legend-box" data-group="protocol" x="610" y="20" width="170" height="35" rx="8" fill="#BA68C8"></rect>
<text class="legend-text" x="625" y="43">Violet = Protocol</text>

<rect class="legend-box" data-group="label" x="800" y="20" width="150" height="35" rx="8" fill="#90EE90"></rect>
<text class="legend-text" x="815" y="43">Green = Label</text>

<rect class="button" id="resetBtn" x="980" y="20" width="150" height="35" rx="8" fill="#444"></rect>
<text class="button-text" x="1015" y="43">Reset Graph</text>
</g>

</svg>
</div>

<div id="popupOverlay">
    <div id="cyberPopup">
        <div id="popupTitle">🔐 Node Details</div>
        <div id="popupContent"></div>
        <button id="popupClose" onclick="closePopup()">OK</button>
    </div>
</div>

<script>
const nodesData = {nodes_json};
const edgesData = {edges_json};

const colorMap = {{
    attack: "#FF4B4B",
    benign: "#87CEEB",
    port: "#FFA500",
    protocol: "#BA68C8",
    label: "#90EE90"
}};

const edgeGroup = document.getElementById("edges");
const nodeGroup = document.getElementById("nodes");
const textGroup = document.getElementById("texts");

let nodesById = {{}};

nodesData.forEach(n => {{
    n.currentY = n.startY;
    nodesById[n.id] = n;
}});

function showPopup(details, nodeType) {{
    const title = document.getElementById("popupTitle");
    let titleText = "🔐 Node Details";

    if (nodeType === "attack") titleText = "🚨 Attack Flow Details";
    else if (nodeType === "benign") titleText = "✅ Benign Flow Details";
    else if (nodeType === "port") titleText = "🔌 Port Node Details";
    else if (nodeType === "protocol") titleText = "🔗 Protocol Node Details";
    else if (nodeType === "label") titleText = "🏷️ Label Node Details";

    title.innerHTML = titleText;

    let html = "";

    Object.keys(details).forEach(key => {{
        if (key === "Reason") {{
            html += `
                <div class="reason-box">
                    <span class="popup-key">Why:</span><br>
                    <span class="popup-value">${{details[key]}}</span>
                </div>
            `;
        }} else {{
            html += `
                <div class="popup-row">
                    <span class="popup-key">${{key}}:</span>
                    <span class="popup-value"> ${{details[key]}}</span>
                </div>
            `;
        }}
    }});

    document.getElementById("popupContent").innerHTML = html;
    document.getElementById("popupOverlay").style.display = "block";
}}

function closePopup() {{
    document.getElementById("popupOverlay").style.display = "none";
}}

document.getElementById("popupOverlay").addEventListener("click", function(e) {{
    if (e.target.id === "popupOverlay") closePopup();
}});

function drawGraph() {{
    edgeGroup.innerHTML = "";
    nodeGroup.innerHTML = "";
    textGroup.innerHTML = "";

    edgesData.forEach(e => {{
        const s = nodesById[e.source];
        const t = nodesById[e.target];

        if (!s || !t) return;

        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("x1", s.x);
        line.setAttribute("y1", s.currentY);
        line.setAttribute("x2", t.x);
        line.setAttribute("y2", t.currentY);
        line.setAttribute("class", "edge");
        line.setAttribute("marker-end", "url(#arrow)");
        edgeGroup.appendChild(line);
    }});

    nodesData.forEach(n => {{
        const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        circle.setAttribute("cx", n.x);
        circle.setAttribute("cy", n.currentY);
        circle.setAttribute("r", n.highlight ? 24 : 17);
        circle.setAttribute("fill", colorMap[n.type]);
        circle.setAttribute("opacity", n.opacity !== undefined ? n.opacity : 1);
        circle.setAttribute("class", "node");

        circle.addEventListener("click", () => {{
            showPopup(n.details, n.type);
        }});

        nodeGroup.appendChild(circle);

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", n.x - 30);
        text.setAttribute("y", n.currentY + 35);
        text.setAttribute("class", "label");
        text.textContent = n.label;
        textGroup.appendChild(text);
    }});
}}

function resetGraph() {{
    nodesData.forEach(n => {{
        n.currentY = n.startY;
        n.highlight = false;
        n.opacity = 1;
    }});
    drawGraph();
}}

function animateGroup(groupName) {{
    nodesData.forEach(n => {{
        n.highlight = n.type === groupName;
        n.opacity = n.type === groupName ? 1 : 0.2;
    }});

    let startTime = null;
    const duration = 900;

    function animate(timestamp) {{
        if (!startTime) startTime = timestamp;
        let progress = Math.min((timestamp - startTime) / duration, 1);

        nodesData.forEach(n => {{
            if (n.type === groupName) {{
                const start = n.startY;
                const end = n.y;
                n.currentY = start + (end - start) * progress;
            }}
        }});

        drawGraph();

        if (progress < 1) requestAnimationFrame(animate);
    }}

    requestAnimationFrame(animate);
}}

document.querySelectorAll(".legend-box").forEach(box => {{
    box.addEventListener("click", () => {{
        const group = box.getAttribute("data-group");
        resetGraph();
        setTimeout(() => animateGroup(group), 100);
    }});
}});

document.getElementById("resetBtn").addEventListener("click", resetGraph);

drawGraph();
</script>

</body>
</html>
"""

    html_code = animated_graph_html(nodes, edges)

    components.html(html_code, height=780, scrolling=False)

    st.markdown("""
    ### ✅ Graph Explanation
    - Complete dataset is used for statistics and attack analysis.
    - Selected sample is used for animation to avoid browser lag.
    - Click legend colors to animate that node type from bottom to top.
    - Click any node to view node details and reason.
    """)

# ---------------------------
# Footer
# ---------------------------
st.markdown("---")
st.markdown("🚀 Built using Python, NetworkX, VF2, Streamlit, and Graph Mining Techniques")