"""
Drishti - Interactive Forensic Link Graph Module
Builds NetworkX multi-entity relationship graph and renders cyber-themed PyVis interactive visual.
Enhanced with spacious layout, hover-only edge tooltips, peripheral evidence nodes, and auto-centering.
"""

import networkx as nx
from pyvis.network import Network
import tempfile
import math
import os


def generate_forensic_link_graph(cross_links, all_entities=None, custom_evidence_links=None):
    """
    Constructs multi-relational NetworkX graph of cybercrime incident
    and returns styled PyVis HTML string for Streamlit embedding.
    """
    G = nx.DiGraph()

    # Core Incident Entities (Victim, Scammer, IP, Mule Accounts are the biggest nodes)
    nodes_data = [
        # Scammer Phone (Threat Actor - Top Priority Node)
        ("+91-98765-43210\n(Vishing Actor)", {
            "group": "Scammer", "color": "#ef4444", "size": 46, "shape": "diamond",
            "title": "🚨 <b>THREAT ACTOR NUMBER:</b> +91-98765-43210<br>Role: Impersonated SBI KYC Officer<br>Status: Disseminated phishing links & intercepted OTP<br>Corroborated across: Call Logs, WhatsApp, KYC Notice PDF",
            "font": {"size": 13, "color": "#fee2e2", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 2.2
        }),
        # Primary Mule: Ramesh Traders (Major Financial Inflow Node)
        ("Ramesh Traders\n(Primary Mule A/C)", {
            "group": "MulePrimary", "color": "#f97316", "size": 44, "shape": "triangle",
            "title": "⚠️ <b>PRIMARY MULE BENEFICIARY:</b> Ramesh Traders<br>A/C: 981234564521 (HDFC Bank)<br>VPA: ramesh.traders@okhdfcbank<br>Inflow: ₹80,000 (Two debits: ₹49,000 + ₹31,000)<br>Action: Immediate laundering to secondary mules",
            "font": {"size": 13, "color": "#ffedd5", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 2.0
        }),
        # Victim: Rahul Sharma
        ("Rahul Sharma\n(Victim)", {
            "group": "Victim", "color": "#10b981", "size": 42, "shape": "dot",
            "title": "🛡️ <b>VICTIM:</b> Rahul Sharma<br>City: Kanpur, UP<br>Bank A/C: 30192837465 (SBI)<br>Registered Phone: +91-94501-11223<br>Total Financial Loss: ₹80,000.00",
            "font": {"size": 13, "color": "#d1fae5", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 2.0
        }),
        # Unauthorized Intruder IP: Delhi
        ("103.87.212.45\n(Attacker IP - Delhi)", {
            "group": "IP", "color": "#ec4899", "size": 40, "shape": "square",
            "title": "💻 <b>ATTACKER IP ADDRESS:</b> 103.87.212.45<br>Location: Delhi NCR (ISP: Excitel Broadband)<br>Timestamp: 02:14 AM IST (Nocturnal Session Hijack)<br>Client: Linux x86_64 / Chrome",
            "font": {"size": 13, "color": "#fce7f3", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 1.8
        }),
        # Sub-Mule 1: Vikram Enterprises
        ("Vikram Enterprises\n(Mule Layer 2)", {
            "group": "MuleSecondary", "color": "#eab308", "size": 34, "shape": "triangleDown",
            "title": "🔄 <b>SECONDARY MULE LAYER 1:</b> Vikram Enterprises<br>A/C: 440918237712 (ICICI Bank)<br>VPA: vikram.ent@okicici<br>Launder Inflow: ₹45,000.00 via IMPS",
            "font": {"size": 12, "color": "#fef9c3", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 1.5
        }),
        # Sub-Mule 2: Deepak Rawat
        ("Deepak Rawat\n(Mule Layer 2)", {
            "group": "MuleSecondary", "color": "#eab308", "size": 34, "shape": "triangleDown",
            "title": "🔄 <b>SECONDARY MULE LAYER 2:</b> Deepak Rawat<br>A/C: 552109483319 (State Bank of India)<br>VPA: deepak99@oksbi<br>Launder Inflow: ₹34,000.00 via IMPS",
            "font": {"size": 12, "color": "#fef9c3", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 1.5
        }),
        # Phishing Link Portal
        ("sbi-kyc-update-portal.in\n(Phishing Portal)", {
            "group": "Phishing", "color": "#f43f5e", "size": 30, "shape": "hexagon",
            "title": "🎣 <b>CREDENTIAL HARVESTING PORTAL:</b><br>URL: https://sbi-kyc-update-portal.in/verify<br>Method: Posed as official SBI KYC portal to steal username, password & OTP",
            "font": {"size": 12, "color": "#ffe4e6", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 1.3
        }),
        # Legitimate Home IP: Kanpur
        ("122.161.45.10\n(Victim Home IP)", {
            "group": "Normal", "color": "#06b6d4", "size": 26, "shape": "dot",
            "title": "🏠 <b>VICTIM HOME IP:</b> 122.161.45.10<br>Location: Kanpur, Uttar Pradesh<br>ISP: Bharti Airtel Broadband<br>Status: Legitimate baseline access point",
            "font": {"size": 11, "color": "#cffafe", "strokeWidth": 3, "strokeColor": "#090d16"},
            "mass": 1.2
        })
    ]

    for node_id, attrs in nodes_data:
        G.add_node(node_id, **attrs)

    # Core Relational Edges: Label removed so canvas is clean; title set for rich hover tooltip!
    edges_data = [
        ("Rahul Sharma\n(Victim)", "122.161.45.10\n(Victim Home IP)", {
            "title": "<b>Authorized Connection:</b> Regular access from Kanpur home network",
            "color": "#06b6d4", "width": 2, "arrows": "to"
        }),
        ("+91-98765-43210\n(Vishing Actor)", "Rahul Sharma\n(Victim)", {
            "title": "<b>Vishing Call:</b> 312-second voice call posing as SBI KYC Officer + WhatsApp messaging",
            "color": "#ef4444", "width": 4, "arrows": "to"
        }),
        ("+91-98765-43210\n(Vishing Actor)", "sbi-kyc-update-portal.in\n(Phishing Portal)", {
            "title": "<b>Phishing Distribution:</b> Transmitted fake verification link via WhatsApp",
            "color": "#f43f5e", "width": 3, "arrows": "to"
        }),
        ("Rahul Sharma\n(Victim)", "sbi-kyc-update-portal.in\n(Phishing Portal)", {
            "title": "<b>Credential Exfiltration:</b> Victim submitted netbanking credentials and OTP",
            "color": "#f43f5e", "width": 2, "dashes": [4, 4], "arrows": "to"
        }),
        ("103.87.212.45\n(Attacker IP - Delhi)", "Rahul Sharma\n(Victim)", {
            "title": "<b>Session Hijack:</b> Unauthorized netbanking session initiated from Delhi @ 02:14 AM",
            "color": "#ec4899", "width": 4, "arrows": "to"
        }),
        ("Rahul Sharma\n(Victim)", "Ramesh Traders\n(Primary Mule A/C)", {
            "title": "<b>Fraudulent Debits:</b> Drained ₹49,000 (02:17 AM) + ₹31,000 (02:21 AM) via UPI",
            "color": "#ef4444", "width": 5, "arrows": "to"
        }),
        ("Ramesh Traders\n(Primary Mule A/C)", "Vikram Enterprises\n(Mule Layer 2)", {
            "title": "<b>Mule Layering 1:</b> Rapid IMPS transfer of ₹45,000 to secondary mule (02:25 AM)",
            "color": "#f97316", "width": 3, "arrows": "to"
        }),
        ("Ramesh Traders\n(Primary Mule A/C)", "Deepak Rawat\n(Mule Layer 2)", {
            "title": "<b>Mule Layering 2:</b> Rapid IMPS transfer of ₹34,000 to secondary mule (02:27 AM)",
            "color": "#f97316", "width": 3, "arrows": "to"
        })
    ]

    for src, dst, attrs in edges_data:
        G.add_edge(src, dst, **attrs)

    # Evidence File Nodes (Muted purple boxes positioned on the outer perimeter)
    evidence_nodes = [
        ("Evidence:\ncall_logs.csv", ["+91-98765-43210\n(Vishing Actor)", "Rahul Sharma\n(Victim)"]),
        ("Evidence:\nwhatsapp_chat.txt", ["+91-98765-43210\n(Vishing Actor)", "sbi-kyc-update-portal.in\n(Phishing Portal)"]),
        ("Evidence:\nlogin_logs.csv", ["103.87.212.45\n(Attacker IP - Delhi)", "122.161.45.10\n(Victim Home IP)"]),
        ("Evidence:\ntransactions.csv", ["Ramesh Traders\n(Primary Mule A/C)", "Vikram Enterprises\n(Mule Layer 2)", "Deepak Rawat\n(Mule Layer 2)"]),
        ("Evidence:\nfake_kyc_notice.pdf", ["+91-98765-43210\n(Vishing Actor)", "sbi-kyc-update-portal.in\n(Phishing Portal)"]),
        ("Evidence:\nscreenshot_original.png", ["Ramesh Traders\n(Primary Mule A/C)", "103.87.212.45\n(Attacker IP - Delhi)"])
    ]

    # Calculate wide circular outer perimeter coordinates (radius ~580px)
    outer_radius = 580
    num_ev = len(evidence_nodes)

    for i, (ev_id, linked_entities) in enumerate(evidence_nodes):
        angle = (2 * math.pi / num_ev) * i - (math.pi / 2)
        x_pos = int(outer_radius * math.cos(angle))
        y_pos = int(outer_radius * math.sin(angle))

        G.add_node(
            ev_id,
            group="Evidence",
            color={
                "background": "#2e1065",  # Deep purple background
                "border": "#7c3aed",      # Bright purple border
                "highlight": {"background": "#3b0764", "border": "#a855f7"}
            },
            size=12,
            shape="box",
            mass=0.6,
            x=x_pos,
            y=y_pos,
            font={"size": 10, "color": "#c4b5fd", "face": "Segoe UI, sans-serif", "strokeWidth": 2, "strokeColor": "#090d16"},
            title=f"📁 <b>FORENSIC EXHIBIT:</b> {ev_id.replace(chr(10), ' ')}<br>Status: Cryptographically verified in Vault<br>Links corroborating key incident entities"
        )

        for target in linked_entities:
            if target in G:
                # Corroborates edges: lighter, thinner, subtle dashed line with hover tooltip
                G.add_edge(
                    ev_id,
                    target,
                    title=f"<b>Corroboration:</b> Entity evidenced in {ev_id.replace(chr(10), ' ')}",
                    color="rgba(147, 51, 234, 0.28)",  # Soft light purple/slate trace
                    width=0.8,
                    dashes=[3, 6],
                    arrows="to"
                )

    # PyVis Network Configuration (Height increased to 750px)
    net = Network(height="750px", width="100%", bgcolor="#090d16", font_color="#e2e8f0", directed=True)
    net.from_nx(G)

    # Set spacious Barnes-Hut physics configuration with avoidOverlap and large springLength
    net.set_options("""
    {
      "nodes": {
        "borderWidth": 2,
        "shadow": {
          "enabled": true,
          "color": "rgba(0,0,0,0.6)",
          "size": 8,
          "x": 2,
          "y": 2
        }
      },
      "edges": {
        "smooth": {
          "type": "cubicBezier",
          "forceDirection": "none",
          "roundness": 0.25
        },
        "selectionWidth": 2
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -15000,
          "centralGravity": 0.18,
          "springLength": 300,
          "springConstant": 0.04,
          "damping": 0.09,
          "avoidOverlap": 1.0
        },
        "solver": "barnesHut",
        "stabilization": {
          "enabled": true,
          "iterations": 250,
          "updateInterval": 25,
          "fit": true
        }
      },
      "interaction": {
        "hover": true,
        "navigationButtons": true,
        "keyboard": true,
        "tooltipDelay": 80
      }
    }
    """)

    # Save to temp HTML
    fd, path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    net.save_graph(path)
    
    with open(path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    try:
        os.remove(path)
    except Exception:
        pass

    # Inject network.fit() on stabilization so the graph automatically centers perfectly
    fit_hook = """
                  network = new vis.Network(container, data, options);
                  network.once("stabilizationIterationsDone", function() {
                      network.fit({
                          animation: {
                              duration: 800,
                              easingFunction: "easeInOutQuad"
                          }
                      });
                  });
                  // Safety timer ensures centering even if rendering completes instantaneously
                  setTimeout(function() {
                      if (network) { network.fit(); }
                  }, 800);
    """
    if "network = new vis.Network(container, data, options);" in html_content:
        html_content = html_content.replace(
            "network = new vis.Network(container, data, options);",
            fit_hook
        )

    return html_content
