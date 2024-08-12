#!/usr/bin/env python

from datetime import datetime
import getopt
from jaal import Jaal
from jaal.datasets import load_got
import json
import matplotlib.pyplot as plt
import networkx
import pandas
import pydot
import sys

if __name__ == '__main__':
    dot_string = sys.stdin.read()
    graph = pydot.graph_from_dot_data(dot_string)[0]

    node_data = []
    for node in graph.get_nodes():
        node_dict = {}
        node_dict["id"] = node.get_name()
        label = json.loads(json.loads(node.get_label()))
        node_dict["key_id"] = label["key_id"]
        node_dict["title"] = label["uid"]
        node_dict["name"] = label["name"]
        node_dict["email"] = label["email"]
        node_dict["comment"] = label["comment"]
        node_dict["is_revoked"] = label["is_revoked"]
        node_dict["is_primary"] = label["is_primary"]

        node_data.append(node_dict)
    node_df = pandas.DataFrame(node_data)
    print(node_df)

    edge_data = []
    for edge in graph.get_edges():
        edge_dict = {}
        edge_dict["from"] = edge.get_source()
        edge_dict["to"] = edge.get_destination()
        edge_dict["self_loop"] = edge.get_source() == edge.get_destination()
        label = json.loads(json.loads(edge.get_label()))
        edge_dict["trust_level"] = label["trust_level"]
        edge_dict["trust_value"] = label["trust_value"]
        edge_dict["sig_type"] = label["sig_type"]
        edge_dict["creation_time"] = datetime.utcfromtimestamp(label["creation_time"])
        edge_data.append(edge_dict)
    edge_df = pandas.DataFrame(edge_data)
    print(edge_df)

    if "--networkx" in sys.argv:
        G = networkx.DiGraph()
        for index, row in node_df.iterrows():
            G.add_node(row["id"], label=row["title"], color='blue' if not row["is_revoked"] else 'red')
        for index, row in edge_df.iterrows():
            G.add_edge(row["from"], row["to"], color='black' if row["sig_type"] != "Revoke" else 'red', label=row["sig_type"] if row["sig_type"] != "Default" else "")

        plt.figure()

        pos = networkx.arf_layout(G)
        networkx.draw(G, pos, edge_color=networkx.get_edge_attributes(G, 'color').values(), node_color=networkx.get_node_attributes(G, 'color').values())
        node_labels = networkx.get_node_attributes(G, 'label')
        networkx.draw_networkx_labels(G, pos, labels=node_labels)
        edge_labels = networkx.get_edge_attributes(G, 'label')
        networkx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

        plt.show()

    if "--jaal" in sys.argv or "--networkx" not in sys.argv:
        # init Jaal and run server
        Jaal(edge_df, node_df).plot(directed=True, vis_opts={'height': '1080px'})

    print()
