"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

import networkx as nx

from app.models.schemas import Network


def build_graph(network: Network) -> nx.DiGraph:
    graph = nx.DiGraph()
    for node in network.nodes:
        graph.add_node(
            node.id,
            name=node.name,
            type=node.type,
            zone=node.zone,
            criticality=node.criticality,
            exposed=node.exposed,
            open_ports=node.open_ports,
            vulnerabilities=[v.model_dump() for v in node.vulnerabilities],
        )
    for edge in network.edges:
        if edge.source not in graph or edge.target not in graph:
            raise ValueError(f"Edge references unknown node: {edge.source} -> {edge.target}")
        if edge.allowed:
            graph.add_edge(
                edge.source,
                edge.target,
                protocol=edge.protocol,
                port=edge.port,
                description=edge.description,
            )
    return graph
