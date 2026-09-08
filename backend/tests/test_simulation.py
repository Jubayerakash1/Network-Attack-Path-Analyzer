"""
Network Attack Path Analyzer
Author: MD Jubayer Khan Akash
Project version: 0.7.0
"""

from app.models.schemas import Network
from app.services.graph_engine import build_graph
from app.services.simulation_engine import simulate_rule_change


def test_rule_simulation_can_block_path():
    network = Network(
        nodes=[
            {"id":"internet","name":"Internet","type":"external","zone":"external","criticality":10,"exposed":True},
            {"id":"db","name":"DB","type":"database","zone":"restricted","criticality":10},
        ],
        edges=[{"source":"internet","target":"db","protocol":"TCP","port":3306,"allowed":True}],
    )
    result = simulate_rule_change(build_graph(network), "internet", "db", "internet", "db", False)
    assert result["baseline_path_count"] == 1
    assert result["post_change_path_count"] == 0
