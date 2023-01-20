import pprint
import json
import sys

pp = pprint.PrettyPrinter(depth=4)

def process_node(node):
    node_name = node["node_name"]
    configured_level = node["configured_level"]
    
    edges = {}
    level = configured_level
    for link in node["links"]:
        result = process_link(link)
        if result is None:
            continue
        start, end, state, our_level, their_level = result
        if level is None:
            level = our_level
        assert(level == our_level)
        edges[end] = {
            "end_level": their_level,
            "state": state
        }
    return node_name, level, edges

def process_link(link):
    start = link["node_name"]
    our_level = link["lie_fsm"]["level"]
    neighbor = link["lie_fsm"]["neighbor"]
    if neighbor is None:
        return None
    their_level = neighbor["level"]
    end = neighbor["name"]
    state = link["lie_fsm"]["lie_state"]

    return start, end, state, our_level, their_level

FILENAME = sys.argv[1]
print(f"opening {FILENAME}.json, writing to {FILENAME}.dot...")

file = open(f"{FILENAME}.json")
network = json.load(file)

graph = ["digraph {"]

all_edges = {}

for node in network["nodes"]:
    node_name, level, link_edges = process_node(node)
    graph.append(f'{node_name} [label="{node_name}\nlevel {level}"];')
    for (end_name, edge_info) in link_edges.items():
        end_level = edge_info["end_level"]
        state = edge_info["state"]
        if (end_name, node_name) in all_edges:
            pair = (end_name, node_name)
            all_edges[pair]["both"] = True

            assert(all_edges[pair]["end_state"] == "unknown")
            all_edges[pair]["end_state"] = state
            
            assert(all_edges[pair]["end_level"] == level)
        else:
            pair = (node_name, end_name)
            all_edges[pair] = {
                "end": end_name,
                "both": False,
                "start_level": level,
                "end_level": end_level,
                "start_state": state,
                "end_state": "unknown",
            }

for ((start, end), info) in all_edges.items():
    both = info["both"]
    start_level = info["start_level"]
    end_level = info["end_level"]
    start_state = info["start_state"]
    end_state = info["end_state"]

    edge_a = start
    edge_b = end
    if end_level > start_level:
        edge_a = end
        edge_b = start

    direction = "both" if both else "forward"

    color_lookup = {
        "OneWay": "green",
        "TwoWay": "blue",
        "ThreeWay": "black",
        "MultipleNeighborsWait": "orange",
        "unknown": "white",
    }
    start_color = color_lookup[start_state]
    end_color = color_lookup[end_state]
    

    graph.append(f'{edge_a} -> {edge_b} [dir={direction} color="{start_color}:{end_color}"];')

graph.append("}")
graph = "\n".join(graph)
outfile = open(f"{FILENAME}.dot", "w")
outfile.write(graph)