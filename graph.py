import pprint
import json

pp = pprint.PrettyPrinter(depth=4)

def process_node(node):
    node_name = node["node_name"]
    configured_level = node["configured_level"]
    
    edges = {}
    for link in node["links"]:
        result = process_link(link)
        if result is None:
            continue
        start, end, constraint = result
        edges[end] = constraint
    return node_name, edges

def process_link(link):
    start = link["node_name"]
    our_level = link["lie_fsm"]["level"]
    neighbor = link["lie_fsm"]["neighbor"]
    if neighbor is None:
        return None
    their_level = neighbor["level"]
    end = neighbor["name"]
    state = link["lie_fsm"]["lie_state"]
    level = link["lie_fsm"]["level"]

    constraint = our_level > their_level
    return start, end, constraint

file = open("1_out.json")
network = json.load(file)

graph = ["digraph {"]

nodes = {}

for node in network["nodes"]:
    node_name, edges = process_node(node)
    nodes[node_name] = edges

pp.pprint(nodes)

for (start, edges) in nodes.items():
    for (end, constraint) in edges.items():
        both = end in nodes and start in nodes[end]
        if both and not constraint:
            continue
        elif both:
            graph.append(f"{start} -> {end} [dir=both]")
        else:
            graph.append(f"{start} -> {end}")

graph.append("}")
graph = "\n".join(graph)
outfile = open("1_out.dot", "w")
outfile.write(graph)