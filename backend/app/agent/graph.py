# backend/app/agent/graph.py
from langgraph.graph import StateGraph, END
from app.agent.state import AgentState
from app.agent.nodes.fetcher import fetcher_node
from app.agent.nodes.prefilter import prefilter_node
from app.agent.nodes.analyzer import analyzer_node
from app.agent.nodes.aggregator import aggregator_node
from app.agent.nodes.reporter import reporter_node


def _should_continue(state: AgentState) -> str:
    # conditional edge — if any node sets error, go to END immediately
    # otherwise continue to next node
    if state.get("error"):
        return "end"
    return "continue"


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    # add all nodes
    graph.add_node("fetcher"    , fetcher_node)
    graph.add_node("prefilter"  , prefilter_node)
    graph.add_node("analyzer"   , analyzer_node)
    graph.add_node("aggregator" , aggregator_node)
    graph.add_node("reporter"   , reporter_node)

    # set entry point
    graph.set_entry_point("fetcher")

    # edges with error checking between each node
    graph.add_conditional_edges(
        "fetcher",
        _should_continue,
        {"continue": "prefilter", "end": END},
    )
    graph.add_conditional_edges(
        "prefilter",
        _should_continue,
        {"continue": "analyzer", "end": END},
    )
    graph.add_conditional_edges(
        "analyzer",
        _should_continue,
        {"continue": "aggregator", "end": END},
    )
    graph.add_edge("aggregator", "reporter")
    graph.add_edge("reporter"  , END)

    return graph.compile()


# singleton — compile graph once, reuse for every scan
_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph