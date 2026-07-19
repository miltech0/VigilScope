"""Build a cycle-safe forest from parent-child process relationships."""

from __future__ import annotations

from dataclasses import dataclass, field

from .process_models import ProcessIdentity, ProcessRecord, process_identity


@dataclass
class ProcessTreeNode:
    record: ProcessRecord
    children: list["ProcessTreeNode"] = field(default_factory=list)


@dataclass
class ProcessForest:
    roots: list[ProcessTreeNode]
    orphans: list[ProcessTreeNode]


def build_process_forest(records: list[ProcessRecord]) -> ProcessForest:
    identities = {process_identity(record): record for record in records}
    pid_index = {int(record["pid"]): identity for identity, record in identities.items()}
    parent_map: dict[ProcessIdentity, ProcessIdentity | None | str] = {}

    for identity, record in identities.items():
        ppid = int(record.get("ppid", 0))
        if ppid <= 0:
            parent_map[identity] = None
            continue
        parent = pid_index.get(ppid)
        if parent is None or parent == identity:
            parent_map[identity] = "orphan"
            continue
        parent_map[identity] = parent

    # Walk upward from every identity to isolate self-cycles and longer loops.
    for identity in list(parent_map):
        seen: set[ProcessIdentity] = set()
        current: ProcessIdentity | None | str = identity
        while isinstance(current, tuple):
            if current in seen:
                for cyclic in seen:
                    parent_map[cyclic] = "orphan"
                break
            seen.add(current)
            current = parent_map.get(current, "orphan")

    nodes = {
        identity: ProcessTreeNode(record=record)
        for identity, record in identities.items()
    }
    roots: list[ProcessTreeNode] = []
    orphans: list[ProcessTreeNode] = []
    for identity, node in nodes.items():
        parent = parent_map[identity]
        if parent is None:
            roots.append(node)
        elif parent == "orphan" or parent not in nodes:
            orphans.append(node)
        else:
            nodes[parent].children.append(node)

    def sort_key(node: ProcessTreeNode) -> tuple[str, int]:
        return (
            str(node.record.get("name", "")).casefold(),
            int(node.record.get("pid", 0)),
        )

    for node in nodes.values():
        node.children.sort(key=sort_key)
    roots.sort(key=sort_key)
    orphans.sort(key=sort_key)
    return ProcessForest(roots=roots, orphans=orphans)
