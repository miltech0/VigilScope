from system_info.process_tree import build_process_forest


def process(pid: int, ppid: int, name: str) -> dict[str, object]:
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "create_time": float(pid),
    }


def test_parent_child_tree_is_built() -> None:
    records = [
        process(1, 0, "root.exe"),
        process(2, 1, "child.exe"),
        process(3, 2, "grandchild.exe"),
    ]
    forest = build_process_forest(records)

    assert [node.record["pid"] for node in forest.roots] == [1]
    assert forest.roots[0].children[0].record["pid"] == 2
    assert forest.roots[0].children[0].children[0].record["pid"] == 3
    assert forest.orphans == []


def test_missing_parent_is_grouped_as_orphan() -> None:
    forest = build_process_forest([process(10, 999, "orphan.exe")])
    assert forest.roots == []
    assert [node.record["pid"] for node in forest.orphans] == [10]


def test_cyclic_parent_data_does_not_recurse() -> None:
    forest = build_process_forest(
        [process(20, 21, "one.exe"), process(21, 20, "two.exe")]
    )
    assert forest.roots == []
    assert {node.record["pid"] for node in forest.orphans} == {20, 21}

