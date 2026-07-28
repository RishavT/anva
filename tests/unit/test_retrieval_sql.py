"""Structural guards for permission-first retrieval SQL."""

from __future__ import annotations

import pytest

from anva.core.services.graph import _GRAPH_SQL
from anva.core.services.search import _SEARCH_SQL


@pytest.mark.unit
@pytest.mark.parametrize(
    ("sql", "authorized_cte"),
    (
        (_SEARCH_SQL, "authorized_chunks AS MATERIALIZED"),
        (_GRAPH_SQL, "authorized_edges AS MATERIALIZED"),
    ),
)
def test_retrieval_sql_binds_current_principal_and_lineage(
    sql: str,
    authorized_cte: str,
) -> None:
    normalized = " ".join(sql.split())

    assert authorized_cte in sql
    assert normalized.index(authorized_cte) < normalized.index("core_membership")
    assert "%(actor_type)s" in sql
    assert "%(actor_id)s" in sql
    assert "%(credential_id)s" in sql
    assert "core_membership" in sql
    assert "core_serviceidentity" in sql
    assert "core_accessgrant" in sql
    assert "core_accessscopemembership" in sql
    assert "core_accessscopeserviceidentity" in sql
    assert "core_accessscoperepository" in sql
    assert "core_accessscopesource" in sql
    assert "core_repositoryaccesstoken" in sql
    assert "core_parsedsource" in sql
    assert "current_revision_id" in sql
    assert "last_seen_run_id" in sql
    assert "snapshot.revoked_at IS NULL" in sql
    assert "scope_ids" not in sql


@pytest.mark.unit
def test_search_authorizes_before_both_ranking_branches() -> None:
    assert _SEARCH_SQL.index("authorized_chunks AS MATERIALIZED") < _SEARCH_SQL.index("lexical AS")
    assert _SEARCH_SQL.index("authorized_chunks AS MATERIALIZED") < _SEARCH_SQL.index("semantic AS")
    assert "search_vector @@ query_input.ts_query" in _SEARCH_SQL
    assert "embedding <=> %(embedding)s::vector" in _SEARCH_SQL
    assert "1.0 / (%(rrf_k)s + lexical.lexical_rank)" in _SEARCH_SQL


@pytest.mark.unit
def test_graph_authorizes_endpoint_scopes_before_recursive_walk() -> None:
    assert _GRAPH_SQL.index("authorized_edges AS MATERIALIZED") < _GRAPH_SQL.index("walk AS")
    assert "JOIN core_accessscope source_scope" in _GRAPH_SQL
    assert "JOIN core_accessscope target_scope" in _GRAPH_SQL
    assert "source_member" in _GRAPH_SQL
    assert "target_member" in _GRAPH_SQL
    assert "source_service" in _GRAPH_SQL
    assert "target_service" in _GRAPH_SQL
    assert "source_repository" in _GRAPH_SQL
    assert "target_repository" in _GRAPH_SQL
    assert "FROM authorized_edges candidate" in _GRAPH_SQL
