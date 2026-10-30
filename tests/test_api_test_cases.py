"""
tests/test_api_test_cases.py — Unit & Integration tests for Test Cases Dataset Explorer API (ISSUE-006)
"""

import pytest
from fastapi.testclient import TestClient
from web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_test_cases_filters(client):
    """Verify that /api/test-cases/filters returns valid aggregated metadata from master_benchmark.parquet."""
    response = client.get("/api/test-cases/filters")
    assert response.status_code == 200, response.text
    data = response.json()

    assert "total_pool_cases" in data
    assert data["total_pool_cases"] >= 9000
    assert "datasets" in data
    assert len(data["datasets"]) > 0
    assert "threat_domains" in data
    assert len(data["threat_domains"]) > 0
    assert "analysis_tiers" in data
    assert len(data["analysis_tiers"]) > 0

    # Ensure dataset items have name and count
    first_ds = data["datasets"][0]
    assert "name" in first_ds and "count" in first_ds
    assert first_ds["count"] > 0


def test_api_test_cases_default_pagination(client):
    """Verify that /api/test-cases returns default paginated records (50 per page)."""
    response = client.get("/api/test-cases")
    assert response.status_code == 200, response.text
    data = response.json()

    assert "cases" in data
    assert "pagination" in data
    cases = data["cases"]
    pag = data["pagination"]

    assert len(cases) == 50
    assert pag["page"] == 1
    assert pag["limit"] == 50
    assert pag["total_records"] >= 9000
    assert pag["total_pages"] > 180
    assert pag["has_next"] is True
    assert pag["has_prev"] is False

    # Check structure of a test case record
    c = cases[0]
    assert "id" in c
    assert "source_dataset" in c
    assert "threat_domain" in c
    assert "analysis_tier" in c
    assert "is_malicious" in c
    assert "cwe" in c
    assert "tool_name" in c
    assert "tool_arguments" in c
    assert "context" in c


def test_api_test_cases_custom_page_and_limit(client):
    """Verify that page stepping and custom limit work accurately."""
    response_p1 = client.get("/api/test-cases?page=1&limit=20")
    assert response_p1.status_code == 200
    data_p1 = response_p1.json()
    assert len(data_p1["cases"]) == 20
    assert data_p1["pagination"]["page"] == 1
    assert data_p1["pagination"]["limit"] == 20

    response_p2 = client.get("/api/test-cases?page=2&limit=20")
    assert response_p2.status_code == 200
    data_p2 = response_p2.json()
    assert len(data_p2["cases"]) == 20
    assert data_p2["pagination"]["page"] == 2
    assert data_p2["pagination"]["has_prev"] is True

    # Page 1 and Page 2 should have completely different test case IDs
    ids_p1 = [c["id"] for c in data_p1["cases"]]
    ids_p2 = [c["id"] for c in data_p2["cases"]]
    assert set(ids_p1).isdisjoint(set(ids_p2))


def test_api_test_cases_filtering(client):
    """Verify filtering by status, threat_domain, dataset, and analysis_tier."""
    # Filter by status: safe (is_malicious = False)
    res_safe = client.get("/api/test-cases?status=safe&limit=20")
    assert res_safe.status_code == 200
    data_safe = res_safe.json()
    for c in data_safe["cases"]:
        assert c["is_malicious"] is False

    # Filter by status: malicious (is_malicious = True)
    res_mal = client.get("/api/test-cases?status=malicious&limit=20")
    assert res_mal.status_code == 200
    data_mal = res_mal.json()
    for c in data_mal["cases"]:
        assert c["is_malicious"] is True

    # Filter by threat_domain: SQLI
    res_sqli = client.get("/api/test-cases?threat_domain=SQLI&limit=20")
    assert res_sqli.status_code == 200
    data_sqli = res_sqli.json()
    for c in data_sqli["cases"]:
        assert c["threat_domain"] == "SQLI"


def test_api_test_cases_empty_state(client):
    """Verify that impossible filter criteria returns 0 records gracefully."""
    response = client.get("/api/test-cases?dataset=NON_EXISTENT_DATASET_XYZ")
    assert response.status_code == 200
    data = response.json()
    assert len(data["cases"]) == 0
    assert data["pagination"]["total_records"] == 0
    assert data["pagination"]["total_pages"] == 1
    assert data["pagination"]["has_next"] is False
    assert data["pagination"]["has_prev"] is False


def test_api_get_single_test_case(client):
    """Verify fetching a specific test case by ID for deep-linking (ISSUE-007)."""
    # 1. Fetch first available case to get a valid ID
    list_res = client.get("/api/test-cases?limit=1")
    assert list_res.status_code == 200
    target_id = list_res.json()["cases"][0]["id"]

    # 2. Fetch specific case by ID
    res = client.get(f"/api/test-cases/{target_id}")
    assert res.status_code == 200
    case_data = res.json()
    assert case_data["id"] == target_id
    assert "source_dataset" in case_data
    assert "threat_domain" in case_data
    assert "analysis_tier" in case_data
    assert "is_malicious" in case_data
    assert "cwe" in case_data
    assert "owasp_llm" in case_data
    assert "traffic_direction" in case_data
    assert "tool_name" in case_data
    assert "tool_arguments" in case_data
    assert "context" in case_data

    # 3. Fetch non-existent ID
    res_404 = client.get("/api/test-cases/non_existent_case_id_999999")
    assert res_404.status_code == 404
    assert "detail" in res_404.json()


def test_api_get_single_test_case_benign_and_threat(client):
    """Verify single case retrieval works for both benign and malicious scenarios."""
    # Find a threat case
    threat_list = client.get("/api/test-cases?status=malicious&limit=1").json()
    threat_id = threat_list["cases"][0]["id"]
    threat_case = client.get(f"/api/test-cases/{threat_id}").json()
    assert threat_case["id"] == threat_id
    assert threat_case["is_malicious"] is True

    # Find a safe case
    safe_list = client.get("/api/test-cases?status=safe&limit=1").json()
    safe_id = safe_list["cases"][0]["id"]
    safe_case = client.get(f"/api/test-cases/{safe_id}").json()
    assert safe_case["id"] == safe_id
    assert safe_case["is_malicious"] is False


def test_api_test_cases_search_special_characters(client):
    """Verify substring ILIKE search handles attack payloads and special chars (ISSUE-008)."""
    # 1. Search for command injection payload
    res_cmd = client.get("/api/test-cases?search=passwd&limit=20")
    assert res_cmd.status_code == 200
    data_cmd = res_cmd.json()
    assert len(data_cmd["cases"]) > 0
    for c in data_cmd["cases"]:
        matched = (
            "passwd" in c["context"].lower()
            or "passwd" in c["tool_arguments"].lower()
            or "passwd" in c["id"].lower()
            or "passwd" in (c.get("cwe") or "").lower()
        )
        assert matched, f"Record {c['id']} did not match search query 'passwd'"

    # 2. Search with quotes / SQL injection fragment
    res_sqli = client.get("/api/test-cases?search=' OR 1=1&limit=20")
    assert res_sqli.status_code == 200
    # Parameterized query should execute cleanly without SQL syntax error
    assert "cases" in res_sqli.json()

    # 3. Search by CWE ID
    res_cwe = client.get("/api/test-cases?search=CWE-78&limit=20")
    assert res_cwe.status_code == 200
    data_cwe = res_cwe.json()
    assert len(data_cwe["cases"]) > 0
    for c in data_cwe["cases"]:
        matched = (
            "cwe-78" in (c.get("cwe") or "").lower()
            or "cwe-78" in c["context"].lower()
            or "cwe-78" in c["tool_arguments"].lower()
            or "cwe-78" in c["id"].lower()
        )
        assert matched


def test_api_test_cases_sorting(client):
    """Verify dynamic server-side column sorting and whitelist fallback (ISSUE-008)."""
    # 1. Sort by id ASC vs DESC
    res_asc = client.get("/api/test-cases?sort_by=id&sort_order=asc&limit=10")
    res_desc = client.get("/api/test-cases?sort_by=id&sort_order=desc&limit=10")
    assert res_asc.status_code == 200
    assert res_desc.status_code == 200
    cases_asc = res_asc.json()["cases"]
    cases_desc = res_desc.json()["cases"]

    assert cases_asc[0]["id"] < cases_desc[0]["id"]

    # 2. Sort by threat_domain
    res_domain = client.get("/api/test-cases?sort_by=threat_domain&sort_order=asc&limit=20")
    assert res_domain.status_code == 200
    domains = [c["threat_domain"] for c in res_domain.json()["cases"]]
    assert domains == sorted(domains)

    # 3. Whitelist fallback: unwhitelisted column should safely fallback to id ASC
    res_invalid = client.get("/api/test-cases?sort_by=NON_EXISTENT_COL;DROP TABLE&sort_order=asc&limit=10")
    assert res_invalid.status_code == 200
    cases_invalid = res_invalid.json()["cases"]
    assert [c["id"] for c in cases_invalid] == [c["id"] for c in cases_asc]



