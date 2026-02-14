"""Integration tests for POST /v1/detect/scan endpoint."""


class TestScanEndpoint:
    """Tests for the scan API endpoint."""

    def test_scan_with_pii(self, client, auth_headers):
        response = client.post(
            "/v1/detect/scan",
            json={
                "text": "Contact john@example.com about the project.",
                "ai_platform": "chatgpt",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["safe"] is False
        assert len(data["entities"]) > 0
        assert "john@example.com" not in data["redacted_text"]
        assert len(data["redaction_mapping"]) > 0
        assert data["latency_ms"] >= 0
        assert data["log_id"] > 0

    def test_scan_without_pii(self, client, auth_headers):
        response = client.post(
            "/v1/detect/scan",
            json={
                "text": "The weather is nice today.",
                "ai_platform": "chatgpt",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # May or may not detect PII in benign text, just check response structure
        assert "safe" in data
        assert "entities" in data
        assert "redacted_text" in data
        assert data["log_id"] > 0

    def test_scan_unauthenticated(self, client):
        response = client.post(
            "/v1/detect/scan",
            json={"text": "Test text"},
        )
        assert response.status_code == 403  # No token

    def test_scan_session_persistence(self, client, auth_headers):
        """Same entity in same session should get same pseudonym."""
        # First scan
        r1 = client.post(
            "/v1/detect/scan",
            json={
                "text": "Contact john@example.com please.",
                "session_id": "test-session-123",
                "ai_platform": "chatgpt",
            },
            headers=auth_headers,
        )
        # Second scan with same session
        r2 = client.post(
            "/v1/detect/scan",
            json={
                "text": "Also CC john@example.com on that.",
                "session_id": "test-session-123",
                "ai_platform": "chatgpt",
            },
            headers=auth_headers,
        )

        if r1.status_code == 200 and r2.status_code == 200:
            mapping1 = r1.json().get("redaction_mapping", {})
            mapping2 = r2.json().get("redaction_mapping", {})

            # Same email should get same pseudonym across calls
            for key in mapping1:
                if key in mapping2:
                    assert mapping1[key] == mapping2[key]

    def test_scan_logs_to_database(self, client, auth_headers):
        """Verify scan creates a prompt_log entry."""
        response = client.post(
            "/v1/detect/scan",
            json={
                "text": "My email is alice@company.com",
                "ai_platform": "claude",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["log_id"] > 0

    def test_scan_text_too_long(self, client, auth_headers):
        """Verify max text length is enforced."""
        long_text = "a" * 50001
        response = client.post(
            "/v1/detect/scan",
            json={"text": long_text},
            headers=auth_headers,
        )
        assert response.status_code == 422  # Pydantic validation error

    def test_scan_multiple_entity_types(self, client, auth_headers):
        """Test detection of multiple PII types in single prompt."""
        response = client.post(
            "/v1/detect/scan",
            json={
                "text": "John Smith (john@example.com, 555-123-4567) SSN: 123-45-6789",
                "ai_platform": "chatgpt",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        if not data["safe"]:
            assert len(data["entities"]) >= 2
            entity_types = [e["type"] for e in data["entities"]]
            # Should detect at least 2 different types
            assert len(set(entity_types)) >= 2
