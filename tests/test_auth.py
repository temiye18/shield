"""Tests for authentication endpoints."""


class TestRegistration:
    """Tests for POST /v1/auth/register."""

    def test_register_success(self, client):
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "securepassword123",
                "full_name": "New User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["full_name"] == "New User"
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_register_with_organization(self, client):
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "admin@company.com",
                "password": "securepassword123",
                "full_name": "Admin User",
                "organization_name": "My Company",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["organization_id"] is not None
        assert "access_token" in data

    def test_register_duplicate_email(self, client):
        # First registration
        client.post(
            "/v1/auth/register",
            json={
                "email": "dup@example.com",
                "password": "securepassword123",
            },
        )
        # Duplicate
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "dup@example.com",
                "password": "securepassword123",
            },
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_register_weak_password(self, client):
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "weak@example.com",
                "password": "short",
            },
        )
        assert response.status_code == 422  # Validation error

    def test_register_invalid_email(self, client):
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "not-an-email",
                "password": "securepassword123",
            },
        )
        assert response.status_code == 422


class TestLogin:
    """Tests for POST /v1/auth/login."""

    def test_login_success(self, client):
        # Register first
        client.post(
            "/v1/auth/register",
            json={
                "email": "login@example.com",
                "password": "securepassword123",
                "full_name": "Login User",
            },
        )
        # Login
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "login@example.com",
                "password": "securepassword123",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["email"] == "login@example.com"

    def test_login_wrong_password(self, client):
        client.post(
            "/v1/auth/register",
            json={
                "email": "wrongpw@example.com",
                "password": "securepassword123",
            },
        )
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "wrongpw@example.com",
                "password": "wrongpassword",
            },
        )
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client):
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "noone@example.com",
                "password": "securepassword123",
            },
        )
        assert response.status_code == 401


class TestMe:
    """Tests for GET /v1/auth/me."""

    def test_me_authenticated(self, client, auth_headers):
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["is_active"] is True

    def test_me_unauthenticated(self, client):
        response = client.get("/v1/auth/me")
        assert response.status_code == 403  # No token provided

    def test_me_invalid_token(self, client):
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": "Bearer invalid_token"},
        )
        assert response.status_code == 401
