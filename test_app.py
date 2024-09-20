import pytest
import json
from app import app, generate_key_pair  # Import the Flask app

@pytest.fixture
def client():
    app.config['TESTING'] = True  # Enable testing mode
    with app.test_client() as client:
        yield client

# Generate an initial key pair for testing
generate_key_pair()

def test_jwks_endpoint(client):
    """Test the JWKS endpoint to ensure it returns valid keys."""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "keys" in data
    assert len(data["keys"]) > 0  # Check that there is at least one key

def test_auth_endpoint(client):
    """Test the /auth endpoint for valid JWT issuance."""
    response = client.post('/auth')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data  # Ensure a token is returned

def test_auth_with_expired_key(client):
    """Test the /auth endpoint with the expired query parameter."""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data  # Ensure a token is returned even for an expired key
    
def test_auth_blackbox(client):
    """Test the /auth endpoint with no body."""
    response = client.post('/auth')  # Send a POST request with no body
    assert response.status_code == 200  # Check if the response status is 200 OK
    data = json.loads(response.data)  # Parse the JSON response
    assert "token" in data  # Ensure that a token is included in the response
    
def test_auth_no_valid_key(client):
    """Test the /auth endpoint when no valid key is available."""
    # Generate keys and then simulate expiration
    generate_key_pair()
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data  # Ensure a token is returned even for an expired key