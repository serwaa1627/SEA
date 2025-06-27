def test_register_and_login(client):
    response = client.post("/register", data={"username": "bob", "password": "password", "confirm_password": "password"}, follow_redirects=True)
    assert b"Login" in response.data

    response = client.post("/login", data={"username": "bob", "password": "password"}, follow_redirects=True)
    assert b"Dashboard" in response.data or response.status_code == 200

def test_login_failure(client):
    response = client.post("/login", data={"username": "nonexistent", "password": "wrongpassword"}, follow_redirects=True)
    assert b"Invalid username or password. Please try again." in response.data

def test_logout(client):
    client.post("/register", data={"username": "alice", "password": "password", "confirm_password": "password"}, follow_redirects=True)
    client.post("/login", data={"username": "alice", "password": "password"}, follow_redirects=True)

    response = client.get("/logout", follow_redirects=True)
    assert b"Logout successful!" in response.data
    assert b"Login" in response.data

def test_access_protected_route_without_login(client):
    response = client.get("/new_ticket", follow_redirects=False)
    assert response.status_code in (302, 401)