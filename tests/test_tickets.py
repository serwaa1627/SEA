import re

def register_and_login(client, username="user1", password="password"):
    client.post("/register", data={
        "username": username,
        "password": password,
        "confirm_password": password
    }, follow_redirects=True)
    client.post("/login", data={
        "username": username,
        "password": password
    }, follow_redirects=True)

def create_ticket(client, title="Test Ticket", description="Test Description", priority="High"):
    return client.post("/new_ticket", data={
        "title": title,
        "description": description,
        "priority": priority
    }, follow_redirects=True)

def test_ticket_creation_and_dashboard_listing(client):
    register_and_login(client)
    response = create_ticket(client, "My Ticket", "Some details", "Medium")
    assert b"My Ticket" in response.data
    assert b"Ticket created successfully!" in response.data

    dashboard = client.get("/", follow_redirects=True)
    assert b"My Ticket" in dashboard.data
    assert b"Medium" in dashboard.data

def test_ticket_view_page(client):
    register_and_login(client)
    create_ticket(client, "Viewable Ticket", "See this ticket", "Low")
    dashboard = client.get("/", follow_redirects=True)

    match = re.search(rb'/view_ticket/(\d+)', dashboard.data)
    assert match
    ticket_id = match.group(1).decode()
    response = client.get(f"/view_ticket/{ticket_id}")
    assert b"View Ticket" in response.data
    assert b"Viewable Ticket" in response.data
    assert b"See this ticket" in response.data

def test_ticket_edit(client):
    register_and_login(client)
    create_ticket(client, "Edit Ticket", "Edit this", "High")
    dashboard = client.get("/", follow_redirects=True)
    match = re.search(rb'/edit_ticket/(\d+)', dashboard.data)
    assert match
    ticket_id = match.group(1).decode()

    response = client.post(f"/edit_ticket/{ticket_id}", data={
        "title": "Edited Ticket",
        "description": "Edited description",
        "status": "In Progress"
    }, follow_redirects=True)
    assert b"Edited Ticket" in response.data or b"Dashboard" in response.data

    dashboard = client.get("/", follow_redirects=True)
    assert b"Edited Ticket" in dashboard.data

def test_ticket_delete(client):
    register_and_login(client)
    create_ticket(client, "Delete Ticket", "To be deleted", "Low")
    dashboard = client.get("/", follow_redirects=True)
    match = re.search(rb'/delete_ticket/(\d+)', dashboard.data)
    assert match
    ticket_id = match.group(1).decode()

    response = client.post(f"/delete_ticket/{ticket_id}", follow_redirects=True)
    assert b"Delete Ticket" not in response.data

    dashboard = client.get("/", follow_redirects=True)
    assert b"Delete Ticket" not in dashboard.data

def test_admin_can_view_and_change_ticket_status(client):
    register_and_login(client, username="user1", password="password")
    create_ticket(client, title="Status Ticket", description="Needs status change", priority="High")
    dashboard = client.get("/", follow_redirects=True)
    match = re.search(rb'/edit_ticket/(\d+)', dashboard.data)
    assert match
    ticket_id = match.group(1).decode()
    client.get("/logout", follow_redirects=True)

    register_and_login(client, username="admin", password="password")
    from models import User, db
    with client.application.app_context():
        admin_user = User.query.filter_by(username="admin").first()
        admin_user.role = "admin"
        db.session.commit()

    client.post("/login", data={"username": "admin", "password": "password"}, follow_redirects=True)
    response = client.post(
        f"/edit_ticket/{ticket_id}",
        data={
            "title": "Status Ticket",
            "description": "Needs status change",
            "status": "Resolved"
        },
        follow_redirects=True
    )
    assert b"Resolved" in response.data or b"Ticket updated" in response.data

    dashboard = client.get("/", follow_redirects=True)
    assert b"Resolved" in dashboard.data