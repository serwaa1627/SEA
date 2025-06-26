# SEA
# 1. Overview
It Helpdesk is a web based application built using Flask.
- User - Can create, view, and edit only their own tickets.
- Admin - can view and manage all tickets, while regular users can manage their own


# 2. Getting Started
Pre-requisites:
- Python
- pip

# To run application:
git clone (repository)
create and activate a virtual environment:
- Windows
- - python -m venv .venv
- - .venv\Scripts\activate
- macOS/Linux:
- - python3 -m venv .venv
- - source .venv/bin/activate

pip install -r requirements.txt
flask run
navigate in your browser to http://127.0.0.1:5000/

# To run tests:
ensure .venv is active - .venv\Scripts\activate
pytest

# Registration
Click register on the login page, enter your username and your password 

# Logging in
Enter username and password and click Login to access dashboard

# Dashboard
The dashboard lists your tickets (or all tickets if you are an admin).
You can filter tickets by status or priority using the filter controls at the top.

Users:
admin admin123
user1 password1
user2 password2
user3 password3
....

