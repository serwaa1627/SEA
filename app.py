from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from flask_bcrypt import Bcrypt
from models import db, User, Ticket 
import random

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db.init_app(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    confirm_password = PasswordField(
            'Confirm Password',
            validators=[
                InputRequired(),
                EqualTo('password', message='Passwords must match')
            ],
            render_kw={"placeholder": "Confirm Password"}
        )
    
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            flash('Username already exists. Please choose a different one or log in.', 'danger')
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    """Form for updating user passwords securely."""
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm New Password", validators=[
        DataRequired(), EqualTo("new_password", message="Passwords must match")
    ])
    submit = SubmitField("Update Password")

def bulk_seed():
    # Creating users
    if User.query.count() == 0:
        admin = User(username='admin', password=bcrypt.generate_password_hash('admin123').decode('utf-8'), role='admin')
        users = [
                User(
                    username=f"user{i}",
                    password=bcrypt.generate_password_hash(f"password{i}"),
                    role="user"
                )
                for i in range(1, 11)
            ]
        db.session.bulk_save_objects(users)        
        db.session.add(admin)
        db.session.commit()

    users = User.query.all()

    # Creating tickets
    priorities = ["High", "Medium", "Low"]
    statuses = ["Open", "In Progress", "Resolved"]
    tickets = [
        Ticket(
            title=f"Sample Ticket {i}",
            description=f"This is the description for ticket {i}.",
            priority=random.choice(priorities),
            status=random.choice(statuses),
            user_id=random.choice(users).id
        )
        for i in range(1, 11)
    ]
    db.session.bulk_save_objects(tickets)
    db.session.commit()

@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    query = Ticket.query.filter_by(is_deleted=False)
    if not current_user.is_admin():
        query = query.filter_by(user_id=current_user.id)

    status = request.args.get('status')
    priority = request.args.get('priority')

    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)

    tickets = query.all()
    return render_template('dashboard.html', tickets=tickets)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user or not bcrypt.check_password_hash(user.password, form.password.data):
            flash('Invalid username or password. Please try again.', 'danger')
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/login-success')
@login_required
def loginSuccess():
    return render_template('login-success.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/new_ticket', methods=['GET', 'POST'])
@login_required
def new_ticket():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']

        new_ticket = Ticket(title=title, description=description, priority=priority, user_id=current_user.id)
        db.session.add(new_ticket)
        db.session.commit()

        flash('Ticket created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('new_ticket.html')


@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)

    # Ensure only the owner or admin can edit
    if not (current_user.is_admin() or ticket.user_id == current_user.id):
        flash('Unauthorised access.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ticket.title = request.form['title']
        ticket.description = request.form['description']
        # Only allow admins to update status
        if current_user.is_admin():
            ticket.status = request.form.get('status', ticket.status)

        db.session.commit()
        flash('Ticket updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_ticket.html', ticket=ticket)

@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    """Allows users to delete their own tickets and admins to delete any ticket"""
    ticket = Ticket.query.get_or_404(ticket_id)

    if current_user.is_admin() or ticket.user_id == current_user.id:
        ticket.is_deleted = True  # Soft delete so moderation and audits can still take place
        db.session.commit()
        flash("Ticket successfully deleted!", "success")
    else:
        flash("You do not have permission to delete this ticket.", "danger")

    return redirect(url_for('dashboard'))

@app.route('/account_settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash("Incorrect current password.", "danger")
            return redirect(url_for("account_settings"))

        current_user.set_password(form.new_password.data)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("account_settings"))
    return render_template("account_settings.html", form=form, user=current_user)

@app.route('/view_ticket/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if not (current_user.is_admin() or ticket.user_id == current_user.id):
        flash('Unauthorised access.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('view_ticket.html', ticket=ticket)

if __name__ == "__main__":
    with app.app_context():
        # db.drop_all()
        db.create_all()
        if User.query.count() == 0 and Ticket.query.count() == 0:
            bulk_seed()
    app.run(debug=True)