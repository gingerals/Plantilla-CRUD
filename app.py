from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import jinja2


# Configuración del motor de plantillas Jinja2
env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de extensiones
login_manager = LoginManager(app)# Manejador de login
bcrypt = Bcrypt(app)  # Encriptación de contraseñas
db = SQLAlchemy(app)  # Base de datos

# Creación de tablas en la base de datos (si no existen)
@app.before_request
def create_tables():
    db.create_all()

# Función para cargar usuarios desde la base de datos
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



# Definición de modelo de usuario para la base de datos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean(), nullable=False, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username
    def get_id(self):
        return str(self.id)
    
# Formulario de registro de usuario
class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    email = StringField('Correo', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrarse')

# Formulario de inicio de sesión
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Autenticarse')

class adminForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    email = StringField('Correo', validators=[DataRequired(), Email()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Accion')

# Página de inicio
@app.route('/')
def home():
    return render_template('home.html')

# Página de registro de usuario
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: # Redirige a dashboard si ya está autenticado
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit(): # Registra al usuario si el formulario es válido
        email = User.query.filter_by(email=form.email.data).first()
        if email: # Si el correo electrónico ya existe
            flash('El correo electrónico ya ha sido registrado. Por favor ingrese otro correo electrónico.', 'danger')
            return render_template('register.html', form=form)
        user = User.query.filter_by(username=form.username.data).first()
        if user: # Si el nombre de usuario ya existe
            flash('El nombre de usuario ya ha sido registrado. Por favor ingrese otro nombre de usuario.', 'danger')
            return render_template('register.html', form=form)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Su cuenta ha sido creada exitosamente, ya puede iniciar sesión', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/validar_usuario', methods=['POST'])
def validar_usuario():
    username = request.form['username']
    email = request.form['email']
    # Verificar si el usuario o correo ya existen en la base de datos
    if User.query.filter_by(username=username).first() is not None:
        mensaje = 'El usuario ya existe'
    elif User.query.filter_by(email=email).first() is not None:
        mensaje = 'El correo ya está registrado'
    else:
        mensaje = ''
    return jsonify(mensaje=mensaje)

# Página de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: # Redirige a dashboard si ya está autenticado
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('No se pudo iniciar sesión, usuario o contraseña incorrectos', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated: # Redirige a dashboard si ya está autenticado
        return render_template('dashboard.html', user=current_user)
    else:
        return redirect(url_for('login'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)  # 403 significa "acceso prohibido"
    else:
        # Obtener la lista de usuarios de la base de datos
        users = User.query.all()
        form = RegistrationForm()
        return render_template("admin.html", users=users, form=form)
    

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        abort(403)  # 403 significa "acceso prohibido"
    else:
        form = RegistrationForm()

        if form.validate_on_submit(): # Registra al usuario si el formulario es válido
            email = User.query.filter_by(email=form.email.data).first()
            if email: # Si el correo electrónico ya existe
                flash('El correo electrónico ya ha sido registrado. Por favor ingrese otro correo electrónico.', 'danger')
                return redirect(url_for('admin_users'))
            user = User.query.filter_by(username=form.username.data).first()
            if user: # Si el nombre de usuario ya existe
                flash('El nombre de usuario ya ha sido registrado. Por favor ingrese otro nombre de usuario.', 'danger')
                return redirect(url_for('admin_users'))
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Su cuenta ha sido creada exitosamente, ya puede iniciar sesión', 'success')
            return redirect(url_for('admin_users'))

        return render_template("admin.html", form=form, user=user)
    
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    edit_user = {
        'id': user.id,
        'username': user.username,
        'email': user.email
    }
    form = RegistrationForm(obj=user)

    if form.validate_on_submit():
        email = User.query.filter_by(email=form.email.data).first()
        if email and email.id != user.id:
            flash('El correo electrónico ya ha sido registrado. Por favor ingrese otro correo electrónico.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        user.username = form.username.data
        user.email = form.email.data
        db.session.commit()
        flash('El usuario ha sido actualizado exitosamente.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin.html', users=User.query.all(), form=form, edit_user=edit_user)


    
@app.route('/admin/users/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)  # 403 significa "acceso prohibido"
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('El usuario ha sido eliminado', 'success')
    return redirect(url_for('admin_users'))



if __name__ == '__main__':
    app.run()