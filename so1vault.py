import argparse, secrets, os, stat, re, sqlite3
from flask import Flask, redirect, url_for, render_template, request, session
from argon2 import PasswordHasher
from datetime import timedelta, datetime
from cryptography.fernet import Fernet
pass_hash = PasswordHasher(hash_len = 128, salt_len = 16)

if not os.path.exists('passwords.db'):
    connection = sqlite3.connect('passwords.db', check_same_thread=False)
    os.chmod('passwords.db', stat.S_IRWXU)
    cursor = connection.cursor()
    cursor.execute('create table passwords (id integer primary key autoincrement, email text, password_hash text, url text, last_modified text, first_created text)')
    connection.commit()
    key = Fernet.generate_key()
    with open("secret.key", 'wb') as f:
        f.write(key)
else:
    connection = sqlite3.connect('passwords.db', check_same_thread=False)
    cursor = connection.cursor()


def load_key():
    with open("secret.key", 'rb') as f:
        return f.read()
def encrypt_data(data):
    data = data.encode()
    key = load_key()
    fernet = Fernet(key)
    return str(fernet.encrypt(data))

def authorization(password=None):
    try:
        if os.path.exists("master_key.txt"):
            with open('master_key.txt', 'r') as f:
                return f.read()
        else:
            with open('master_key.txt', 'w') as f:
                f.write(pass_hash.hash(password))
                os.chmod('master_key.txt', stat.S_IRWXU)
                return pass_hash.hash(password)
    except Exception as e:
        return f'<h1>{e}</h1>'
        connection.close()

def main():
    if not os.geteuid() == 0:
        raise Exception('must be ran as root')
        connection.close()


    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('--session-time', type=int, default=10)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()
    web_site = Flask(__name__)
    web_site.secret_key = secrets.token_hex(128)
    web_site.permanent_session_lifetime = timedelta(minutes = args.session_time)

    @web_site.route('/', methods=['GET', 'POST'])
    def home():
        session.permanent = True
        if os.path.exists('master_key.txt'):
            return redirect(url_for('login'))

        elif request.method == 'POST':
            try:
                site_password = request.form["master_password"]
                authorization(site_password)
                session['authorized'] = True
                return redirect(url_for('dashboard'))
            except Exception as e:
                return f"<h1>{e}</h1>"
                connection.close()
        return render_template("first.html")


    @web_site.route('/login/', methods=['GET', 'POST'])
    def login():
        try:
            if 'authorized' in session:
                return redirect(url_for('dashboard'))

            if os.path.exists('master_key.txt'):
                if request.method == 'GET':
                    return render_template('login.html')
                else:
                    site_password = request.form["master_password"]
                    master_password = authorization()
                    if pass_hash.verify(master_password, site_password):
                        session['authorized'] = True
                        return redirect(url_for('dashboard'))
            return redirect(url_for('home'))
        except Exception as e:
            return f'<h1>{e}</h1>'
            connection.close()

    @web_site.route('/dashboard/')
    def dashboard():
        if 'authorized' in session:
            return render_template('dashboard.html')
        return redirect(url_for('home'))


    @web_site.route('/dashboard/add/', methods=['GET', 'POST'])
    def add():
        if 'authorized' in session:
            if request.method == 'GET':
                return render_template('add.html')
            else:
                email = request.form['email']
                password = request.form['password']
                url = request.form['url']
                last_modified = datetime.now()
                first_created = datetime.now()
                cursor.execute('INSERT INTO passwords (email, password_hash, url, last_modified, first_created) VALUES (?, ?, ?, ?, ?)',(encrypt_data(email), encrypt_data(password), encrypt_data(url), str(last_modified), str(first_created)))
                connection.commit()
                return redirect(url_for('dashboard'))
        return redirect(url_for('home'))

    @web_site.errorhandler(404)
    def invalid_url(e):
        return redirect(url_for("home"))

    web_site.run(host='127.0.0.1', port=args.port, debug=args.debug, ssl_context=('cert.pem', 'key.pem'))

if __name__ == "__main__":
    try:
        main()
        connection.close()

    except KeyboardInterrupt:
        print(f'exiting..')
        connection.close()
    except Exception as e:
        print(f'error: {e}')
        connection.close()

