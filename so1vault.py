import argparse, secrets, os, stat, re
from flask import Flask, redirect, url_for, render_template, request, session
from argon2 import PasswordHasher
from datetime import timedelta

pass_hash = PasswordHasher(hash_len = 128, salt_len = 16)




def authorization(password=None):
    try:
        if os.path.exists("master_key.txt"):
            with open('master_key.txt', 'r') as f:
                master_password = f.read()
                return master_password
        else:
            with open('master_key.txt', 'w') as f:
                f.write(pass_hash.hash(password))
            os.chmod('master_key.txt', stat.S_IRWXU)
            with open('master_key.txt', 'r') as f:
                master_password = f.read()
                return master_password


    except Exception as e:
        return f'<h1>{e}</h1>'

def main():
    if not os.geteuid() == 0:
        raise Exception('must be ran as root')
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('-m', '--master-pass', type=str)
    parser.add_argument('--session-time', type=int, default=10)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    pass_hash = PasswordHasher(hash_len = 128, salt_len = 16)


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




    @web_site.route('/dashboard/')
    def dashboard():
        if 'authorized' in session:
            return render_template('dashboard.html')
        return redirect(url_for('home'))

    @web_site.errorhandler(404)
    def invalid_url(e):
        return redirect(url_for("home"))


    web_site.run(port=args.port, debug=args.debug)




if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f'exiting..')
    except Exception as e:
        print(f'error: {e}')

