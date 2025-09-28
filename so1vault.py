import argparse, secrets, os, stat
from flask import Flask, redirect, url_for, render_template, request, session
from argon2 import PasswordHasher
from datetime import timedelta


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('-m', '--master-pass', type=str)
    parser.add_argument('--session-time', type=int, default=15)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    pass_hash = PasswordHasher(hash_len = 128, salt_len = 16)

    try:
        if os.path.exists("master_key.txt"):
            with open('master_key.txt', 'r') as f:
                master_password = f.read()
        else:
            if args.master_pass:
                password = args.master_pass
                with open('master_key.txt', 'w') as f:
                    f.write(pass_hash.hash(password))
                os.chmod('master_key.txt', stat.S_IRWXU)
                with open('master_key.txt', 'r') as f:
                    master_password = f.read()
            else:
                print('Please enter a master password')
                password = input()
                with open('master_key.txt', 'w') as f:
                    f.write(pass_hash.hash(password))
                os.chmod('master_key.txt', stat.S_IRWXU)
                with open('master_key.txt', 'r') as f:
                    master_password = f.read()
    except Exception as e:
        print(e)





    web_site = Flask(__name__)
    web_site.secret_key = secrets.token_hex(128)
    web_site.permanent_session_lifetime = timedelta(minutes = args.session_time)



    @web_site.route('/', methods=['GET', 'POST'])
    def home():
        session.permanent = True
        if 'authorized' in session:
            return render_template('dashboard.html')

        if request.method == 'POST':
            try:
                site_password = request.form["master_password"]

                if pass_hash.verify(master_password, site_password):
                    session['authorized'] = True
                    return redirect(url_for('dashboard'))
            except Exception:
                return render_template("first_time.html")

        return render_template("first_time.html")


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

