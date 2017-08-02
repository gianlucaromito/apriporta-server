import sys
sys.stdout = sys.stderr

python_home = /develop/apriporta-server/env

activate_this = python_home + '/bin/activate_this.py'
with open(activate_this) as file_:
    exec(file_.read(), dict(__file__=activate_this))

from apriporta-server import app as application