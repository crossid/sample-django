# Readme

First, install dependencies

```bash
python3  -m venv env
source ./env/bin/activate
pip3 install -r requirements.txt
```


Then you can run the server with

```bash
CLIENT_ID=<client_id>\
CLIENT_SECRET=<client_secret> \
REDIRECT_URI=https://localhost/callback \
ISSUER_BASE_URL=https://<tenant_id>.crossid.io/oauth2/ \
django-admin runserver --pythonpath=. --settings=app
```


## Deploying on Digital Ocean

Click this button to deploy the app to the DigitalOcean App Platform.

[![Deploy to DigitalOcean](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/crossid/sample-django/tree/main)

Fill the needed enviroment variables: CLIENT_ID, CLIENT_SECRET, ISSUER_BASE_URL

or if you have `doctl` installed then run:

`doctl apps create --spec .do/app.yaml`

Then go to the DigitalOcean admin screen and update the enviroment variables: Fill the needed enviroment variables: CLIENT_ID, CLIENT_SECRET, ISSUER_BASE_URL

Take note of the public url of your new app.

Finally, go to CrossID admin screen, edit the oauth2 client, and add the correct callback url: {public_url}/callback and to post logout redirect uris: {public_url}
