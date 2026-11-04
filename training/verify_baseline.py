"""Instructor baseline check, intentionally separate from hardened acceptance tests."""
import os
os.environ["DJANGO_SETTINGS_MODULE"]="config.settings.security_lab"
from config.environment import prepare_environment
prepare_environment()
import django
django.setup()
from django.test import Client
client=Client(HTTP_HOST="localhost")
assert client.login(username="lab-alice",password="local-training-only"), "Seed the local training fixture first."
normal=client.get('/training/search/',{'q':'laptop'}).content.decode()
quote=client.get('/training/search/',{'q':"'"}).content.decode()
attack=client.get('/training/search/',{'q':"%' OR 1=1 -- "}).content.decode()
assert 'ALICE_SYNTHETIC_RECORD' in normal and 'BOB_PRIVATE_FIXTURE' not in normal
assert 'Training database error:' in quote
assert 'BOB_PRIVATE_FIXTURE' in attack
print('Original vulnerability reproduced: normal own result, SQL error, injected cross-owner disclosure.')
