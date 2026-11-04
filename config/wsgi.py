from config.environment import prepare_environment
prepare_environment()
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
