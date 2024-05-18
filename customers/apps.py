from django.apps import AppConfig


class CustomersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'customers'




# WHAT MAKES THE SIGNALS WORKS

    def ready(self):
        import customers.signals
