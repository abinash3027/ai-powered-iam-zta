# realtime/apps.py

from django.apps import AppConfig

class RealtimeConfig(AppConfig):
    name = 'realtime'

    def ready(self):
        # Import here so Django is fully initialized
        from .feeder_service import start_feeder
        # Launch feeder in background
        start_feeder()
