# realtime/urls.py

from django.urls import path
from .views import (
    session_ui,
    session_api,
    reset_sessions_api,
    set_user,
    latest_payload,
    history,
)

app_name = 'realtime'
urlpatterns = [
    # original UI + API
    path('ui/',            session_ui,          name='session_ui'),
    path('api/session/',   session_api,         name='session_api'),
    path('api/reset/',     reset_sessions_api,  name='reset_sessions_api'),

    # feeder‐control
    path('set_user/',      set_user,            name='set_user'),
    path('latest_payload/',latest_payload,      name='latest_payload'),
    path('history/',       history,             name='history'),
]
