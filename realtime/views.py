# realtime/views.py

import json
from django.shortcuts import render
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# Original model‐inference logic
from .test_model2 import process_entry, session_history, save_history
# Feeder control helpers
from .feeder_service import set_current_user, get_latest_entry, get_history

def session_ui(request):
    """Renders session_ui.html for operators."""
    return render(request, 'realtime/session_ui.html')

@csrf_exempt
@require_POST
def session_api(request):
    """Original endpoint: process a single payload."""
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error':'Invalid JSON'}, status=400)
    try:
        result = process_entry(payload)
        save_history()
        return JsonResponse(result)
    except Exception as ex:
        return JsonResponse({'error': str(ex)}, status=500)

@csrf_exempt
@require_POST
def reset_sessions_api(request):
    """Original endpoint: clear all history."""
    session_history.clear()
    save_history()
    return JsonResponse({'status':'ok'})

@csrf_exempt
@require_POST
def set_user(request):
    """Switch the feeder to a new UserID."""
    try:
        data = json.loads(request.body)
        uid  = int(data.get('UserID'))
    except (ValueError,TypeError,KeyError):
        return HttpResponseBadRequest('UserID must be an integer')
    set_current_user(uid)
    return JsonResponse({'status':'ok'})

def latest_payload(request):
    """GET → most recent feeder payload + response."""
    entry = get_latest_entry() or {}
    return JsonResponse(entry, safe=False)

def history(request):
    """GET → last 15 feeder entries."""
    return JsonResponse(get_history(), safe=False)
