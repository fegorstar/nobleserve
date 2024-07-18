# core/context_processors.py

def base_url(request):
    return {
        'BASE_API_URL': 'https://backendapi.noblepay.online/public/api/v1'
    }
