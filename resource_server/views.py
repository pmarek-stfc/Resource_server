from django.conf import settings
from django.http import HttpResponse
import requests
import jwt
import json


def resource_server(request):
    """
        Resource server receives Bearer access token and validates it.
        Firstly, it checks if the token is valid by calling Keycloak
        token introspection endpoint.
        Secondly, if the token is VALID, the server verifies its signature with
        a PUBLIC KEY provided by Keycloak.
        Once all checks are successfully passed, HTTP response is sent back
        containing decoded token information in the header along with 200 OK status
        so the user can be logged in.
        If the token is invalid, appropriate response with an error is sent back instead.

    :param request:
    :return: response
    """

    # extract headers from the request
    data = request.headers

    # extract access token from headers
    token = data['Authorization'].strip('Bearer').strip()

    payload = {
        'client_secret': settings.KEYCLOAK_CLIENT_SECRET,
        'client_id': settings.KEYCLOAK_CLIENT_ID,
        'token': token
    }
    # 1) Call Keycloak token introspection endpoint
    # 2) make the information within response from Keycloak accessible by '.json()' method
    response = requests.post('http://localhost:9000/auth/realms/master/protocol/openid-connect/token/introspect',
                             data=payload).json()

    if response['active']:
        # verify signature and store decoded token information in a variable
        decoded = jwt.decode(token, settings.KEYCLOAK_PUBLIC_KEY, algorithms='RS256', audience="account", verify=True)

        response = HttpResponse(content_type="application/json", status=200)
        # put decoded token information inside the header of the response too
        response['user_info'] = json.dumps(decoded)
        return response
    elif not response['active']:
        response = HttpResponse(content_type="application/json", status=401)
        response['error'] = 'invalid token'
        return response
    else:
        response = HttpResponse(content_type="application/json", status=400)
        response['error'] = 'invalid request'
        return response

