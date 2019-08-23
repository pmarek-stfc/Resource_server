from .authentication import Authenticate
def resource_server(request):
    """
        The method receives request from Keycloak django application and processes the token.
        After validation of the token, returns the response containing user's details.
        If the user's not authorized, the response is containing appropriate staus code
        and the error.

    :param request:
    :return: response
    """
    # extract headers from the request
    data = request.headers

    # extract access token from headers
    token = data['Authorization'].strip('Bearer').strip()
    return Authenticate.server(token)