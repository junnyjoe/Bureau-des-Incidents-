class ResponsePolicyMiddleware:
    """A small, explicit policy for the server-rendered starter."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # The course UI has no inline scripts/styles or third-party assets.
        # Django admin has its own assets/inline behavior; review its CSP separately.
        if not request.path.startswith("/admin/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'"
            )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Never let a shared cache retain private/authentication pages.
        if request.user.is_authenticated or request.path.startswith("/accounts/"):
            response.headers["Cache-Control"] = "no-store, private"
        return response
