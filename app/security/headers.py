"""Security headers applied to every response.

Registered once, in the app factory, via Flask's `after_request` hook --
so every route gets these headers for free, including ones a future
contributor adds without knowing this file exists. That "opt-out by
default is safe" property is the whole point: a header allowlist someone
has to remember to add per-route gets forgotten; an after_request hook
does not.
"""

from flask import Response


def apply_security_headers(response: Response) -> Response:
    # Stops the browser from guessing (sniffing) a response's MIME type
    # from its content instead of trusting the declared Content-Type --
    # sniffing is how a text file can end up executed as script/HTML in
    # some legacy attack chains.
    response.headers["X-Content-Type-Options"] = "nosniff"

    # This is a JSON API, not something meant to be embedded in another
    # site's <iframe>. DENY blocks all framing, closing off clickjacking
    # attacks that rely on overlaying invisible frames of this app.
    response.headers["X-Frame-Options"] = "DENY"

    # Belt-and-suspenders alongside X-Frame-Options: modern browsers
    # honor frame-ancestors from CSP over X-Frame-Options, older ones
    # only understand the header. default-src 'none' is safe here since
    # every response is JSON, not HTML that needs to load scripts/styles.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"

    # Tells browsers to only ever reach this host over HTTPS for the next
    # year, even if a user types http:// or follows an http:// link --
    # closes the window for a downgrade/strip attack on the first
    # request. Meaningless (and not sent) over plain HTTP in dev, so
    # this is harmless to include unconditionally; a browser only acts
    # on it when it's delivered over a connection that's already HTTPS.
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Legacy header, superseded by CSP's reflected-XSS protections in
    # modern browsers, but a handful of older clients still honor it and
    # it costs nothing to set.
    response.headers["X-XSS-Protection"] = "0"

    # Don't leak this origin's URLs (which can carry sensitive path
    # segments, like a password-reset token if one were ever put in a
    # URL) to third-party sites via the Referer header on outbound links.
    response.headers["Referrer-Policy"] = "no-referrer"

    # This API isn't a webpage that needs camera/mic/geolocation -- deny
    # every browser feature by default so an XSS bug can't silently
    # request access to hardware this service has no legitimate use for.
    response.headers["Permissions-Policy"] = (
        "geolocation=(), camera=(), microphone=(), payment=()"
    )

    return response
