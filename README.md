# Varnish-VCL-Config

ACLs

– Purge and trusted network ACLs are defined.

Initialization:

– A round‑robin director (“cluster”) is set up, and optional files (blacklist, device detection) are loaded.

Hashing:

– The cache key is built from (restored) cookies, the X‑Forwarded‑Proto header, host (or server IP), and a canonical URL (without query strings). Logged‑in status is also incorporated.

vcl_recv (Request Processing):

– ACME challenge requests bypass caching.

– Vulnerable headers (e.g. “proxy”) are unset.

– The client’s real IP is set (useful behind CloudFlare).

– If “no‑cache” is detected (and the client IP is in the purge ACL), the object is forced to miss.

– URL normalization and query string sorting are applied; tracking parameters are removed.

– RSS feeds and search requests bypass caching.

– Only standard HTTP methods (GET/HEAD) are cached; others are piped or passed.

– Requests from logged‑in users (detected via “wordpress_logged_in” cookie) bypass caching.

– Cookies are unset for non‑admin, non‑preview requests.

– Basic auth (or any remaining cookies) triggers a pass.

– The Accept‑Encoding header is normalized so that media files aren’t recompressed.

– For dynamic content (WordPress/WooCommerce), additional checks are performed to vary on user role and bypass caching if session or cart cookies exist.

– Finally, ESI support is enabled and the X‑Forwarded‑For header is updated.

vcl_backend_response (Backend Response Processing):

– ESI support is enabled if requested.

– The response’s Vary header is adjusted to vary only on “x‑user‑roles” when needed.

– For large objects, streaming is enabled and objects are marked uncacheable if necessary.

– For static assets (images, CSS, JS, fonts, etc.), long TTLs and public Cache‑Control headers are set, and Set‑Cookie is removed to avoid cross‑user session issues.

– A fallback TTL is applied if the object is uncacheable, and if the status indicates an error (e.g. 5xx) the response is abandoned.

– Gzip is disabled for media files but enabled (with a “ZIP” tag) for other responses and ensured for text content.

vcl_deliver (Delivery to Client):

– Browser caching headers (Expires and Cache‑Control) are set based on file type.

– Debug headers (X‑Cache, X‑Cache‑Hits) are added for monitoring.

– Unwanted headers (X‑Powered‑By, X‑Drupal‑Cache, X‑Varnish, Via, Link, X‑Generator) are removed.

– Finally, the response is delivered.

Purge, Pipe/Pass, and Optional Stale Handling:

– Purge handling is included (only allowed from specified IPs).

– Non‑standard requests are piped.

– An optional “vcl_hit” routine is provided to serve stale content when within grace.

– A custom backend error routine is included to serve a custom error page if the backend is down.
