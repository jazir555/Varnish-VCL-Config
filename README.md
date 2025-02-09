#Varnish VCL Configuration for WordPress & WooCommerce

This repository contains a custom Varnish VCL configuration designed to optimize the performance, security, and caching behavior of your WordPress site—with special consideration for WooCommerce. It leverages advanced query string filtering, dynamic cookie handling, load-balancing via directors, and custom error page generation to provide a robust caching layer in front of your application server(s).

**IMPORTANT:**

**Backends & Directors:** Replace BACKEND_SERVERS and BACKEND_DIRECTORS with your actual backend definitions and director/load-balancing configuration.
**Cookie Management:** Ensure your WordPress installation sets a user_roles cookie (using the provided PHP snippet or a similar method) and that WooCommerce cookies (such as woocommerce_items_in_cart and wp_woocommerce_session) are managed as expected.
**Testing**: Test this configuration thoroughly in a staging environment before deploying it to production.

#Features

**Load Balancing & Backend Management:**
Uses Varnish directors (round-robin in this example) to distribute traffic across multiple backend servers.

**Custom Error Pages:**
Generates user-friendly error pages with a consistent style for various HTTP error responses.
**Advanced Query String Handling:**

Normalizes URLs by sorting query parameters and removing unnecessary or tracking parameters (e.g., fbclid, gclid, utm_*).

**Cookie & Session Optimization:**
Strips unwanted cookies, backs up cookies when needed, and extracts user roles for tailored caching behavior.

**Security & Rate Limiting:**
Implements ACLs for purge requests, denies access from non-authorized IP addresses, and includes basic bot filtering and request throttling.

**Caching Optimizations:**
Applies tailored TTLs and grace periods based on content type, logged-in status, and backend responses. Static assets are cached for up to 7 days, while dynamic content receives shorter TTLs.

**ESI Support & Streaming:**
Supports Edge Side Includes (ESI) for dynamic content assembly and enables streaming for large content responses.

**Header Normalization:**
Adjusts security headers (HSTS, X-Content-Type-Options, etc.) and strips server-identifying headers before delivery.

#Prerequisites

**Varnish Version:**

This configuration is written for Varnish VCL 4.1. Ensure you are running Varnish 4.1 or newer.

**Required VMODs:**

querystring – for advanced query string filtering.
vsthrottle – for request rate limiting.

**Backend Web Server(s):**
One or more backend servers hosting your WordPress/WooCommerce installation.

**WordPress Configuration:**
Implement the necessary PHP snippet (or similar) to set the user_roles cookie, which this VCL uses to determine caching behavior for logged-in versus guest users.

#Installation

**Customize the Configuration:**

**Backend & Director Settings**:

Edit the VCL file (e.g., default.vcl) and replace the placeholders BACKEND_SERVERS and BACKEND_DIRECTORS with your actual backend definitions and load-balancing configurations.

**ACLs & Trusted Networks**:
Update the purge and trusted_networks ACLs to include your IP addresses or network ranges as needed.

#Configuration Overview

**ACLs & Variables**:

Defines ACLs for purge requests and trusted networks.

#Custom Error Page (generate_error_page):
Produces styled HTML error pages based on the response status.

**Backend Definitions:**
Configures connection settings (host, port, timeouts, health probes) for your backend servers.

**VCL Initialization (vcl_init):**
Initializes load-balancing directors and loads additional VCL files (e.g., for blacklists or device detection).

**Hash Function (vcl_hash):**
Normalizes URLs by stripping query strings, handling cookies, and ensuring consistent cache keys.

**Client Request Processing (vcl_recv):**
Handles URL normalization, purge requests, HTTPS redirection, security checks, cookie management, query string filtering, and request method handling.

**Backend Response Processing (vcl_backend_response):**
Adjusts caching parameters, enables streaming for large objects, applies security headers, and modifies cache-control behavior.

**Delivery (vcl_deliver):**
Sets final response headers (e.g., HSTS, cache status, debug headers for trusted networks) and cleans up sensitive server information.

**Synthetic Responses (vcl_synth):**
Manages error handling and redirections, including custom error page generation.

**Purge Handling & Pass Modes:**
Supports cache purging (with ACL checks), WebSocket handling, and bypassing the cache for non-GET/HEAD methods or authorized requests.

#Testing & Validation

**Staging Environment:**
Always test in a staging environment before deploying to production. Verify that all backend interactions, cache hit/miss behavior, and error handling work as expected.

**Log Monitoring:**
Monitor Varnish logs to track cache performance, backend errors, and security events.

**Cookie & Session Checks:**
Ensure that the user_roles cookie is correctly set and that other cookies (especially those from WooCommerce) are properly handled in both logged-in and guest scenarios.

**Contributing**
Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request if you have suggestions or improvements.








-----------------------------

-----------------------------
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
