vcl 7.4;

###############################################################################
# Imports
###############################################################################
import std;
import directors;
import querystring;
import vsthrottle;
import chunk;
import tcp;
import shard;
import blob;
import unix;
import xkey;
import bodyaccess;
import cookie;
import header;
import vtc;         # Optional for local testing
import saintmode;  # RE-ENABLED for advanced 5xx "saint mode" recovery
import re2;        # Use the RE2 vmod for faster regex matching

###############################################################################
# Suggested varnishd runtime parameters (adjust as needed):
#
# varnishd \
#   -p workspace_client=256k \
#   -p workspace_backend=256k \
#   -p thread_pool_min=200 \
#   -p thread_pool_max=4000 \
#   -p thread_pool_timeout=300 \
#   -p thread_pools=2 \
#   -p pcre_match_limit=10000 \
#   -p pcre_match_limit_recursion=10000 \
#   -p http_resp_size=64k \
#   -p http_req_size=64k
#
# For HTTP/2 or HTTP/3, place a TLS terminator (e.g., Hitch, HAProxy, Nginx)
# in front of Varnish to handle TLS + H2/H3. Varnish will still speak HTTP/1.1
# to the backend, but you can set Alt-Svc or other hints as below.
###############################################################################

# ------------------------------------------------------------------------------
# ACLs
# ------------------------------------------------------------------------------
acl purge {
    "localhost";
    "127.0.0.1"/8;
    "192.168.1.0"/24;
    "::1"/128;
    "fe80::"/10;
}

acl trusted_networks {
    "localhost";
    "127.0.0.1"/8;
    "192.168.1.0"/24;
    "::1"/128;
    "fe80::"/10;
}

# ------------------------------------------------------------------------------
# Health Checks
# ------------------------------------------------------------------------------
probe tcp_probe {
    .window     = 10;
    .initial    = 4;
    .threshold  = 6;
    .interval   = 2s;
    .timeout    = 1s;
}

probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval          = 2s;
    .timeout           = 1s;
    .window            = 10;
    .threshold         = 6;
    .initial           = 4;
    .expected_response = 200;
    .match_pattern     = "OK";
    .threshold         = 3;
}

# ------------------------------------------------------------------------------
# Backend Configuration
# ------------------------------------------------------------------------------
backend default {
    .host = "192.168.1.50";  # Adjust for your environment
    .port = "8080";
    .first_byte_timeout     = 60s;
    .between_bytes_timeout  = 15s;
    .max_connections        = 1000;
    .probe                  = backend_probe;

    # Optimized TCP settings
    .tcp_keepalive_time   = 180;
    .tcp_keepalive_probes = 4;
    .tcp_keepalive_intvl  = 20;
    .connect_timeout      = 1s;

    # Connection pooling
    .min_pool_size = 50;
    .max_pool_size = 500;
    .pool_timeout  = 30s;
}

# ------------------------------------------------------------------------------
# Directors / Pools / Rate Limiting
# ------------------------------------------------------------------------------
sub vcl_init {
    # Sharding Director (supports advanced load balancing)
    new cluster = shard.director({
        .backend           = default;
        .by_hash           = true;  # consistent hashing
        .warmup            = 15s;
        .rampup            = 45s;
        .retries           = 5;
        .skip_gone         = true;
        .healthy_threshold = 2;
    });

    # Rate limiting for general traffic
    new throttle = vsthrottle.rate_limit(
        .max_rate    = 250,   # base rate
        .duration    = 60,    # 60s window
        .burst       = 75,    # extra capacity
        .penalty_box = 300    # time in penalty box
    );

    # TCP Pool for advanced connection reuse
    new pool = tcp.pool(
        .max_connections = 2500,
        .min_connections = 200,
        .idle_timeout    = 180,
        .connect_timeout = 0.5
    );

    return (ok);
}

# ------------------------------------------------------------------------------
# Security Headers (delivered in vcl_deliver)
# ------------------------------------------------------------------------------
sub add_security_headers {
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload";
    set resp.http.X-Content-Type-Options    = "nosniff";
    set resp.http.X-XSS-Protection          = "1; mode=block";
    set resp.http.Referrer-Policy           = "strict-origin-when-cross-origin";
    set resp.http.Permissions-Policy        = "interest-cohort=()";
    set resp.http.X-Frame-Options           = "SAMEORIGIN";

    # NEW: More modern CSP with 'strict-dynamic' (as an example).
    #      Adjust to your actual requirements or keep minimal if uncertain.
    if (re2.match(req.url, "\\.(html|php)$", "")) {
        set resp.http.Content-Security-Policy =
            "default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; script-src 'strict-dynamic' 'unsafe-inline' https:; object-src 'none';";
    }

    # NEW: DNS Prefetch Control (example)
    set resp.http.X-DNS-Prefetch-Control = "off";
}

# ------------------------------------------------------------------------------
# Saint Mode for Backend Errors (improves resilience)
# ------------------------------------------------------------------------------
sub vcl_backend_error {
    if (beresp.status >= 500) {
        std.log("Saint mode triggered for: " + bereq.url);
        # Mark this object as "sick" for a short period to avoid repeated fetches
        saintmode.record(30s);
        return (retry);
    }
}

# ------------------------------------------------------------------------------
# WordPress / WooCommerce Helper Routines
# ------------------------------------------------------------------------------
sub is_logged_in {
    if (req.http.Cookie) {
        # RE2 single-pattern approach for typical WP/Woo "logged-in" cookies
        if (re2.find(req.http.Cookie,
            "(wordpress_logged_in|wordpress_sec_|wp_woocommerce_session|woocommerce_items_in_cart|woocommerce_cart_hash)")) {
            return(true);
        }
    }
    return(false);
}

sub is_admin_area {
    if (re2.find(req.url, "(wp-admin|wp-login\\.php)")) {
        return(true);
    }
    return(false);
}

sub is_wp_rest_api {
    if (re2.match(req.url, "^/wp-json/", "")) {
        return(true);
    }
    return(false);
}

# NEW: WP Preview detection
sub is_wp_preview {
    # WordPress previews often have ?preview=true or ?preview_id=
    if (re2.find(req.url, "(preview=true|preview_id=)")) {
        return(true);
    }
    return(false);
}

# NEW: Detect if WooCommerce cart cookie is empty
sub cart_cookie_empty {
    if (req.http.Cookie) {
        if (!re2.find(req.http.Cookie, "woocommerce_items_in_cart")) {
            return(true);
        }
        if (re2.find(req.http.Cookie, "woocommerce_items_in_cart=0")) {
            return(true);
        }
    }
    return(false);
}

# NEW: Helper to detect wc-ajax for cart fragments (potential ESI usage)
sub is_woocommerce_ajax {
    if (re2.find(req.url, "wc-ajax=")) {
        return(true);
    }
    return(false);
}

# ------------------------------------------------------------------------------
# Device Detection (Using re2)
# ------------------------------------------------------------------------------
sub detect_device {
    if (req.http.User-Agent) {
        if (re2.find(req.http.User-Agent,
            "(?i)(mobile|android|iphone|ipod|tablet|up\\.browser|up\\.link|mmp|symbian|smartphone|midp|wap|phone|windows ce)")) {
            set req.http.X-Device-Type = "mobile";
        } else if (re2.find(req.http.User-Agent, "(?i)(ipad|playbook|silk)")) {
            set req.http.X-Device-Type = "tablet";
        } else {
            set req.http.X-Device-Type = "desktop";
        }
    } else {
        set req.http.X-Device-Type = "desktop";
    }
}

# ------------------------------------------------------------------------------
# Advanced Query Parameter Stripping
# ------------------------------------------------------------------------------
sub clean_query_parameters {
    # Remove marketing/tracking parameters
    set req.url = querystring.regfilter(
        req.url,
        "^(utm_|fbclid|gclid|mc_eid|ref|cx|ie|cof|siteurl|zanpid|origin|amp)"
    );
    set req.url = regsuball(
        req.url,
        "(^|&)(_ga|_ke|mr:[A-Za-z0-9_]+|ncid|platform|spm|sp_|zan-src|mtm|trk|si)=",
        "&"
    );
    set req.url = regsub(req.url, "(\\?|&)+$", "");
}

# ------------------------------------------------------------------------------
# Remove non-essential WordPress cookies
# ------------------------------------------------------------------------------
sub remove_unnecessary_wp_cookies {
    if (req.http.Cookie) {
        # Only remove these cookies if the user is not recognized as "logged in".
        if (!is_logged_in()) {
            # Common WP settings cookies that don't affect page content
            set req.http.Cookie = regsuball(
                req.http.Cookie,
                "(^|; )wp-settings-[^=]*=[^;]+(; |$)",
                "\1"
            );
            set req.http.Cookie = regsuball(
                req.http.Cookie,
                "(^|; )wp-settings-time-[^=]*=[^;]+(; |$)",
                "\1"
            );
            set req.http.Cookie = regsuball(
                req.http.Cookie,
                "(^|; )wordpress_test_cookie=[^;]+(; |$)",
                "\1"
            );

            # Remove WordPress comment_author_* cookies if not logged in
            set req.http.Cookie = regsuball(
                req.http.Cookie,
                "(^|; )comment_author_[^=]*=[^;]+(; |$)",
                "\1"
            );
            set req.http.Cookie = regsuball(
                req.http.Cookie,
                "(^|; )comment_author_email_[^=]*=[^;]+(; |$)",
                "\1"
            );

            # NEW: Strip WooCommerce cart cookies if the cart is empty
            if (cart_cookie_empty()) {
                set req.http.Cookie = regsuball(
                    req.http.Cookie,
                    "(^|; )woocommerce_items_in_cart=[^;]+(; |$)",
                    "\1"
                );
                set req.http.Cookie = regsuball(
                    req.http.Cookie,
                    "(^|; )woocommerce_cart_hash=[^;]+(; |$)",
                    "\1"
                );
            }

            # If the cookie header is now empty or only spaces, unset it
            if (req.http.Cookie ~ "^\s*$") {
                unset req.http.Cookie;
            }
        }
    }
}

# ------------------------------------------------------------------------------
# vcl_hash
# ------------------------------------------------------------------------------
sub vcl_hash {
    # Combine URL + Host + Device-type for your hash
    hash_data(blob.encode(req.url + req.http.host + req.http.X-Device-Type, blob.BASE64));

    # If you want separate caches for HTTP vs. HTTPS
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    # Optional per-user caching (e.g., membership sites)
    if (req.http.X-User-ID) {
        hash_data(req.http.X-User-ID);
    }

    return (lookup);
}

# ------------------------------------------------------------------------------
# vcl_hit
# ------------------------------------------------------------------------------
sub vcl_hit {
    # Optional background refresh (advanced usage) - RE-ENABLED
    if (obj.ttl < 30s && obj.ttl > 0s && std.healthy(req.backend_hint)) {
        std.log("Background fetch triggered for near-expiry object: " + req.url);
        return (miss);
    }

    if (obj.ttl >= 0s) {
        return (deliver);
    }
    if (obj.ttl + obj.grace > 0s) {
        return (deliver);
    }
    return (miss);
}

# ------------------------------------------------------------------------------
# Handle WebSockets / CONNECT in vcl_pipe
# ------------------------------------------------------------------------------
sub vcl_pipe {
    if (re2.find(req.http.Upgrade, "(?i)websocket")) {
        return (pipe);
    }
    return (pipe);
}

# ------------------------------------------------------------------------------
# vcl_recv: Entry Point for Client Requests
# ------------------------------------------------------------------------------
sub vcl_recv {
    # 1) Ensure X-Forwarded-For always includes client IP
    if (!req.http.X-Forwarded-For) {
        set req.http.X-Forwarded-For = client.ip;
    } else {
        set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    }

    # NEW: If no X-Forwarded-Proto is present, infer it based on this connection (optional).
    #      Adjust if you already have a load balancer or TLS terminator handling it.
    if (!req.http.X-Forwarded-Proto) {
        if (std.port(server.ip) == 443) {
            set req.http.X-Forwarded-Proto = "https";
        } else {
            set req.http.X-Forwarded-Proto = "http";
        }
    }
    # NEW: ESI endpoints pass
    if (re2.find(req.url, "^/wp-json/wp-esi-enabler/v1/(cart-fragment|full-cart-fragment)")) {
        return (pass);
    }
    # 2) Socket pacing for large vs. smaller content
    if (tcp.is_idle(client.socket)) {
        if (re2.find(req.url, "\\.(mp4|mkv|iso)$")) {
            tcp.set_socket_pace(client.socket, 5MB);
        } else {
            tcp.set_socket_pace(client.socket, 1MB);
        }
    }

    # 3) Normalize host (remove any port suffix)
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    # 4) Device detection
    call detect_device;

    # 5) Clean up query parameters
    call clean_query_parameters;

    # 6) Remove URL fragment, then sort query
    set req.url = std.querysort(regsub(req.url, "#.*$", ""));

    # 7) PURGE checks
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(403, "Forbidden"));
        }
        # xkey-based purge if header present
        if (req.http.xkey) {
            set req.http.n_gone = xkey.purge(req.http.xkey);
            return (synth(200, "Purged " + req.http.n_gone + " objects"));
        } else {
            ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
            return (synth(200, "Banned via ban-lurker"));
        }
    }

    # 8) Pass non-idempotent methods
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # 9) Basic known-bot checks
    if (re2.find(req.http.User-Agent, "(?i)(ahrefs|semrush|mj12bot|dotbot|petalbot)")) {
        if (vsthrottle.is_denied("bot:" + client.ip, 20, 60s)) {
            return (synth(429, "Bot traffic blocked"));
        }
    }

    # 10) Generic bot/crawler checks (excludes major search engines)
    if (re2.find(req.http.User-Agent, "(?i)(bot|crawl|slurp|spider)")) {
        if (!re2.find(req.http.User-Agent, "(?i)(googlebot|bingbot|yandex|baiduspider)")) {
            # DNS-based verification example (could be expanded)
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$", "\\4.\\3.\\2.\\1.in-addr.arpa"))) {
                if (vsthrottle.is_denied("bot:" + client.ip, 50, 60s)) {
                    unix.syslog(unix.LOG_WARNING, "Generic Bot banned: " + client.ip);
                    return (synth(403, "Bot Access Denied"));
                }
            }
        }
    }

    # 11) Rate-limiting for general traffic
    if (vsthrottle.is_denied(client.ip, 250, 60s)) {
        # Second-level threshold
        if (vsthrottle.is_denied(client.ip, 350, 300s)) {
            unix.syslog(unix.LOG_WARNING, "Heavy rate-limit exceeded: " + client.ip);
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # NEW: If there's an Authorization header, we pass (for WP Application Passwords or Basic Auth).
    if (req.http.Authorization) {
        return (pass);
    }

    # 12) WordPress & WooCommerce checks
    #     A) If WP Admin area or logged-in user => pass
    if (is_admin_area() || is_logged_in()) {
        return (pass);
    }

    #     B) If WP Preview => pass
    if (is_wp_preview()) {
        return (pass);
    }

    #     C) WooCommerce & WP special endpoints => pass
    if (is_woocommerce_ajax()) {
        return (pass);
    }
    if (re2.find(req.url, "(wp-admin|wp-login|wc-api|checkout|cart|my-account|add-to-cart|logout|lost-password)")) {
        return (pass);
    }

    #     D) WP REST API
    if (is_wp_rest_api()) {
        return (pass);
    }

    #     E) Remove non-critical WP cookies for non-logged-in users
    call remove_unnecessary_wp_cookies;

    # 13) Static file handling
    if (re2.find(req.url, "(?i)\\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\\?.*)?$")) {
        unset req.http.Cookie;
        set req.http.X-Static = "1";

        # OPTIONAL: If you want to ignore query strings on static (like ?ver=123)
        # set req.url = regsub(req.url, "\\?.*$", "");

        return (hash);
    }

    # 14) Grace for dynamic content
    if (req.http.X-Grace) {
        set req.grace = std.duration(req.http.X-Grace, 24h);
    } else {
        # 2h base + random up to 1h
        set req.grace = 2h + std.random(30m, 3600);
    }

    # 15) Handle Range requests by passing (can be replaced by chunk logic)
    if (req.http.Range) {
        return (pass);
    }

    # 16) Handle WP Heartbeat (Ajax)
    if (re2.find(req.url, "wp-admin/admin-ajax\\.php") && req.http.body ~ "action=heartbeat") {
        return (pass);
    }

    # NEW (optional): ESI approach for cart fragments or partial placeholders
    # if (re2.find(req.url, "cart-fragment-esi")) {
    #     return (pass);
    # }

    return (hash);
}

# ------------------------------------------------------------------------------
# vcl_backend_fetch
# ------------------------------------------------------------------------------
sub vcl_backend_fetch {
    # (A) Ensure we get compressed data from the backend if available
    if (bereq.http.Accept-Encoding) {
        set bereq.http.Accept-Encoding = "gzip, deflate, br";
    } else {
        set bereq.http.Accept-Encoding = "gzip, deflate";
    }

    # (B) Background fetch for near-expiry content
    if (bereq.uncacheable == false && bereq.ttl < 120s && bereq.ttl > 0s) {
        set bereq.do_stream = false;
        set bereq.background_fetch = true;
    }

    return (fetch);
}

# ------------------------------------------------------------------------------
# vcl_backend_response
# ------------------------------------------------------------------------------
sub vcl_backend_response {
    # 1) Saint Mode for 5xx
    if (beresp.status >= 500) {
        set beresp.ttl   = 1s;
        set beresp.grace = 5s;
        return (abandon);
    }

    # 2) ESI detection
    if (re2.find(beresp.http.Surrogate-Control, "ESI/1\\.0")) {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi    = true;
        set beresp.do_stream = true;
        if (re2.find(beresp.http.Content-Type, "(?i)text")) {
            set beresp.do_gzip = true;
        }
    }

    # Surrogate key purging: X-Purge-Keys -> xkey
    if (beresp.http.X-Purge-Keys) {
        xkey.add(beresp.http.X-Purge-Keys);
    }

    # 3) Detect static
    if (
        bereq.http.X-Static == "1" ||
        re2.find(bereq.url, "\\.(?i)(css|js|jpg|jpeg|png|gif|ico|woff2)$")
    ) {
        set beresp.ttl   = 365d;
        set beresp.grace = 7d;
        set beresp.keep  = 7d;

        set beresp.http.Cache-Control =
            "public, max-age=31536000, immutable, stale-while-revalidate=86400, stale-if-error=86400";
        set beresp.http.Vary = "Accept-Encoding";

        # Stream large files
        if (std.integer(beresp.http.Content-Length, 0) > 5242880) {
            set beresp.do_stream = true;
            set beresp.http.X-Stream = "true";
        }

        # Potential GZIP for text-based assets
        if (re2.find(beresp.http.Content-Type, "(?i)(text|application/(javascript|json|xml))")) {
            if (std.integer(beresp.http.Content-Length, 0) > 860) {
                set beresp.do_gzip = true;
            }
        }

    } else {
        # 4) Dynamic content default TTL
        if (!beresp.http.Cache-Control) {
            set beresp.ttl   = 4h;
            set beresp.grace = 24h;
            set beresp.keep  = 24h;
            set beresp.http.Cache-Control =
                "public, max-age=14400, stale-while-revalidate=3600, stale-if-error=43200";
        }

        # OPTIONAL: If this is a feed (e.g. /feed/ or ?feed=)
        if (re2.find(bereq.url, "(^|/)feed/") || re2.find(bereq.url, "(\\?|&)feed=")) {
            set beresp.ttl   = 10m;
            set beresp.grace = 1h;
        }

        # NEW: Ensure we Vary by device type for dynamic objects
        if (beresp.http.Vary) {
            if (! re2.find(beresp.http.Vary, "X-Device-Type")) {
                set beresp.http.Vary = beresp.http.Vary ", X-Device-Type";
            }
        } else {
            set beresp.http.Vary = "X-Device-Type";
        }
    }

    # NEW: Negative caching for 404/410
    if (beresp.status == 404 || beresp.status == 410) {
        set beresp.ttl   = 30s;
        set beresp.grace = 5m;
    }

    # 5) Body compression for text/JSON/JS
    if (re2.find(beresp.http.Content-Type, "(?i)(text|application/json|application/javascript)")) {
        if (std.integer(beresp.http.Content-Length, 0) < 860) {
            set beresp.do_gzip = false;
        } else {
            set beresp.do_gzip = true;
            # For large dynamic content, stream as well
            if (std.integer(beresp.http.Content-Length, 0) > 102400) {
                set beresp.do_stream = true;
            }
        }
    }

    # OPTIONAL: Use chunk vmod for partial caching / slicing large range requests
    # if (bereq.http.Range) {
    #     chunk.slice(beresp, 1MB);
    # }

    # NEW: Optionally generate ETag if none is provided
    if (!beresp.http.ETag &&
        re2.find(beresp.http.Content-Type, "(?i)(text|application/json|application/javascript)")) {
        set beresp.http.ETag =
            "W/\"" + std.digest(beresp.http.Content-Length + bereq.url, "sha256") + "\"";
    }

    # (Optional) Generate a Last-Modified header if none is present
    # if (!beresp.http.Last-Modified &&
    #     re2.find(beresp.http.Content-Type, "(?i)(text|application/json|application/javascript)")) {
    #     set beresp.http.Last-Modified = std.tolower(std.timestamp());
    # }
}

# ------------------------------------------------------------------------------
# vcl_deliver
# ------------------------------------------------------------------------------
sub vcl_deliver {
    # 1) Remove sensitive headers
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    # 2) Add global security headers
    call add_security_headers;

    # HTTP/2 / HTTP/3 advertisement
    set resp.http.Alt-Svc = "h3=\":443\"; ma=86400, h3-29=\":443\"; ma=86400";

    # Example: Preload critical assets (HTTP/2+ approach)
    # if (req.url == "/some-page") {
    #     set resp.http.Link = "</static/app.css>; rel=preload; as=style, </static/app.js>; rel=preload; as=script";
    # }

    # 3) Debug info if client is in trusted network
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache      = (obj.hits > 0) ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By  = server.hostname;
        set resp.http.X-Pool       = req.backend_hint;
        set resp.http.X-Grace      = req.grace;

        if (resp.http.X-Stream) {
            set resp.http.X-Stream-Size = beresp.http.Content-Length;
        }
        if (obj.hits > 0) {
            set resp.http.X-Age = obj.age;
        }
    }

    # Show user ID if your application passes X-User-ID
    if (req.http.X-User-ID) {
        set resp.http.X-User-Cache-ID = req.http.X-User-ID;
    }
}

# ------------------------------------------------------------------------------
# vcl_synth
# ------------------------------------------------------------------------------
sub vcl_synth {
    # 301 redirect if status 750
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + req.url;
        return (deliver);
    }

    # Rate-limited or custom error response
    if (resp.status == 429) {
        set resp.http.Retry-After  = "60";
        set resp.http.Content-Type = "application/json";
        synthetic({"{\"error\": \"Too many requests\", \"retry_after\": 60}"});
    }

    # Add security headers even on error
    call add_security_headers;

    return (deliver);
}

# ------------------------------------------------------------------------------
# Optional: Custom Error Page Generator
# ------------------------------------------------------------------------------
sub generate_error_page {
    # Example usage:
    # synthetic("<html><body><h1>Something went wrong!</h1></body></html>");
    # set resp.http.Content-Type = "text/html; charset=utf-8";
}
