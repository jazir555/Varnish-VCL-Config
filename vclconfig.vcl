vcl 7.4;

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
import vtc;  # Optional for local testing or advanced Varnish testcases

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
# to the backend, but you can set Alt-Svc and other hints as below.
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
    .host = "192.168.1.50";      # Adjust to your environment
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
    # NEW: Add X-Frame-Options
    set resp.http.X-Frame-Options          = "SAMEORIGIN";

    # Minimal default CSP for *.html or *.php
    if (req.url ~ "\.(html|php)$") {
        set resp.http.Content-Security-Policy =
            "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';";
    }

    # Example of setting Access-Control-Allow-Origin for static assets:
    # if (req.http.X-Static == "1") {
    #     set resp.http.Access-Control-Allow-Origin = "*";
    # }
}

# ------------------------------------------------------------------------------
# Saint Mode for Backend Errors (improves resilience)
# ------------------------------------------------------------------------------
sub vcl_backend_error {
    if (beresp.status >= 500) {
        std.log("Saint mode triggered for: " + bereq.url);
        return (retry);
    }
}

# ------------------------------------------------------------------------------
# WordPress / WooCommerce Helper Routines
# ------------------------------------------------------------------------------
sub is_logged_in {
    # Typical WP/Woo logged-in cookies
    if (req.http.Cookie) {
        if (
            req.http.Cookie ~ "wordpress_logged_in" ||
            req.http.Cookie ~ "wordpress_sec_" ||
            req.http.Cookie ~ "wp_woocommerce_session" ||
            req.http.Cookie ~ "woocommerce_items_in_cart" ||
            req.http.Cookie ~ "woocommerce_cart_hash"
        ) {
            return(true);
        }
    }
    return(false);
}

sub is_admin_area {
    if (req.url ~ "(wp-admin|wp-login\.php)") {
        return(true);
    }
    return(false);
}

sub is_wp_rest_api {
    if (req.url ~ "^/wp-json/") {
        return(true);
    }
    return(false);
}

# NEW: WP Preview detection
sub is_wp_preview {
    # WordPress previews often have `?preview=true` or `preview_id=`
    if (req.url ~ "(preview=true|preview_id=)") {
        return(true);
    }
    return(false);
}

# ------------------------------------------------------------------------------
# Device Detection
# ------------------------------------------------------------------------------
sub detect_device {
    if (req.http.User-Agent ~ "(?i)(mobile|android|iphone|ipod|tablet|up.browser|up.link|mmp|symbian|smartphone|midp|wap|phone|windows ce)") {
        set req.http.X-Device-Type = "mobile";
    } else if (req.http.User-Agent ~ "(?i)(ipad|playbook|silk)") {
        set req.http.X-Device-Type = "tablet";
    } else {
        set req.http.X-Device-Type = "desktop";
    }
}

# ------------------------------------------------------------------------------
# Advanced Query Parameter Stripping
# ------------------------------------------------------------------------------
sub clean_query_parameters {
    # Remove marketing/tracking parameters
    set req.url = querystring.regfilter(req.url, "^(utm_|fbclid|gclid|mc_eid|ref|cx|ie|cof|siteurl|zanpid|origin|amp)");
    set req.url = regsuball(req.url, "(^|&)(_ga|_ke|mr:[A-Za-z0-9_]+|ncid|platform|spm|sp_|zan-src|mtm|trk|si)=", "&");
    set req.url = regsub(req.url, "(\?|&)+$", "");
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

            # Optional additional cookie removal if desired:
            # set req.http.Cookie = regsuball(
            #     req.http.Cookie,
            #     "(^|; )_ga=[^;]+(; |$)",
            #     "\1"
            # );
            # set req.http.Cookie = regsuball(
            #     req.http.Cookie,
            #     "(^|; )_gid=[^;]+(; |$)",
            #     "\1"
            # );

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
    if (req.http.Upgrade ~ "(?i)websocket") {
        return (pipe);
    }
    return (pipe);
}

# ------------------------------------------------------------------------------
# vcl_recv: Entry Point for Client Requests
# ------------------------------------------------------------------------------
sub vcl_recv {
    # 1) Ensure X-Forwarded-For always includes the client IP
    if (!req.http.X-Forwarded-For) {
        set req.http.X-Forwarded-For = client.ip;
    } else {
        set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    }

    # 2) Socket pacing for large vs. smaller content
    if (tcp.is_idle(client.socket)) {
        if (req.url ~ "\.(mp4|mkv|iso)$") {
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

    # 6) Remove URL fragment, sort query
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
    if (req.http.User-Agent ~ "(?i)(ahrefs|semrush|mj12bot|dotbot|petalbot)") {
        if (vsthrottle.is_denied("bot:" + client.ip, 20, 60s)) {
            return (synth(429, "Bot traffic blocked"));
        }
    }

    # 10) Generic bot/crawler checks (excludes major search engines)
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            # DNS-based verification (example check)
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", "\4.\3.\2.\1.in-addr.arpa"))) {
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

    # 12) WordPress & WooCommerce checks

    #     A) If WP Admin area or logged-in user -> pass
    if (is_admin_area() || is_logged_in()) {
        return (pass);
    }

    #     B) If WP Preview => pass
    if (is_wp_preview()) {
        return (pass);
    }

    #     C) WooCommerce & WP special endpoints => pass
    if (req.url ~ "wc-ajax=") {
        return (pass);
    }
    if (req.url ~ "(wp-admin|wp-login|wc-api|checkout|cart|my-account|add-to-cart|logout|lost-password)") {
        return (pass);
    }

    #     D) WP REST API (optional)
    if (is_wp_rest_api()) {
        return (pass);
    }

    #     E) Remove non-critical WP cookies for non-logged-in users
    call remove_unnecessary_wp_cookies;

    # 13) Static file handling
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        set req.http.X-Static = "1";

        # OPTIONAL: If you want to ignore query strings on static (like ?ver=123),
        # uncomment below for higher cache-hit ratio (but also means WP can't bust cache via ?ver=).
        #
        # set req.url = regsub(req.url, "\?.*$", "");

        return (hash);
    }

    # 14) Grace for dynamic content
    if (req.http.X-Grace) {
        set req.grace = std.duration(req.http.X-Grace, 24h);
    } else {
        # 2h base + random up to 1h
        set req.grace = 2h + std.random(30m, 3600);
    }

    # 15) Handle Range requests by passing (can be replaced by chunk slicing logic)
    if (req.http.Range) {
        return (pass);
    }

    # 16) Handle WP Heartbeat (short Ajax requests)
    if (req.url ~ "wp-admin/admin-ajax.php" && req.http.body ~ "action=heartbeat") {
        return (pass);
    }

    return (hash);
}

# ------------------------------------------------------------------------------
# vcl_backend_fetch
# ------------------------------------------------------------------------------
sub vcl_backend_fetch {
    # (A) Ensure we get compressed data from the backend if available
    if (bereq.http.Accept-Encoding) {
        # If your backend supports brotli, keep "br"
        set bereq.http.Accept-Encoding = "gzip, deflate, br";
    } else {
        set bereq.http.Accept-Encoding = "gzip, deflate";
    }

    # (B) Background fetch for near-expiry content (keeps popular objects fresh)
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
        set beresp.saintmode = 30s;
        return (retry);
    }

    # 2) ESI detection
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi    = true;
        set beresp.do_stream = true;
        if (beresp.http.content-type ~ "text") {
            set beresp.do_gzip = true;
        }
    }

    # If the origin sets X-Purge-Keys, we attach them as xkey for advanced
    # surrogate key purging.
    if (beresp.http.X-Purge-Keys) {
        xkey.add(beresp.http.X-Purge-Keys);
    }

    # 3) Detect static
    if (bereq.http.X-Static == "1" ||
        bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|woff2)$") {

        set beresp.ttl        = 365d;
        set beresp.grace      = 7d;
        set beresp.keep       = 7d;

        set beresp.http.Cache-Control =
            "public, max-age=31536000, immutable, stale-while-revalidate=86400, stale-if-error=86400";
        set beresp.http.Vary  = "Accept-Encoding";

        # Stream large files
        if (std.integer(beresp.http.Content-Length, 0) > 5242880) {
            set beresp.do_stream = true;
            set beresp.http.X-Stream = "true";
        }

        # Potential GZIP for text-based assets
        if (beresp.http.content-type ~ "text" ||
            beresp.http.content-type ~ "application/(javascript|json|xml)") {
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
        # you might want a shorter TTL, for example:
        if (bereq.url ~ "(^|/)feed/" || bereq.url ~ "(\?|&)feed=") {
            set beresp.ttl = 10m;
            set beresp.grace = 1h;
        }
    }

    # 5) If 5xx, short TTL + possible abandon
    if (beresp.status >= 500) {
        set beresp.ttl   = 1s;
        set beresp.grace = 5s;
        return (abandon);
    }

    # 6) Body compression for text/JSON/JS
    if (beresp.http.content-type ~ "text" ||
        beresp.http.content-type ~ "application/json" ||
        beresp.http.content-type ~ "application/javascript") {

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

    # OPTIONAL: Use chunk vmod for partial caching if you prefer,
    # especially for big range-based downloads:
    # if (bereq.http.Range) {
    #     chunk.slice(beresp, 1MB);
    # }

    # NEW: Optionally generate ETag if none is provided
    if (!beresp.http.ETag &&
        (beresp.http.content-type ~ "text" ||
         beresp.http.content-type ~ "application/json" ||
         beresp.http.content-type ~ "application/javascript")) {
        set beresp.http.ETag = "W/\"" + std.digest(beresp.http.Content-Length + bereq.url, "sha256") + "\"";
    }
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

    # Example: Preload critical assets (replacing old server push)
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
