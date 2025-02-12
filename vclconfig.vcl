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
import vtc;  # Optional: for local testing

# ------------------------------------------------------------------------------
# Runtime Parameter Suggestions (set outside this VCL):
# varnishd -p workspace_client=256k \
#           -p workspace_backend=256k \
#           -p thread_pool_min=200 \
#           -p thread_pool_max=4000 \
#           -p thread_pool_timeout=300 \
#           -p thread_pools=2 \
#           -p pcre_match_limit=10000 \
#           -p pcre_match_limit_recursion=10000
# Tweak these for your hardware/traffic for best performance.
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Access Control Lists
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
    .window    = 10;
    .initial   = 4;
    .threshold = 6;
    .interval  = 2s;
    .timeout   = 1s;
}

probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval         = 2s;
    .timeout          = 1s;
    .window           = 10;
    .threshold        = 6;
    .initial          = 4;
    .expected_response= 200;
    .match_pattern    = "OK";
    .threshold        = 3;
}

# ------------------------------------------------------------------------------
# Backend Configuration
# ------------------------------------------------------------------------------
backend default {
    .host = "192.168.1.50";      # <-- Adjust to your backend IP or hostname
    .port = "8080";              # <-- Adjust as needed
    .first_byte_timeout     = 60s;
    .between_bytes_timeout  = 15s;
    .max_connections        = 1000;
    .probe                  = backend_probe;

    # Optimized TCP settings
    .tcp_keepalive_time  = 180;
    .tcp_keepalive_probes= 4;
    .tcp_keepalive_intvl = 20;
    .connect_timeout     = 1s;

    # Connection pooling (for reuse)
    .min_pool_size = 50;
    .max_pool_size = 500;
    .pool_timeout  = 30s;
}

# ------------------------------------------------------------------------------
# Directors / Pools / Rate Limiting
# ------------------------------------------------------------------------------
sub vcl_init {
    # --------------------------------------------------------------------------
    # 1) Sharding Director
    # If you have multiple backends, define them separately and load-balance.
    # By default, we set up a single "default" backend. 
    # --------------------------------------------------------------------------
    new cluster = shard.director({
        .backend           = default;
        .by_hash           = true;      # consistent hashing
        .warmup            = 15s;
        .rampup            = 45s;
        .retries           = 5;
        .skip_gone         = true;
        .healthy_threshold = 2;
    });

    # --------------------------------------------------------------------------
    # 2) Progressive rate limiting with vsthrottle
    # This helps mitigate abusive or high-rate requests.
    # --------------------------------------------------------------------------
    new throttle = vsthrottle.rate_limit(
        .max_rate    = 250,   # base rate
        .duration    = 60,    # per 60 seconds
        .burst       = 75,    # extra burst capacity
        .penalty_box = 300    # time in penalty box (seconds)
    );

    # --------------------------------------------------------------------------
    # 3) TCP Pool
    # Useful if you have multiple connections to your backend and want 
    # advanced connection reuse.
    # --------------------------------------------------------------------------
    new pool = tcp.pool(
        .max_connections = 2500,
        .min_connections = 200,
        .idle_timeout    = 180,
        .connect_timeout = 0.5
    );

    return (ok);
}

# ------------------------------------------------------------------------------
# Security Headers
# Added in vcl_deliver to ensure they apply to all successful or error responses.
# ------------------------------------------------------------------------------
sub add_security_headers {
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload";
    set resp.http.X-Content-Type-Options    = "nosniff";
    set resp.http.X-XSS-Protection          = "1; mode=block";
    set resp.http.Referrer-Policy           = "strict-origin-when-cross-origin";
    set resp.http.Permissions-Policy        = "interest-cohort=()";

    # Example minimal CSP for HTML/PHP:
    # Adjust to fit your site’s actual needs for inline JS, fonts, frames, etc.
    if (req.url ~ "\.(html|php)$") {
        set resp.http.Content-Security-Policy =
            "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';";
    }
}

# ------------------------------------------------------------------------------
# Saint Mode for Backend Errors
# - Tries a re-fetch or to avoid a failing backend for a short time
# ------------------------------------------------------------------------------
sub vcl_backend_error {
    if (beresp.status >= 500) {
        std.log("Backend error: saint mode -> " + bereq.url);
        return (retry);
    }
}

# ------------------------------------------------------------------------------
# WP/WooCommerce Helper Routines
# ------------------------------------------------------------------------------
sub is_logged_in {
    # Typical WordPress/WooCommerce logged-in cookies
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
    # WordPress admin routes
    if (req.url ~ "(wp-admin|wp-login\.php)") {
        return(true);
    }
    return(false);
}

# ------------------------------------------------------------------------------
# Additional WP-related detection
# (e.g., WP REST API endpoints, if you want to pass them)
# ------------------------------------------------------------------------------
sub is_wp_rest_api {
    if (req.url ~ "^/wp-json/") {
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
# Removes known marketing/tracking params
# ------------------------------------------------------------------------------
sub clean_query_parameters {
    set req.url = querystring.regfilter(req.url, "^(utm_|fbclid|gclid|mc_eid|ref|cx|ie|cof|siteurl|zanpid|origin|amp)");
    # Additional known patterns
    set req.url = regsuball(req.url, "(^|&)(_ga|_ke|mr:[A-Za-z0-9_]+|ncid|platform|spm|sp_|zan-src|mtm|trk|si)=", "&");
    set req.url = regsub(req.url, "(\?|&)+$", "");
}

# ------------------------------------------------------------------------------
# vcl_hash
# ------------------------------------------------------------------------------
sub vcl_hash {
    # Use a composite hash: URL + Host + Device type
    hash_data(blob.encode(req.url + req.http.host + req.http.X-Device-Type, blob.BASE64));

    # Distinguish by X-Forwarded-Proto if you vary content by HTTP vs. HTTPS
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    # Optional per-user cache key
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
# vcl_recv: Main Entry Point for Requests
# ------------------------------------------------------------------------------
sub vcl_recv {
    # 1) TCP Socket Pacing (large vs. smaller files)
    if (tcp.is_idle(client.socket)) {
        if (req.url ~ "\.(mp4|mkv|iso)$") {
            tcp.set_socket_pace(client.socket, 5MB);
        } else {
            tcp.set_socket_pace(client.socket, 1MB);
        }
    }

    # 2) Host normalization (remove port)
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    # 3) Detect device for possible separate caching
    call detect_device;

    # 4) Clean query parameters (remove marketing/tracking)
    call clean_query_parameters;

    # 5) Remove fragment (#...) then sort remaining query
    set req.url = std.querysort(regsub(req.url, "#.*$", ""));

    # 6) PURGE checks (with ACL)
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(403, "Forbidden"));
        }
        if (req.http.xkey) {
            # xkey-based selective purge
            set req.http.n_gone = xkey.purge(req.http.xkey);
            return (synth(200, "Purged " + req.http.n_gone + " objects"));
        } else {
            # fallback to ban-lurker if no xkey present
            ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
            return (synth(200, "Banned via ban-lurker"));
        }
    }

    # 7) Non-idempotent methods -> pass
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # 8) Known heavy bots (simple user-agent check)
    if (req.http.User-Agent ~ "(?i)(ahrefs|semrush|mj12bot|dotbot|petalbot)") {
        if (vsthrottle.is_denied("bot:" + client.ip, 20, 60s)) {
            return (synth(429, "Bot traffic blocked"));
        }
    }

    # 9) More thorough generic bot detection
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        # Exclude common search engine bots we want to allow
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            # DNS-based check (reverse DNS)
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", "\4.\3.\2.\1.in-addr.arpa"))) {
                if (vsthrottle.is_denied("bot:" + client.ip, 50, 60s)) {
                    unix.syslog(unix.LOG_WARNING, "Generic Bot banned: " + client.ip);
                    return (synth(403, "Bot Access Denied"));
                }
            }
        }
    }

    # 10) Rate-limiting for general traffic
    if (vsthrottle.is_denied(client.ip, 250, 60s)) {
        # If they exceed higher threshold, block harder
        if (vsthrottle.is_denied(client.ip, 350, 300s)) {
            unix.syslog(unix.LOG_WARNING, "Heavy rate-limit exceeded: " + client.ip);
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # 11) WordPress & WooCommerce logic
    #     Pass for admin, login, or if user is logged in
    if (is_admin_area() || is_logged_in()) {
        return (pass);
    }
    #     Pass if wc-ajax (AJAX cart ops)
    if (req.url ~ "wc-ajax=") {
        return (pass);
    }
    #     Also pass for certain WC endpoints (cart, checkout, etc.)
    if (req.url ~ "(wp-admin|wp-login|wc-api|checkout|cart|my-account|add-to-cart|logout|lost-password)") {
        return (pass);
    }
    #     Optionally pass WP REST API (if you want it uncached)
    if (is_wp_rest_api()) {
        return (pass);
    }

    # 12) Static file handling
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;        # no cookies for static
        set req.http.X-Static = "1";  # custom flag
        return (hash);
    }

    # 13) Grace period for dynamic content
    if (req.http.X-Grace) {
        set req.grace = std.duration(req.http.X-Grace, 24h);
    } else {
        # e.g. base of 2h, plus random up to 1h for staggered revalidation
        set req.grace = 2h + std.random(30m, 3600);
    }

    return (hash);
}

# ------------------------------------------------------------------------------
# vcl_backend_response
# ------------------------------------------------------------------------------
sub vcl_backend_response {
    # 1) Saint mode for 5xx
    if (beresp.status >= 500) {
        set beresp.saintmode = 30s;
        return (retry);
    }

    # 2) ESI detection
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
        set beresp.do_stream = true;
        if (beresp.http.content-type ~ "text") {
            set beresp.do_gzip = true;
        }
    }

    # 3) Static assets
    if (bereq.http.X-Static == "1" || bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|woff2)$") {
        set beresp.ttl  = 365d;
        set beresp.grace= 7d;
        set beresp.keep = 7d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        set beresp.http.Vary = "Accept-Encoding";

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
    }
    else {
        # 4) Dynamic content defaults
        if (!beresp.http.Cache-Control) {
            set beresp.ttl  = 4h;
            set beresp.grace= 24h;
            set beresp.keep = 24h;
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # 5) If 5xx is present, short TTL + attempt to abandon
    if (beresp.status >= 500) {
        set beresp.ttl   = 1s;
        set beresp.grace = 5s;
        return (abandon);
    }

    # 6) Body compression optimization for text-based or JSON content
    if (beresp.http.content-type ~ "text" ||
        beresp.http.content-type ~ "application/json" ||
        beresp.http.content-type ~ "application/javascript") {

        if (std.integer(beresp.http.Content-Length, 0) < 860) {
            set beresp.do_gzip = false;
        } else {
            set beresp.do_gzip = true;
            # Stream large text
            if (std.integer(beresp.http.Content-Length, 0) > 102400) {
                set beresp.do_stream = true;
            }
        }
    }
}

# ------------------------------------------------------------------------------
# vcl_deliver
# ------------------------------------------------------------------------------
sub vcl_deliver {
    # 1) Remove or mask revealing headers
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    # 2) Add global security headers
    call add_security_headers;

    # 3) Debug info for trusted networks only
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

    # If you pass user IDs from your application, you can expose them here 
    # for debugging, personalization, or logging.
    if (req.http.X-User-ID) {
        set resp.http.X-User-Cache-ID = req.http.X-User-ID;
    }
}

# ------------------------------------------------------------------------------
# vcl_synth
# ------------------------------------------------------------------------------
sub vcl_synth {
    # e.g., 750 -> 301 redirect
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + req.url;
        return (deliver);
    }

    # Handle rate-limited or custom errors with JSON
    if (resp.status == 429) {
        set resp.http.Retry-After = "60";
        set resp.http.Content-Type = "application/json";
        synthetic({"{\"error\": \"Too many requests\", \"retry_after\": 60}"});
    }

    # Add security headers even on error pages
    call add_security_headers;

    return (deliver);
}

# ------------------------------------------------------------------------------
# Custom Error Page Generator (Optional)
# ------------------------------------------------------------------------------
sub generate_error_page {
    # If you want to build a custom error page, do it here:
    # e.g. synthetic("<html><body><h1>Something went wrong.</h1></body></html>");
}
