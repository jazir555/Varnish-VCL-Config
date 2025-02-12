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
# Runtime Parameter Suggestions (outside this file):
# varnishd -p workspace_client=256k \
#           -p workspace_backend=256k \
#           -p thread_pool_min=200 \
#           -p thread_pool_max=4000 \
#           -p thread_pool_timeout=300 \
#           -p thread_pools=2 \
#           -p pcre_match_limit=10000 \
#           -p pcre_match_limit_recursion=10000
# ------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# ACLs
#------------------------------------------------------------------------------
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

#------------------------------------------------------------------------------
# Health Checks
#------------------------------------------------------------------------------
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
    .interval        = 2s;
    .timeout         = 1s;
    .window          = 10;
    .threshold       = 6;
    .initial         = 4;
    .expected_response = 200;
    .match_pattern     = "OK";
    .threshold         = 3;
}

#------------------------------------------------------------------------------
# Backend Configuration
#------------------------------------------------------------------------------
backend default {
    .host = "192.168.1.50";      # Adjust to your backend
    .port = "8080";              # Adjust to your backend
    .first_byte_timeout     = 60s;
    .between_bytes_timeout  = 15s;
    .max_connections        = 1000;
    .probe                  = backend_probe;
    
    # Optimized TCP settings
    .tcp_keepalive_time  = 180;
    .tcp_keepalive_probes= 4;
    .tcp_keepalive_intvl = 20;
    .connect_timeout     = 1s;
    
    # Connection pooling
    .min_pool_size = 50;
    .max_pool_size = 500;
    .pool_timeout  = 30s;
}

#------------------------------------------------------------------------------
# Directors / Pools / Rate Limiting
#------------------------------------------------------------------------------
sub vcl_init {
    # Advanced sharding (if you have multiple backends, replicate & add them here)
    new cluster = shard.director({
        .backend          = default;
        .by_hash          = true;
        .warmup           = 15s;
        .rampup           = 45s;
        .retries          = 5;
        .skip_gone        = true;
        .healthy_threshold= 2;
    });

    # Progressive rate limiting with a bigger burst
    new throttle = vsthrottle.rate_limit(
        .max_rate    = 250,
        .duration    = 60,
        .burst       = 75,
        .penalty_box = 300
    );

    # Optimized TCP pool
    new pool = tcp.pool(
        .max_connections = 2500,
        .min_connections = 200,
        .idle_timeout    = 180,
        .connect_timeout = 0.5
    );

    return (ok);
}

#------------------------------------------------------------------------------
# Security Headers (added during deliver)
#------------------------------------------------------------------------------
sub add_security_headers {
    # Strict Transport Security
    set resp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload";
    # Additional Hardening
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-XSS-Protection       = "1; mode=block";
    set resp.http.Referrer-Policy        = "strict-origin-when-cross-origin";
    set resp.http.Permissions-Policy     = "interest-cohort=()";

    # Example basic CSP for HTML/PHP pages (adjust as needed)
    if (req.url ~ "\.(html|php)$") {
        set resp.http.Content-Security-Policy =
            "default-src 'self' https: 'unsafe-inline' 'unsafe-eval';";
    }
}

#------------------------------------------------------------------------------
# Saint mode handling for backend errors
#------------------------------------------------------------------------------
sub vcl_backend_error {
    # If backend returns 500+, try re-fetching (or another backend) briefly
    if (beresp.status >= 500) {
        std.log("Backend error: activating saint mode for: " + bereq.url);
        return (retry);
    }
}

#------------------------------------------------------------------------------
# WP/WooCommerce Helper Routines
#------------------------------------------------------------------------------
sub is_logged_in {
    # Detect typical WordPress/WooCommerce logged-in cookies
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
    # Typical WordPress admin URLs
    if (req.url ~ "(wp-admin|wp-login\.php)") {
        return(true);
    }
    return(false);
}

#------------------------------------------------------------------------------
# Device Detection
#------------------------------------------------------------------------------
sub detect_device {
    if (req.http.User-Agent ~ "(?i)(mobile|android|iphone|ipod|tablet|up.browser|up.link|mmp|symbian|smartphone|midp|wap|phone|windows ce)") {
        set req.http.X-Device-Type = "mobile";
    } else if (req.http.User-Agent ~ "(?i)(ipad|playbook|silk)") {
        set req.http.X-Device-Type = "tablet";
    } else {
        set req.http.X-Device-Type = "desktop";
    }
}

#------------------------------------------------------------------------------
# Advanced Query Parameter Stripping
#------------------------------------------------------------------------------
sub clean_query_parameters {
    # Remove known marketing/tracking parameters.
    set req.url = querystring.regfilter(req.url, "^(utm_|fbclid|gclid|mc_eid|ref|cx|ie|cof|siteurl|zanpid|origin|amp)");
    # Additional blocks of known patterns
    set req.url = regsuball(req.url, "(^|&)(_ga|_ke|mr:[A-Za-z0-9_]+|ncid|platform|spm|sp_|zan-src|mtm|trk|si)=", "&");
    # Remove trailing ? or & if left empty
    set req.url = regsub(req.url, "(\?|&)+$", "");
}

#------------------------------------------------------------------------------
# vcl_hash
#------------------------------------------------------------------------------
sub vcl_hash {
    # Combine URL + Host + Device into the hash
    hash_data(blob.encode(req.url + req.http.host + req.http.X-Device-Type, blob.BASE64));

    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    # Per-user caching if needed
    if (req.http.X-User-ID) {
        hash_data(req.http.X-User-ID);
    }

    return (lookup);
}

#------------------------------------------------------------------------------
# vcl_hit
#------------------------------------------------------------------------------
sub vcl_hit {
    if (obj.ttl >= 0s) {
        return (deliver);
    }
    if (obj.ttl + obj.grace > 0s) {
        return (deliver);
    }
    return (miss);
}

#------------------------------------------------------------------------------
# vcl_recv: Entry Point for Client Requests
#------------------------------------------------------------------------------
sub vcl_recv {
    # Socket pacing for large or small files
    if (tcp.is_idle(client.socket)) {
        if (req.url ~ "\.(mp4|mkv|iso)$") {
            tcp.set_socket_pace(client.socket, 5MB);
        } else {
            tcp.set_socket_pace(client.socket, 1MB);
        }
    }

    # Host normalization
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

    # Device detection
    call detect_device;

    # Clean query parameters
    call clean_query_parameters;

    # Remove fragment parts (#...), then sort the query
    set req.url = std.querysort(regsub(req.url, "#.*$", ""));

    # PURGE checks (with ACL)
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(403, "Forbidden"));
        }
        # If no error, do a normal purge or xkey-based purge
        if (req.http.xkey) {
            # Using xkey for selective purging
            set req.http.n_gone = xkey.purge(req.http.xkey);
            return (synth(200, "Purged " + req.http.n_gone + " objects"));
        } else {
            # Fallback ban if no xkey
            ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
            return (synth(200, "Banned via ban-lurker"));
        }
    }

    # Pass on non-idempotent methods
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Simple advanced known-bot check (e.g. Ahrefs, Semrush, MJ12bot, Dotbot, Petalbot)
    if (req.http.User-Agent ~ "(?i)(ahrefs|semrush|mj12bot|dotbot|petalbot)") {
        if (vsthrottle.is_denied("bot:" + client.ip, 20, 60s)) {
            return (synth(429, "Bot traffic blocked"));
        }
    }

    # More thorough bot check for other crawlers
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        # Exclude common search engines
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            # DNS-based bot verification
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", "\4.\3.\2.\1.in-addr.arpa"))) {
                if (vsthrottle.is_denied("bot:" + client.ip, 50, 60s)) {
                    unix.syslog(unix.LOG_WARNING, "Bot banned via DNS check: " + client.ip);
                    return (synth(403, "Bot Access Denied"));
                }
            }
        }
    }

    # Rate-limiting for general traffic
    if (vsthrottle.is_denied(client.ip, 250, 60s)) {
        # If they exceed a second threshold, block harder
        if (vsthrottle.is_denied(client.ip, 350, 300s)) {
            unix.syslog(unix.LOG_WARNING, "Heavy rate limit exceeded: " + client.ip);
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # WordPress & WooCommerce checks
    # 1) Pass if admin area, login, or user is logged in
    if (is_admin_area() || is_logged_in()) {
        return (pass);
    }
    # 2) Pass if it's a WC Ajax endpoint
    if (req.url ~ "wc-ajax=") {
        return (pass);
    }
    # 3) Additional WP/WC endpoints that must remain dynamic
    if (req.url ~ "(wp-admin|wp-login|wc-api|checkout|cart|my-account|add-to-cart|logout|lost-password)") {
        return (pass);
    }

    # Smart static file handling
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        set req.http.X-Static = "1";
        return (hash);
    }

    # Grace period
    if (req.http.X-Grace) {
        set req.grace = std.duration(req.http.X-Grace, 24h);
    } else {
        # Example: 2h base + a random up to 1 hour for staggered grace
        set req.grace = 2h + std.random(30m, 3600);
    }

    return (hash);
}

#------------------------------------------------------------------------------
# vcl_backend_response
#------------------------------------------------------------------------------
sub vcl_backend_response {
    # Saint mode activation if 500+ from backend
    if (beresp.status >= 500) {
        set beresp.saintmode = 30s;
        return (retry);
    }

    # ESI detection
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
        set beresp.do_stream = true;
        if (beresp.http.content-type ~ "text") {
            set beresp.do_gzip = true;
        }
    }

    # Check if we flagged this as a static asset
    if (bereq.http.X-Static == "1" || bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|woff2)$") {
        # Very long cache for static
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

        # Possibly compress text or JavaScript
        if (beresp.http.content-type ~ "text" ||
            beresp.http.content-type ~ "application/(javascript|json|xml)") {
            if (std.integer(beresp.http.Content-Length, 0) > 860) {
                set beresp.do_gzip = true;
            }
        }
    }
    else {
        # Dynamic content TTL if not explicitly set by backend
        if (!beresp.http.Cache-Control) {
            set beresp.ttl  = 4h;
            set beresp.grace= 24h;
            set beresp.keep = 24h;
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # If the backend returns an error (5xx), short TTL, attempt to abandon
    # (some folks prefer letting saintmode handle it fully)
    if (beresp.status >= 500) {
        set beresp.ttl   = 1s;
        set beresp.grace = 5s;
        return (abandon);
    }

    # Body compression optimization
    if (beresp.http.content-type ~ "text" ||
        beresp.http.content-type ~ "application/json" ||
        beresp.http.content-type ~ "application/javascript") {

        if (std.integer(beresp.http.Content-Length, 0) < 860) {
            set beresp.do_gzip = false;
        } else {
            set beresp.do_gzip = true;
            # Stream large text content
            if (std.integer(beresp.http.Content-Length, 0) > 102400) {
                set beresp.do_stream = true;
            }
        }
    }
}

#------------------------------------------------------------------------------
# vcl_deliver
#------------------------------------------------------------------------------
sub vcl_deliver {
    # Remove or mask potentially revealing headers
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    # Add security headers (HSTS, CSP, etc.)
    call add_security_headers;

    # Debug info for internal/trusted IPs
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

    # Example: exposing user ID if set by your application layer
    if (req.http.X-User-ID) {
        set resp.http.X-User-Cache-ID = req.http.X-User-ID;
    }
}

#------------------------------------------------------------------------------
# vcl_synth
#------------------------------------------------------------------------------
sub vcl_synth {
    # 301 redirect if status == 750
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + req.url;
        return (deliver);
    }

    # Custom rate-limit or error responses
    if (resp.status == 429) {
        set resp.http.Retry-After = "60";
        set resp.http.Content-Type = "application/json";
        synthetic({"{\"error\": \"Too many requests\", \"retry_after\": 60}"});
    }

    # Add security headers even on errors
    call add_security_headers;

    return (deliver);
}

#------------------------------------------------------------------------------
# Optional: Custom Error Page Generator
#------------------------------------------------------------------------------
sub generate_error_page {
    # For advanced error page handling, you can populate or rewrite resp with a template here.
    # Otherwise, leave blank to let Varnish generate a minimal error page.
}
