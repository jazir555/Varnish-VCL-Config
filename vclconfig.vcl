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
import xkey;         # For selective purging
import bodyaccess;   # For response body manipulation
import cookie;       # Advanced cookie handling
import vtc;          # Varnish testing framework (if needed for local testing)

#------------------------------------------------------------------------------
# Memory management & threading
#------------------------------------------------------------------------------
# You can set these parameters outside the VCL or as runtime parameters, e.g.:
# varnishd -p workspace_client=256k \
#           -p workspace_backend=256k \
#           -p thread_pool_min=200 \
#           -p thread_pool_max=4000 \
#           -p thread_pool_timeout=300 \
#           -p thread_pools=2 \
#           -p pcre_match_limit=10000 \
#           -p pcre_match_limit_recursion=10000

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
    .window   = 10;
    .initial  = 4;
    .threshold = 6;
    .interval = 2s;
    .timeout  = 1s;
}

probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval = 2s;
    .timeout  = 1s;
    .window   = 10;
    .threshold = 6;
    .initial   = 4;
    .expected_response = 200;
    .match_pattern     = "OK";
    .threshold         = 3;
}

#------------------------------------------------------------------------------
# Backend Configuration
#------------------------------------------------------------------------------
backend default {
    .host = "192.168.1.50";
    .port = "8080";
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
# Advanced Directors / Pools
#------------------------------------------------------------------------------
sub vcl_init {
    # Sharding with warmup
    new cluster = shard.director(
        {
            .backend        = default;
            .by_hash        = true;
            .warmup         = 15s;
            .rampup         = 45s;
            .retries        = 5;
            .skip_gone      = true;
            .healthy_threshold = 2;
        }
    );

    # Progressive rate limiting
    new throttle = vsthrottle.rate_limit(
        .max_rate    = 250,   # Increased rate
        .duration    = 60,
        .burst       = 75,    # Increased burst
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
# vcl_hash
#------------------------------------------------------------------------------
sub vcl_hash {
    # Composite hashing (URL + Host + Device)
    hash_data(blob.encode(req.url + req.http.host + req.http.X-Device-Type, blob.BASE64));

    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    # If there's a user ID header, incorporate for user-specific caching
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
# Helper Routines / WP + WooCommerce detection
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
# vcl_recv
#------------------------------------------------------------------------------
sub vcl_recv {
    # Optimize TCP handling for idle sockets
    if (tcp.is_idle(client.socket)) {
        if (req.url ~ "\.(mp4|mkv|iso)$") {
            tcp.set_socket_pace(client.socket, 2MB);
        } else {
            tcp.set_socket_pace(client.socket, 150KB);
        }
    }

    # Normalize host and sort query parameters
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);

    # Remove URL fragments (#, trailing ?)
    if (req.url ~ "[#\?]") {
        set req.url = chunk.replace(req.url, "[#\?].*$", "");
    }

    # Device detection
    if (req.http.User-Agent) {
        if (req.http.User-Agent ~ "(?i)mobile|android|iphone|ipod|tablet") {
            set req.http.X-Device-Type = "mobile";
        } else {
            set req.http.X-Device-Type = "desktop";
        }
    }

    # Advanced parameter cleaning (UTM, ref, etc.)
    if (req.url ~ "[?&](utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_|campaign_|medium_|term_)") {
        set req.url = chunk.replace(req.url, "(utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_|campaign_|medium_|term_)[^&]+&?", "");
        set req.url = chunk.replace(req.url, "(\?|&)$", "");
    }

    # Selective PURGE via xkey
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed"));
        }
        if (req.http.xkey) {
            set req.http.n-gone = xkey.purge(req.http.xkey);
            return (synth(200, "Purged " + req.http.n-gone + " objects"));
        } else {
            ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
            return (synth(200, "Banned"));
        }
    }

    # Enhanced bot handling
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            # Advanced bot DNS check
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", "\4.\3.\2.\1.in-addr.arpa"))) {
                if (vsthrottle.is_denied("bot:" + client.ip, 50, 60s)) {
                    unix.syslog(unix.LOG_WARNING, "Bot banned: " + client.ip);
                    return (synth(403, "Bot Access Denied"));
                }
            }
        }
    }

    # Intelligent rate limiting
    if (vsthrottle.is_denied(client.ip, 250, 60s)) {
        if (vsthrottle.is_denied(client.ip, 350, 300s)) {
            unix.syslog(unix.LOG_WARNING, "Heavy rate limit exceeded: " + client.ip);
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # Handle WooCommerce & WordPress
    # --------------------------------------------------------------------------
    # 1) If user is requesting wp-admin, wp-login.php, or a logged-in user cookie,
    #    we do not cache. This ensures correct dynamic behavior.
    # 2) If request is for WooCommerce cart, checkout, or has cart fragments,
    #    we also pass.
    if (is_admin_area() || is_logged_in()) {
        return (pass);
    }
    
    # If it's a WC Ajax endpoint (e.g., ?wc-ajax=...),
    # pass to avoid caching dynamic cart data.
    if (req.url ~ "wc-ajax=") {
        return(pass);
    }

    # Bypass caching for POST or other non-idempotent methods (just in case)
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Smart static file handling
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        set req.http.X-Static-Asset = "true";
        return (hash);
    }

    # Dynamic grace period
    if (req.http.X-Grace) {
        set req.grace = std.duration(req.http.X-Grace, 24h);
    } else {
        set req.grace = 24h;
    }

    return (hash);
}

#------------------------------------------------------------------------------
# vcl_backend_response
#------------------------------------------------------------------------------
sub vcl_backend_response {
    # Advanced ESI detection
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
        set beresp.do_stream = true;
        if (beresp.http.content-type ~ "text") {
            set beresp.do_gzip = true;
        }
    }

    # Intelligent static asset handling
    if (bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|woff2)$") {
        set beresp.ttl  = 365d;
        set beresp.grace= 7d;
        set beresp.keep = 7d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        set beresp.http.Vary = "Accept-Encoding";

        # Streaming for large files
        if (std.integer(beresp.http.Content-Length, 0) > 5242880) {
            set beresp.do_stream = true;
            set beresp.http.X-Stream = "true";
        }

        # Compression for text-like assets
        if (beresp.http.content-type ~ "text" ||
            beresp.http.content-type ~ "application/(javascript|json|xml)") {
            if (std.integer(beresp.http.Content-Length, 0) > 860) {
                set beresp.do_gzip = true;
            }
        }
    } else {
        # Default dynamic content TTL
        if (!beresp.http.Cache-Control) {
            set beresp.ttl  = 4h;
            set beresp.grace= 24h;
            set beresp.keep = 24h;
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # Handle server errors
    if (beresp.status >= 500) {
        set beresp.ttl = 1s;
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
            # Stream large responses
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
    # Remove sensitive headers
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    # Debug info for trusted networks
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache       = (obj.hits > 0) ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits  = obj.hits;
        set resp.http.X-Served-By   = server.hostname;
        set resp.http.X-Pool        = req.backend_hint;
        set resp.http.X-Grace       = req.grace;

        if (resp.http.X-Stream) {
            set resp.http.X-Stream-Size = beresp.http.Content-Length;
        }
        if (obj.hits > 0) {
            set resp.http.X-Age = obj.age;
        }
    }
}

#------------------------------------------------------------------------------
# vcl_synth
#------------------------------------------------------------------------------
sub vcl_synth {
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + resp.reason;
        return (deliver);
    }

    # Rate Limit / 429
    if (resp.status == 429) {
        set resp.http.Retry-After       = "60";
        set resp.http.X-RateLimit-Reset = std.time(now + 60s, "%s");
        set resp.http.X-RateLimit-Limit = "250";
    }

    call generate_error_page;
    return (deliver);
}

#------------------------------------------------------------------------------
# Optional: Custom Error Page Generator
#------------------------------------------------------------------------------
sub generate_error_page {
    # If you have a custom error page generation, put it here.
    # Otherwise, it can remain empty or minimal.
}
