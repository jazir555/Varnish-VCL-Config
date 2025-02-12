vcl 7.4;

import std;
import directors;
import querystring;
import vsthrottle;
import chunk; # New in 7.0+
import tcp;   # New in 7.0+
import shard; # New in 7.0+
import blob;  # New in 7.0+
import unix;  # New in 7.0+

# Enhanced ACLs with specific CIDR ranges and IPv6 support
acl purge {
    "localhost";
    "127.0.0.1";
    "192.168.1.100";
    "192.168.1.101";
    "::1"/128;           # IPv6 localhost
    "fe80::"/10;        # IPv6 link-local
}

acl trusted_networks {
    "localhost";
    "127.0.0.1";
    "192.168.1.0"/24;
    "::1"/128;
    "fe80::"/10;
}

# Advanced health checks with TCP checks
probe tcp_probe {
    .window = 8;
    .initial = 3;
    .threshold = 5;
    .interval = 3s;
    .timeout = 1s;
}

probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval = 3s;
    .timeout = 1s;
    .window = 8;
    .threshold = 5;
    .initial = 3;
    .expected_response = 200;
    # New in 7.0+: Match response body
    .match_pattern = "OK";
}

# Enhanced backend definition with TCP tuning
backend default {
    .host = "192.168.1.50";
    .port = "8080";
    .first_byte_timeout = 120s;
    .between_bytes_timeout = 30s;
    .max_connections = 800;
    .probe = backend_probe;
    # New TCP optimizations
    .tcp_keepalive_time = 300;
    .tcp_keepalive_probes = 5;
    .tcp_keepalive_intvl = 30;
}

# Advanced director setup with sharding
sub vcl_init {
    new bar = shard.director(
        {.backend = default;},
        .rampup = 60s,          # Gradual backend warmup
        .warmup = 9s,           # Individual warmup time
        .retries = 3            # Number of retry attempts
    );
    
    # Enhanced rate limiting with progressive thresholds
    new throttle = vsthrottle.rate_limit(
        .max_rate = 200,
        .duration = 60,
        .burst = 50
    );
    
    # TCP connection pool
    new pool = tcp.pool(
        .max_connections = 2000,
        .min_connections = 100,
        .idle_timeout = 300
    );
    
    return (ok);
}

# Optimized hash function with blob support
sub vcl_hash {
    # Efficient blob-based hashing
    hash_data(blob.encode(req.url + req.http.host, blob.BASE64));
    
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
    
    if (req.http.X-WP-Logged-In-Hash) {
        hash_data(req.http.X-WP-Logged-In-Hash);
    }
    return (lookup);
}

sub vcl_recv {
    # Enhanced TCP optimization
    if (tcp.is_idle(client.socket)) {
        tcp.set_socket_pace(client.socket, 100KB);
    }

    # Normalize request with improved efficiency
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);
    
    # Efficient URL cleaning with chunked processing
    if (req.url ~ "[#\?]") {
        set req.url = chunk.replace(req.url, "#.*$", "");
        set req.url = chunk.replace(req.url, "\?$", "");
    }

    # Advanced HTTPS redirect with HSTS preload check
    if (req.restarts == 0 && req.http.X-Forwarded-Proto !~ "(?i)https") {
        return (synth(750, req.url));
    }

    # Enhanced parameter cleaning with chunk support
    if (req.url ~ "[?&](utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_)") {
        set req.url = chunk.replace(req.url, "(utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_)[^&]+&?", "");
        set req.url = chunk.replace(req.url, "(\?|&)$", "");
    }

    # Advanced PURGE with shard support
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed"));
        }
        if (req.http.X-Purge-Pattern) {
            ban("obj.http.x-url ~ " + req.http.X-Purge-Pattern);
        } else {
            ban("obj.http.x-url == " + req.url + " && obj.http.x-host == " + req.http.host);
        }
        return (synth(200, "Purged"));
    }

    # Enhanced bot detection with fingerprinting
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        # Verify legitimate bots through DNS reverse lookup
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            if (!std.dns("txt", regsub(client.ip, "^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$", "\4.\3.\2.\1.in-addr.arpa"))) {
                return (synth(403, "Bot Access Denied"));
            }
        }
    }

    # Advanced rate limiting with progressive thresholds
    if (vsthrottle.is_denied(client.ip, 200, 60s)) {
        if (vsthrottle.is_denied(client.ip, 300, 300s)) {
            unix.syslog(unix.LOG_WARNING, "Rate limit exceeded by " + client.ip);
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # Enhanced WordPress handling with blob hashing
    if (req.http.Cookie) {
        if (req.http.Cookie ~ "wordpress_logged_in_") {
            set req.http.X-WP-Logged-In-Hash = blob.encode(req.http.Cookie, blob.BASE64);
        }
        
        if (req.http.Cookie ~ "(wordpress_logged_in|wp_woocommerce_session|woocommerce_items_in_cart)") {
            return (pass);
        }
        unset req.http.Cookie;
    }

    # Optimized static file pattern
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        # Set optimal TCP parameters for static content
        tcp.set_socket_pace(client.socket, 1MB);
        return (hash);
    }

    # Enhanced grace mode with dynamic TTL
    set req.grace = std.duration(req.http.Grace-TTL, 24h);

    # Advanced content negotiation with Brotli support
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
            unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "br") {
            set req.http.Accept-Encoding = "br";
        } elsif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else {
            unset req.http.Accept-Encoding;
        }
    }
}

sub vcl_backend_response {
    # Advanced ESI with streaming
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
        set beresp.do_stream = true;
        if (beresp.http.content-type ~ "text") {
            set beresp.do_gzip = true;
        }
    }

    # Enhanced static asset caching with optimal settings
    if (bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|gz|tgz|bz2|tbz|mp3|ogg|swf)$") {
        set beresp.ttl = 365d;
        set beresp.grace = 7d;
        set beresp.keep = 7d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        unset beresp.http.Set-Cookie;
        set beresp.http.Vary = "Accept-Encoding";
        # Enable streaming for large files
        if (std.integer(beresp.http.Content-Length, 0) > 10485760) {
            set beresp.do_stream = true;
        }
    } else {
        set beresp.ttl = 4h;
        set beresp.grace = 24h;
        set beresp.keep = 24h;
        if (!beresp.http.Cache-Control) {
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # Comprehensive security headers
    set beresp.http.Content-Security-Policy = 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-eval' https://example.com; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self';";
    set beresp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload";
    set beresp.http.X-Content-Type-Options = "nosniff";
    set beresp.http.X-Frame-Options = "DENY";
    set beresp.http.Referrer-Policy = "strict-origin-when-cross-origin";
    set beresp.http.Permissions-Policy = "geolocation=(), microphone=(), camera=()";
    
    unset beresp.http.X-Powered-By;
    unset beresp.http.Server;

    # Advanced compression strategy
    if (beresp.http.content-type ~ "text" || 
        beresp.http.content-type ~ "application/json" ||
        beresp.http.content-type ~ "application/javascript") {
        if (std.integer(beresp.http.Content-Length, 0) < 1024) {
            # Skip compression for small files
            set beresp.do_gzip = false;
        } else {
            set beresp.do_gzip = true;
        }
    }
}

sub vcl_deliver {
    # Enhanced security header cleanup
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    
    # Comprehensive debug headers for trusted networks
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By = server.hostname;
        set resp.http.X-Grace = req.grace;
        set resp.http.X-Backend = beresp.backend.name;
        set resp.http.X-Processing-Time = std.duration(now - req.http.X-Request-Start, 0s);
    }

    call add_cors_headers;
}

sub vcl_synth {
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + resp.reason;
        return (deliver);
    }

    if (resp.status == 429) {
        set resp.http.Retry-After = "60";
        set resp.http.X-RateLimit-Reset = std.time(now + 60s, "%s");
    }

    call generate_error_page;
    return (deliver);
}
