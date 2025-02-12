vcl 4.1;

import std;
import directors;
import querystring;
import vsthrottle;

# Expanded ACLs with more specific CIDR ranges
acl purge {
    "localhost";
    "127.0.0.1";
    "192.168.1.100";
    "192.168.1.101";  # Added backup admin
}

acl trusted_networks {
    "localhost";
    "127.0.0.1";
    "192.168.1.0/24";
}

# Enhanced backend probe with smarter checks
probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval = 3s;          # More frequent checks
    .timeout = 1s;           # Faster timeout
    .window = 8;             # Larger window for better accuracy
    .threshold = 5;          # Higher threshold
    .initial = 3;            # More initial checks
    .expected_response = 200;
}

backend default {
    .host = "192.168.1.50";
    .port = "8080";
    .first_byte_timeout = 120s;     # Reduced from 300s
    .between_bytes_timeout = 30s;    # Reduced from 60s
    .max_connections = 800;          # Added connection limiting
    .probe = backend_probe;
}

# Enhanced director setup with retry logic
sub vcl_init {
    new cluster = directors.round_robin();
    cluster.add_backend(default);
    
    # Added global rate limiting settings
    new throttle = vsthrottle.rate_limit();
    return (ok);
}

# Optimized hash function
sub vcl_hash {
    # Base hash on URL and host
    hash_data(req.url);
    hash_data(req.http.host);
    
    # Include protocol in hash only if needed
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
    
    # More efficient logged-in user handling
    if (req.http.X-WP-Logged-In-Hash) {
        hash_data(req.http.X-WP-Logged-In-Hash);
    }
    return (lookup);
}

sub vcl_recv {
    # Normalize request first
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);
    
    # More efficient URL cleaning
    if (req.url ~ "[#\?]") {
        set req.url = regsub(req.url, "#.*$", "");
        set req.url = regsub(req.url, "\?$", "");
    }

    # Improved HTTPS redirect
    if (req.restarts == 0 && req.http.X-Forwarded-Proto !~ "(?i)https") {
        return (synth(750, req.url));
    }

    # More efficient parameter cleaning
    if (req.url ~ "[?&](utm_|fbclid|gclid|fb_|ga_|_ga|_gl)") {
        set req.url = regsuball(req.url, "(utm_|fbclid|gclid|fb_|ga_|_ga|_gl)[^&]+&?", "");
        set req.url = regsub(req.url, "(\?|&)$", "");
    }

    # Enhanced PURGE handling with better security
    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, "Not allowed"));
        }
        ban("obj.http.X-Purge-Host == " + req.http.host + " && obj.http.X-Purge-URL == " + req.url);
        return (synth(200, "Purged"));
    }

    # Improved bot detection
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider)") {
        if (req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
            return (synth(403, "Bot Access Denied"));
        }
    }

    # Progressive rate limiting
    if (vsthrottle.is_denied(client.ip, 200, 60s)) {
        if (vsthrottle.is_denied(client.ip, 300, 300s)) {
            # Extended ban for aggressive clients
            return (synth(429, "Too Many Requests"));
        }
        return (synth(429, "Rate Limited"));
    }

    # Optimized WordPress handling
    if (req.http.Cookie) {
        if (req.http.Cookie ~ "wordpress_logged_in_") {
            set req.http.X-WP-Logged-In-Hash = std.md5(req.http.Cookie);
        }
        
        # Bypass cache for dynamic content
        if (req.http.Cookie ~ "(wordpress_logged_in|wp_woocommerce_session|woocommerce_items_in_cart)") {
            return (pass);
        }
        unset req.http.Cookie;
    }

    # Enhanced static file caching
    if (req.url ~ "(?i)\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        return (hash);
    }

    # Improved grace mode
    set req.grace = 24h;

    # Optimized content negotiation
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") {
            unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else {
            unset req.http.Accept-Encoding;
        }
    }
}

sub vcl_backend_response {
    # Enhanced ESI processing
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
        set beresp.do_gzip = true;
    }

    # Improved static asset caching
    if (bereq.url ~ "\.(?i)(css|js|jpg|jpeg|png|gif|ico|gz|tgz|bz2|tbz|mp3|ogg|swf)$") {
        set beresp.ttl = 365d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        unset beresp.http.Set-Cookie;
        set beresp.http.Vary = "Accept-Encoding";
    } else {
        # Dynamic content caching
        set beresp.ttl = 4h;
        set beresp.grace = 24h;
        if (!beresp.http.Cache-Control) {
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # Enhanced security headers
    set beresp.http.Content-Security-Policy = 
        "default-src 'self'; script-src 'self' 'unsafe-eval' https://example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-ancestors 'none';";
    set beresp.http.Strict-Transport-Security = "max-age=31536000; includeSubDomains; preload";
    set beresp.http.X-Content-Type-Options = "nosniff";
    set beresp.http.X-Frame-Options = "DENY";
    set beresp.http.Referrer-Policy = "strict-origin-when-cross-origin";
    
    unset beresp.http.X-Powered-By;
    unset beresp.http.Server;

    # Compression optimization
    if (beresp.http.content-type ~ "text" || beresp.http.content-type ~ "application/json") {
        set beresp.do_gzip = true;
    }
}

sub vcl_deliver {
    # Security header cleanup
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    
    # Debug headers for trusted networks
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By = server.identity;
        set resp.http.X-Grace = req.grace;
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
    }

    call generate_error_page;
    return (deliver);
}
