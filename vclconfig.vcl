vcl 4.1;

import std;
import directors;
import querystring;
import vsthrottle;

acl purge {
    "localhost";
    "127.0.0.1";
    "192.168.1.100";
}

acl trusted_networks {
    "localhost";
    "127.0.0.1";
    "192.168.1.0/24";
}

// Custom Error Pages & CORS (unchanged)
sub generate_error_page {}
sub add_cors_headers {}

// Backend Probe Definition (unchanged)
probe backend_probe {
    .request = "HEAD /health HTTP/1.1" +
               "Host: _health" +
               "Connection: close" +
               "User-Agent: Varnish Health Probe";
    .interval = 5s;
    .timeout = 2s;
    .window = 5;
    .threshold = 3;
    .initial = 2;
    .expected_response = 200;
}

backend default {
    .host = "192.168.1.50";
    .port = "8080";
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 60s;
    .probe = backend_probe;
}

sub vcl_init {
    new cluster = directors.round_robin();
    cluster.add_backend(default);
    return (ok);
}

sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) {
        hash_data(req.http.host);
    }
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
    // Use pre-calculated cookie hash from recv
    if (req.http.X-WP-Logged-In-Hash) {
        hash_data(req.http.X-WP-Logged-In-Hash);
    }
    return (lookup);
}

sub vcl_recv {
    // Normalize host and URL first
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);
    set req.url = regsub(req.url, "#.*$", "");
    set req.url = regsub(req.url, "\?$", "");

    // Custom HTTPS redirect
    if (req.restarts == 0 && req.http.X-Forwarded-Proto !~ "(?i)https") {
        return (synth(750, req.url));
    }

    // Clean up tracking parameters
    if (req.url ~ "(\?|&)(utm_|fbclid|gclid)=") {
        set req.url = regsuball(req.url, "utm_[a-z]+=[-_A-Za-z0-9]+&?", "");
        set req.url = regsub(req.url, "\?&?$", "");
    }

    // PURGE handling
    if (req.method == "PURGE") {
        if (client.ip ~ purge) {
            ban("obj.http.X-Purge-Host ~ " + req.http.host + " && obj.http.X-Purge-URL ~ " + req.url);
            return (synth(200, "Purged"));
        }
        return (synth(405));
    }

    // Bot mitigation
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider|libwww|wget|curl)" &&
        req.http.User-Agent !~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
        return (synth(403));
    }

    // Rate limiting
    if (vsthrottle.is_denied(client.ip, 200, 60s)) {
        return (synth(429));
    }

    // Pre-process cookies for logged-in users before unsetting
    if (req.http.Cookie) {
        // Capture WordPress login state before removing cookies
        if (req.http.Cookie ~ "wordpress_logged_in_") {
            set req.http.X-WP-Logged-In-Hash = std.md5(req.http.Cookie);
        }
        // Bypass cache for dynamic sessions
        if (req.http.Cookie ~ "(wordpress_logged_in|wp_woocommerce_session_|woocommerce_items_in_cart)") {
            return (pass);
        }
    }

    // Bypass dynamic requests
    if (req.url ~ "^/(cart|checkout|my-account|wp-admin|wp-login\.php|wc-(api|ajax))" ||
        req.url ~ "\?(add-to-cart|remove_item|variable)=") {
        return (pass);
    }

    // Remove cookies for cacheable requests
    unset req.http.Cookie;

    // Optimize static assets
    if (req.url ~ "^[^?]+\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svgz?|swf|tar|tbz|tgz|ttf|txt|txz|wav|web[mp]|woff2?|xlsx|xml|xz|zip)(\?.*)?$") {
        set req.url = regsub(req.url, "\?.*$", "");
        return (hash);
    }

    // Grace handling
    set req.grace = 60s;

    // Content negotiation
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gz|tgz|bz2|tbz|mp3|ogg|swf|mp4|flv)$") {
            unset req.http.Accept-Encoding;
        } else if (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else {
            unset req.http.Accept-Encoding;
        }
    }
}

sub vcl_backend_response {
    // ESI processing
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }

    // Static asset caching
    if (bereq.url ~ "\.(jpe?g|png|gif|ico|webp|svg|css|js|woff2?)$") {
        set beresp.ttl = 90d;
        set beresp.http.Cache-Control = "public, max-age=7776000, immutable";
        unset beresp.http.Set-Cookie;
        set beresp.http.Vary = "Accept-Encoding";
    } else {
        set beresp.ttl = 2d;
        set beresp.grace = 12h;
        unset beresp.http.Set-Cookie;
    }

    // Security headers
    set beresp.http.Content-Security-Policy = 
        "default-src 'self'; script-src 'self' 'unsafe-eval' https://example.com; object-src 'none';";
    unset beresp.http.X-Powered-By;
    set beresp.http.Referrer-Policy = "no-referrer-when-downgrade";
    set beresp.http.X-Content-Type-Options = "nosniff";
    set beresp.http.X-Frame-Options = "DENY";

    // Aggressive caching
    set beresp.uncacheable = false;
}

sub vcl_deliver {
    // Header cleanup
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;

    // Trusted network diagnostics
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By = server.identity;
    }

    call add_cors_headers;
}

sub vcl_synth {
    if (resp.status == 750) {
        set resp.status = 301;
        set resp.http.Location = "https://" + req.http.Host + resp.reason;
        set resp.reason = "Moved Permanently";
        return (deliver);
    }

    if (resp.status == 429) {
        set resp.http.Retry-After = "60";
    }

    call generate_error_page;
    call add_cors_headers;
}

sub vcl_purge {
    return (synth(200));
}
