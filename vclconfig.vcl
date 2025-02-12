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
import xkey;      # New for selective purging
import bodyaccess; # New for response body manipulation
import cookie;    # New for advanced cookie handling
import vtc;       # New for testing support

# Memory management tuning
# -p workspace_client=256k
# -p workspace_backend=256k
# -p thread_pool_min=200
# -p thread_pool_max=4000
# -p thread_pool_timeout=300
# -p thread_pools=2
# -p pcre_match_limit=10000
# -p pcre_match_limit_recursion=10000

# Optimized ACLs with specific CIDR ranges
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

# Multi-layer health checks
probe tcp_probe {
    .window = 10;
    .initial = 4;
    .threshold = 6;
    .interval = 2s;
    .timeout = 1s;
}

probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: _health"
        "Connection: close"
        "User-Agent: Varnish Health Probe";
    .interval = 2s;
    .timeout = 1s;
    .window = 10;
    .threshold = 6;
    .initial = 4;
    .expected_response = 200;
    .match_pattern = "OK";
    .threshold = 3;
}

# Advanced backend configuration
backend default {
    .host = "192.168.1.50";
    .port = "8080";
    .first_byte_timeout = 60s;      # Reduced for faster failing
    .between_bytes_timeout = 15s;    # Reduced for better responsiveness
    .max_connections = 1000;         # Increased for higher concurrency
    .probe = backend_probe;
    
    # Optimized TCP settings
    .tcp_keepalive_time = 180;      # Reduced for faster connection reuse
    .tcp_keepalive_probes = 4;
    .tcp_keepalive_intvl = 20;
    .connect_timeout = 1s;          # Quick fail for connection issues
    
    # Advanced connection pooling
    .min_pool_size = 50;           # Minimum idle connections
    .max_pool_size = 500;          # Maximum connection pool size
    .pool_timeout = 30s;           # Connection pool timeout
}

# Initialization with advanced director setup
sub vcl_init {
    # Advanced sharding with warmup
    new cluster = shard.director(
        {
            .backend = default;
            .by_hash = true;           # Use consistent hashing
            .warmup = 15s;             # Warmup period
            .rampup = 45s;             # Ramp-up period
            .retries = 5;              # Number of retries
            .skip_gone = true;         # Skip unavailable backends
            .healthy_threshold = 2;     # Number of healthy probes
        }
    );
    
    # Progressive rate limiting
    new throttle = vsthrottle.rate_limit(
        .max_rate = 250,              # Increased base rate
        .duration = 60,
        .burst = 75,                  # Increased burst allowance
        .penalty_box = 300            # Time in penalty box
    );
    
    # Optimized TCP pool
    new pool = tcp.pool(
        .max_connections = 2500,      # Increased max connections
        .min_connections = 200,       # Increased min connections
        .idle_timeout = 180,          # Reduced idle timeout
        .connect_timeout = 0.5        # Quick connection timeout
    );
    
    return (ok);
}

# Optimized hash function
sub vcl_hash {
    # Efficient composite key hashing
    hash_data(blob.encode(req.url + req.http.host + req.http.X-Device-Type, blob.BASE64));
    
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }
    
    # User-specific caching
    if (req.http.X-User-ID) {
        hash_data(req.http.X-User-ID);
    }
    
    return (lookup);
}

# Advanced hit-for-pass object handling
sub vcl_hit {
    if (obj.ttl >= 0s) {
        return (deliver);
    }
    
    if (obj.ttl + obj.grace > 0s) {
        return (deliver);
    }
    
    return (miss);
}

sub vcl_recv {
    # Optimized TCP handling
    if (tcp.is_idle(client.socket)) {
        if (req.url ~ "\.(mp4|mkv|iso)$") {
            tcp.set_socket_pace(client.socket, 2MB);
        } else {
            tcp.set_socket_pace(client.socket, 150KB);
        }
    }

    # Request normalization
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);
    
    # Efficient URL cleaning
    if (req.url ~ "[#\?]") {
        set req.url = chunk.replace(req.url, "[#\?].*$", "");
    }

    # Device detection for caching
    if (req.http.User-Agent) {
        if (req.http.User-Agent ~ "(?i)mobile|android|iphone|ipod|tablet") {
            set req.http.X-Device-Type = "mobile";
        } else {
            set req.http.X-Device-Type = "desktop";
        }
    }

    # Advanced parameter cleaning
    if (req.url ~ "[?&](utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_|campaign_|medium_|term_)") {
        set req.url = chunk.replace(req.url, "(utm_|fbclid|gclid|fb_|ga_|_ga|_gl|ref_|source_|campaign_|medium_|term_)[^&]+&?", "");
        set req.url = chunk.replace(req.url, "(\?|&)$", "");
    }

    # Selective purging with xkey
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
            # Advanced bot verification
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
}

sub vcl_backend_response {
    # Advanced ESI handling
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
        set beresp.ttl = 365d;
        set beresp.grace = 7d;
        set beresp.keep = 7d;
        set beresp.http.Cache-Control = "public, max-age=31536000, immutable";
        set beresp.http.Vary = "Accept-Encoding";
        
        # Streaming for large files
        if (std.integer(beresp.http.Content-Length, 0) > 5242880) {
            set beresp.do_stream = true;
            set beresp.http.X-Stream = "true";
        }
        
        # Compression optimization
        if (beresp.http.content-type ~ "text" || 
            beresp.http.content-type ~ "application/(javascript|json|xml)") {
            if (std.integer(beresp.http.Content-Length, 0) > 860) {
                set beresp.do_gzip = true;
            }
        }
    } else {
        # Dynamic content handling
        if (!beresp.http.Cache-Control) {
            set beresp.ttl = 4h;
            set beresp.grace = 24h;
            set beresp.keep = 24h;
            set beresp.http.Cache-Control = "public, max-age=14400";
        }
    }

    # Error handling
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
            if (std.integer(beresp.http.Content-Length, 0) > 102400) {
                set beresp.do_stream = true;
            }
        }
    }
}

sub vcl_deliver {
    # Performance headers cleanup
    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    
    # Debug info for trusted networks
    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By = server.hostname;
        set resp.http.X-Pool = req.backend_hint;
        set resp.http.X-Grace = req.grace;
        if (resp.http.X-Stream) {
            set resp.http.X-Stream-Size = beresp.http.Content-Length;
        }
        if (obj.hits > 0) {
            set resp.http.X-Age = obj.age;
        }
    }
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
        set resp.http.X-RateLimit-Limit = "250";
    }

    call generate_error_page;
    return (deliver);
}
