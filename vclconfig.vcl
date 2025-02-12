vcl 4.1;

import std;
import directors;
import querystring;
import vsthrottle;

##############################################################################
# ACLs & VARIABLES
##############################################################################
acl purge {
    "localhost";
    "127.0.0.1";
    "192.168.1.100";  # Custom purge IPs
}

acl trusted_networks {
    "localhost";
    "127.0.0.1";
    "192.168.1.0/24";  # Adjust to your network
}

##############################################################################
# CUSTOM ERROR PAGE
##############################################################################
sub generate_error_page {
    set resp.http.Content-Type = "text/html; charset=utf-8";
    synthetic(    
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "  <head>"
        "    <meta charset=\"utf-8\">"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "    <title>[$resp.status] $resp.reason</title>"
        "    <style>"
        "      body { font-family: system-ui; line-height: 1.5; padding: 2rem; max-width: 45rem; margin: 0 auto; color: #333; }"
        "      h1 { color: #dc2626; margin-bottom: 1rem; font-size: 1.75rem; }"
        "      p { margin-bottom: 1rem; font-size: 1rem; }"
        "      .error-code { color: #6b7280; font-size: 0.875rem; }"
        "    </style>"
        "  </head>"
        "  <body>"
        "    <h1>Error [$resp.status]</h1>"
        "    <p>$resp.reason</p>"
        "    <p class=\"error-code\">Error Code: [$resp.status]</p>"
        "  </body>"
        "</html>"
    );
}

##############################################################################
# BACKEND PROBE
##############################################################################
probe backend_probe {
    .request =
        "HEAD /health HTTP/1.1"
        "Host: example.com"
        "Connection: close"
        "User-Agent: Varnish Health Probe"
        "Accept-Encoding: gzip";
    .interval = 5s;
    .timeout = 2s;
    .window = 5;
    .threshold = 3;
    .initial = 2;
    .expected_response = 200;
}

##############################################################################
# BACKEND DEFINITIONS
##############################################################################
backend default {
    .host = "192.168.1.50";
    .port = "8080";
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 60s;
    .connect_timeout = 5s;
    .max_connections = 800;
    .probe = backend_probe;
}

##############################################################################
# VCL INIT
##############################################################################
sub vcl_init {
    new cluster = directors.round_robin();
    cluster.add_backend(default);
    return (ok);
}

##############################################################################
# HASH FUNCTION
##############################################################################
sub vcl_hash {
    hash_data(req.url);
    if (req.http.host) { hash_data(req.http.host); }
    if (req.http.X-Forwarded-Proto) { hash_data(req.http.X-Forwarded-Proto); }
    if (req.http.X-Logged-In) { hash_data(req.http.X-Logged-In); }
    return (lookup);
}

##############################################################################
# CLIENT REQUEST PROCESSING (vcl_recv)
##############################################################################
sub vcl_recv {
    ##########################################
    # General Normalization
    ##########################################
    std.collect(req.http.Cookie);
    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    set req.url = std.querysort(req.url);
    set req.url = regsub(req.url, "#.*$", "");  
    set req.url = regsub(req.url, "\?$", ""); 
    set req.http.X-Forwarded-Proto = 
        (req.http.X-Forwarded-Proto ? 
         req.http.X-Forwarded-Proto : (std.port(server.ip) == 443 ? "https" : "http"));

    ##########################################
    # Cookie & Parameter Sanitization
    ##########################################
    unset req.http.Cookie;  
    if (req.url ? req.url ~ "(\?|&)(utm_|fbclid|gclid)=") {  
        set req.url = regsuball(req.url, "utm_[a-z]+=[-_A-Za-z0-9]+&?", "");
        set req.url = regsub(req.url, "\(.*\)", "");  
    }

    ##########################################
    # External PURGE Handling
    ##########################################
    if (req.method == "PURGE") {  
        if (client.ip ~ purge) {
            ban("obj.http.X-Purge-Host ~ " + req.http.host + 
                " && obj.http.X-Purge-URL ~ " + req.url);  
            return (synth(200, "Purged"));  
        } else {
            return (synth(405));  
        }
    }

    ##########################################
    # HTTPS Redirection (Adjust port if needed)
    ##########################################
    if (req.http.X-Forwarded-Proto != "https") {
        return (synth(750, req.url));
    }

    ##########################################
    # Bot Mitigation & Rate Limiting
    ##########################################
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider|libwww|wget|curl)" &&  
        !req.http.User-Agent ~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
        return (synth(403));  
    }
    if (vsthrottle.is_denied(client.ip, 200, 60s)) {
        return (synth(429, "Retries allowed in: " + vsthrottle.retry_after(client.ip)));  
    }

    ##########################################
    # Dynamic Request Bypass
    ##########################################
    if (req.url ~ "^/(cart|checkout|my-account|wc-(api|ajax))" ||  
        req.url ~ "\?(add-to-cart|wc-api)=" ||  
        req.http.Cookie ~ "wordpress_logged_in|woocommerce_") {
        return (pass);  
    }

    ##########################################
    # Content Negotiation Adjustments
    ##########################################
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gz|tgz|bz2|tbz|mp3|ogg|swf|mp4|flv)$") {
            unset req.http.Accept-Encoding;
        } elseif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } else {
            unset req.http.Accept-Encoding;
        }
    }

    ##########################################
    # Static Asset Optimization
    ##########################################
    if (req.url ~ "(\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xlsx|xml|xz|zip)(\?.*)?|^/$)")  {
        unset req.http.Cookie;
        set req.url = regsub(req.url, "\?.*$", "");
        return (hash);  
    }

    ##########################################
    # ESI Support & Modern Headers
    ##########################################
    set req.http.Surrogate-Capability = "key=ESI/1.0";
    if (req.restarts == 0) {
        set req.http.X-Forwarded-For = client.ip + ", " + req.http.X-Forwarded-For;
    }
    set req.grace = 60s;
}

##############################################################################
# BACKEND RESPONSE PROCESSING (vcl_backend_response)
##############################################################################
sub vcl_backend_response {
    ##########################################
    # ESI Processing
    ##########################################
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }

    ##########################################
    # TTL & Caching Logic
    ##########################################
    if (bereq.url ~ "\.(jpg|jpeg|png|gif|ico|webp|svg|css|js|woff2?)$") {
        set beresp.ttl = 30d;  
        set beresp.http.Cache-Control = "public, max-age=2592000, immutable";
        unset beresp.http.Set-Cookie;
        set beresp.http.Vary = "Accept-Encoding";
    } else {
        set beresp.ttl = 1d;  
        set beresp.grace = 6h;
        unset beresp.http.Set-Cookie;
    }

    ##########################################
    # Security & Hardening
    ##########################################
    set beresp.http.Content-Security-Policy = 
        "default-src 'self'; script-src 'self' 'unsafe-eval' https://example.com; object-src 'none'";
    unset beresp.http.X-Powered-By;

    ##########################################
    # Analytics & Observability
    ##########################################
    set beresp.http.X-Backend = beresp.backend.name;
    set beresp.http.X-CDN-Cache = obj.hits > 0 ? "HIT" : "MISS";
    set beresp.http.X-CDN-Cache-Hits = obj.hits;
}

##############################################################################
# DELIVERY (vcl_deliver)
##############################################################################
sub vcl_deliver {
    if (req.http.X-Forwarded-Proto != "https") {
        set resp.http.Location = "https://" + req.http.Host + req.url;
        set resp.status = 301;
        return (deliver);
    }

    unset resp.http.Server;
    unset resp.http.X-Powered-By;
    unset resp.http.Via;
    unset resp.http.X-Varnish;

    if (client.ip ~ trusted_networks) {
        set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";
        set resp.http.X-Cache-Hits = obj.hits;
        set resp.http.X-Served-By = server.identity;
    }

    if (obj.hits == 0) {
        set resp.http.X-CDN-Port = server.port;
    } else { 
        set resp.http.X-CDN-Pass = req.http.sticky;
    }
}

##############################################################################
# SYNTHETIC RESPONSES (vcl_synth)
##############################################################################
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

    if (resp.status == 301 || resp.status == 302) {
        set resp.http.Location = resp.reason;
        set resp.reason = (resp.status == 301) ? "Moved Permanently" : "Found";
        set resp.http.Content-Type = "text/plain";
        synthetic("Redirecting to: " + resp.http.Location);
        return (deliver);
    }

    call generate_error_page;
}

##############################################################################
# PURGE HANDLING
##############################################################################
sub vcl_purge {
    return (synth(200));
}
