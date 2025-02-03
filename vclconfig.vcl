vcl 4.1;
import std;
import directors;
import querystring;      # Advanced query string filtering VMOD
import vsthrottle;

###############################################################################
# ACLs & VARIABLES
###############################################################################
acl purge {
    "localhost";
    "127.0.0.1";
    "192.168.1.100";   // REPLACE with your actual purge IP(s)
}

acl trusted_networks {
    "localhost";
    "127.0.0.1";
    "192.168.1.0/24";  // Adjust for your trusted networks
}

###############################################################################
# CUSTOM ERROR PAGE
###############################################################################
sub generate_error_page {
    set resp.http.Content-Type = "text/html; charset=utf-8";
    synthetic ({"<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>"} + resp.status + " " + resp.reason + {"</title>
  <style>
    body { font-family: -apple-system, system-ui, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", sans-serif; line-height: 1.5; padding: 2rem; max-width: 45rem; margin: 0 auto; color: #333; }
    h1 { color: #e53e3e; margin-bottom: 1rem; }
    hr { border: 0; border-top: 1px solid #eee; margin: 2rem 0; }
    .error-code { color: #718096; font-size: 0.875rem; }
  </style>
</head>
<body>
  <h1>Error "} + resp.status + {"</h1>
  <p>"} + resp.reason + {"</p>
  <hr>
  <p class=\"error-code\">Error Code: "} + resp.status + {"</p>
</body>
</html>
"});
}

###############################################################################
# BACKEND DEFINITIONS
###############################################################################
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

backend default {
    .host = "192.168.1.50";  // Adjust to your content server
    .port = "8080";          // Adjust as needed
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 60s;
    .connect_timeout = 5s;
    .max_connections = 800;
    .probe = backend_probe;
}

###############################################################################
# VCL INIT
###############################################################################
sub vcl_init {
    new cluster = directors.round_robin();
    cluster.add_backend(default);
    /* Optionally load extra runtime files (e.g. blacklists, device detection) */
    new blacklist = std.file("/etc/varnish/blacklist.vcl", "text");
    new device_detect = std.file("/etc/varnish/device_detect.vcl", "text");
}

###############################################################################
# HASH FUNCTION (REQUIRED)
###############################################################################
sub vcl_hash {
    if (req.http.Cookie-Backup) {
        set req.http.Cookie = req.http.Cookie-Backup;
        unset req.http.Cookie-Backup;
    }
    if (req.http.Cookie) { hash_data(req.http.Cookie); }
    if (req.http.X-Forwarded-Proto) { hash_data(req.http.X-Forwarded-Proto); }
    if (req.http.host) { hash_data(req.http.host); } else { hash_data(server.ip); }
    /* Canonicalize URL by stripping any query string */
    set req.http.ccsuri = regsub(req.url, "\?.*$", "");
    hash_data(req.http.ccsuri);
    if (req.http.X-Logged-In) { hash_data(req.http.X-Logged-In); }
    return (lookup);
}

###############################################################################
# BACKEND FETCH / MISS
###############################################################################
sub vcl_miss { 
    return (fetch); 
}
sub vcl_backend_fetch { 
    return (fetch); 
}

###############################################################################
# CLIENT REQUEST PROCESSING (vcl_recv)
###############################################################################
sub vcl_recv {
    ##########################################
    # LetsEncrypt Certbot Passthrough
    ##########################################
    if (req.url ~ "^/\\.well-known/acme-challenge/") {
        return (pass);
    }

    ##########################################
    # URL & Header Normalization
    ##########################################
    std.collect(req.http.Cookie);
    if (req.url ~ "#") { set req.url = regsub(req.url, "#.*", ""); }
    if (req.url ~ "\?$") { set req.url = regsub(req.url, "\?$", ""); }
    if (req.http.Host) { set req.http.Host = regsub(req.http.Host, ":[0-9]+", ""); }
    set req.url = std.querysort(req.url);
    if (req.url ~ "(\?|&)(_bta_[a-z]+|cof|cx|fbclid|gclid|ie|mc_[a-z]+|origin|siteurl|utm_[a-z]+|zanpid)=") {
         set req.url = regsuball(req.url, "(_bta_[a-z]+|cof|cx|fbclid|gclid|ie|mc_[a-z]+|origin|siteurl|utm_[a-z]+|zanpid)=[-_A-Za-z0-9+()%.]+&?", "");
         set req.url = regsub(req.url, "[?|&]+$", "");
    }
    if (req.url ~ "(?i)nocache=1") { return (pass); }

    ##########################################
    # PURGE Requests
    ##########################################
    if (req.method == "PURGE") {
        if (client.ip !~ purge) { 
            return (synth(405, "Not allowed."));
        }
        ban("req.url ~ " + req.url + " && req.http.Host == " + req.http.Host);
        if (req.method != "PURGE") {
            set req.http.X-Purge = "Yes";
            return (restart);
        }
        return (synth(200, "Purged"));
    }

    ##########################################
    # HTTPS Redirection (if on insecure port)
    ##########################################
    if (std.port(server.ip) == 6080) {
        set req.http.x-redir = "https://" + req.http.Host + req.url;
        return (synth(301, req.http.x-redir));
    }

    ##########################################
    # Security & Bot Protection
    ##########################################
    if (req.http.User-Agent ~ "(?i)(bot|crawl|slurp|spider|libwww|wget|curl)" &&
        !req.http.User-Agent ~ "(?i)(googlebot|bingbot|yandex|baiduspider)") {
        return (synth(403, "Bot Access Denied"));
    }
    if (vsthrottle.is_denied(client.identity, 200, 60s)) {
        return (synth(429, "Too Many Requests"));
    }

    ##########################################
    # Forwarding & Backend Selection
    ##########################################
    set req.backend_hint = cluster.backend();
    set req.http.X-Real-IP = client.ip;
    if (req.http.X-Forwarded-For) {
         set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
    } else {
         set req.http.X-Forwarded-For = client.ip;
    }
    set req.http.X-Forwarded-Proto = "https";

    ##########################################
    # Method & Authorization Check
    ##########################################
    if (req.method != "GET" && req.method != "HEAD") { return (pass); }
    if (req.http.Authorization) { return (pass); }

    ##########################################
    # Accept-Encoding Adjustment
    ##########################################
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf|mp4|flv)$") {
            remove req.http.Accept-Encoding;
        } elseif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } elseif (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            remove req.http.Accept-Encoding;
        }
    }

    ##########################################
    # CMS & Dynamic Content Optimizations
    ##########################################
    if (req.method == "GET" &&
        (req.url ~ "^/(shop|product|category|tag|archive|blog|page|search|wp-json|feed)") &&
        req.url !~ "\?add-to-cart=" &&
        req.url !~ "wc-ajax|get_refreshed_fragments" &&
        req.url !~ "(cart|checkout|my-account|wc-api|resetpass|wp-admin|xmlrpc.php|customer-area|addons)") {
        if (req.url ~ "^/wp-json/wp/v2/users/me") { return (pass); }
        if (req.http.Cookie ~ "wordpress_logged_in") {
            if (req.http.Cookie ~ "user_roles=") {
                set req.http.X-User-Roles = regsub(req.http.Cookie, "^.*?user_roles=([^;]+);*.*$", "\1");
            } else {
                set req.http.X-User-Roles = "loggedin";
            }
            set req.http.X-Logged-In = "true";
            set req.http.Cookie-Backup = req.http.Cookie;
            unset req.http.Cookie;
        } else if (req.http.Cookie) {
            if (req.http.Cookie ~ "user_roles=") {
                set req.http.X-User-Roles = regsub(req.http.Cookie, "^.*?user_roles=([^;]+);*.*$", "\1");
            } else {
                set req.http.X-User-Roles = "guest";
            }
            set req.http.Cookie-Backup = req.http.Cookie;
            unset req.http.Cookie;
        }
    }
    if (req.method == "GET" &&
        req.url ~ "admin-ajax.php" &&
        !req.http.Cookie ~ "wordpress_logged_in") {
        return (lookup);
    }

    ##########################################
    # Cookie & Tracking Cleanup
    ##########################################
    set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\\s*)(__[a-z]+|has_js)=[^;]*", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "__utm\\w+=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_gat=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "utmccn=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "__qc\\w+=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "__atuv\\w*=[^;]+(; )?", "");
    set req.http.Cookie = regsub(req.http.Cookie, "^;\\s*", "");
    if (req.http.Cookie ~ "^\s*$") { unset req.http.Cookie; }

    ##########################################
    # Static Assets Handling
    ##########################################
    if (req.url ~ "^[^?]*\\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpe?g|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\\?.*)?$") {
        unset req.http.Cookie;
        if (querystring.exists(req.url)) {
            set req.url = querystring.remove(req.url);
        } else {
            set req.url = regsub(req.url, "\\?.*$", "");
        }
        return (hash);
    }

    ##########################################
    # CMS-Specific Bypass for Sensitive Endpoints
    ##########################################
    if (req.url ~ "(wp-(login|admin)|wc-ajax|get_refreshed_fragments|cart|checkout|my-account|wc-api|resetpass|xmlrpc.php|customer-area|preview=true)") {
        return (pass);
    }
    if (req.http.Cookie && req.http.Cookie ~ "(wordpress_|wp-settings-)") {
        if (req.url ~ "(cart|checkout|my-account|wc-api|resetpass|wp-admin|xmlrpc.php)") {
            return (pass);
        } else {
            if (req.http.Cookie ~ "user_roles=") {
                set req.http.X-User-Roles = regsub(req.http.Cookie, "^.*?user_roles=([^;]+);*.*$", "\1");
            } else {
                set req.http.X-User-Roles = "loggedin";
            }
            set req.http.X-Logged-In = "true";
            set req.http.Cookie-Backup = req.http.Cookie;
            unset req.http.Cookie;
        }
    } else {
        unset req.http.Cookie;
    }

    ##########################################
    # Query String Filtering & Sorting
    ##########################################
    set req.url = querystring.filter_except(req.url,
        "sort"          + querystring.filtersep() +
        "q"             + querystring.filtersep() +
        "dom"           + querystring.filtersep() +
        "dedupe_hl"     + querystring.filtersep() +
        "filter"        + querystring.filtersep() +
        "attachment"    + querystring.filtersep() +
        "attachment_id" + querystring.filtersep() +
        "author"        + querystring.filtersep() +
        "author_name"   + querystring.filtersep() +
        "cat"           + querystring.filtersep() +
        "calendar"      + querystring.filtersep() +
        "category_name" + querystring.filtersep() +
        "comments_popup"+ querystring.filtersep() +
        "cpage"         + querystring.filtersep() +
        "day"           + querystring.filtersep() +
        "error"         + querystring.filtersep() +
        "exact"         + querystring.filtersep() +
        "exclude"       + querystring.filtersep() +
        "feed"          + querystring.filtersep() +
        "hour"          + querystring.filtersep() +
        "m"             + querystring.filtersep() +
        "minute"        + querystring.filtersep() +
        "monthnum"      + querystring.filtersep() +
        "more"          + querystring.filtersep() +
        "name"          + querystring.filtersep() +
        "order"         + querystring.filtersep() +
        "orderby"       + querystring.filtersep() +
        "p"             + querystring.filtersep() +
        "page_id"       + querystring.filtersep() +
        "page"          + querystring.filtersep() +
        "paged"         + querystring.filtersep() +
        "pagename"      + querystring.filtersep() +
        "pb"            + querystring.filtersep() +
        "post_type"     + querystring.filtersep() +
        "posts"         + querystring.filtersep() +
        "preview"       + querystring.filtersep() +
        "q"             + querystring.filtersep() +
        "robots"        + querystring.filtersep() +
        "s"             + querystring.filtersep() +
        "search"        + querystring.filtersep() +
        "second"        + querystring.filtersep() +
        "sentence"      + querystring.filtersep() +
        "static"        + querystring.filtersep() +
        "subpost"       + querystring.filtersep() +
        "subpost_id"    + querystring.filtersep() +
        "taxonomy"      + querystring.filtersep() +
        "tag"           + querystring.filtersep() +
        "tb"            + querystring.filtersep() +
        "tag_id"        + querystring.filtersep() +
        "term"          + querystring.filtersep() +
        "url"           + querystring.filtersep() +
        "w"             + querystring.filtersep() +
        "withcomments"  + querystring.filtersep() +
        "withoutcomments" + querystring.filtersep() +
        "year"
    );
    if (req.url ~ "\?") { set req.url = querystring.sort(req.url); }

    ##########################################
    # WebSocket & HTTP Method Handling
    ##########################################
    if (req.http.Upgrade && req.http.Upgrade ~ "(?i)websocket") { return (pipe); }
    if (req.method != "GET" && req.method != "HEAD") { return (pass); }
    if (req.http.Authorization) { return (pass); }

    ##########################################
    # ESI Support & Final X-Forwarded-For Update
    ##########################################
    set req.http.Surrogate-Capability = "key=ESI/1.0";
    if (req.restarts == 0) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        } else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }
    set req.grace = 60s;
    return (hash);
}

###############################################################################
# HASHING (vcl_hash)
###############################################################################
sub vcl_hash {
    if (req.http.Cookie-Backup) {
        set req.http.Cookie = req.http.Cookie-Backup;
        unset req.http.Cookie-Backup;
    }
    if (req.http.Cookie) { hash_data(req.http.Cookie); }
    if (req.http.x-forwarded-proto) { hash_data(req.http.x-forwarded-proto); }
    if (req.http.host) { hash_data(req.http.host); } else { hash_data(server.ip); }
    set req.http.ccsuri = regsub(req.url, "\?.*$", "");
    hash_data(req.http.ccsuri);
    if (req.http.X-Logged-In) { hash_data(req.http.X-Logged-In); }
    return;
}

###############################################################################
# BACKEND RESPONSE PROCESSING (vcl_backend_response)
###############################################################################
sub vcl_backend_response {
    if (beresp.http.Surrogate-Control && beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }
    if (bereq.http.X-User-Roles) {
        if (!beresp.http.Vary) { set beresp.http.Vary = "x-user-roles"; }
        else if (beresp.http.Vary !~ "x-user-roles") { set beresp.http.Vary = beresp.http.Vary + ", x-user-roles"; }
    }
    if (std.integer(beresp.http.Content-Length, 0) > 10485760) {
        set beresp.do_stream = true;
        set beresp.uncacheable = true;
    }
    if (bereq.url ~ "(?i)\\.(jpg|jpeg|png|gif|ico|webp|svg|css|js|woff2?)$") {
        set beresp.ttl = 7d;
        set beresp.http.Cache-Control = "public, max-age=604800";
        set beresp.http.Vary = "Accept-Encoding";
        unset beresp.http.Set-Cookie;
    } else {
        if (!(bereq.url ~ "(?i)wp-(login|admin)|cart|checkout|my-account|wc-api|resetpass") &&
            !beresp.http.Set-Cookie) {
            unset beresp.http.Set-Cookie;
            if (bereq.http.X-Logged-In) { 
                set beresp.ttl = 2h; 
                set beresp.grace = 1h; 
            } else {
                if (bereq.url ~ "^/article/") { 
                    set beresp.ttl = 5m; 
                } else { 
                    set beresp.ttl = 45m; 
                }
                set beresp.grace = 6h;
            }
        }
        if (beresp.status == 301 || beresp.status == 302) {
            set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
        }
    }
    if (beresp.http.Cache-Control !~ "max-age" || beresp.http.Cache-Control ~ "max-age=0") {
        set beresp.http.Cache-Control = "public, max-age=180, stale-while-revalidate=360, stale-if-error=43200";
    }
    if (beresp.ttl <= 0s || beresp.http.Set-Cookie || beresp.http.Vary == "*") {
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
        return (deliver);
    }
    if (beresp.status >= 500 && beresp.status < 600) { return (abandon); }
    set beresp.grace = 6h;
    return (deliver);
}

###############################################################################
# DELIVERY (vcl_deliver)
###############################################################################
sub vcl_deliver {
    if (obj.hits > 0) { set resp.http.X-Cache = "HIT"; }
    else { set resp.http.X-Cache = "MISS"; }
    set resp.http.X-Cache-Hits = obj.hits;
    if (req.http.X-User-Roles) { set resp.http.X-User-Roles = req.http.X-User-Roles; }
    if (req.http.sticky) {
        if (!resp.http.Set-Cookie) { set resp.http.Set-Cookie = ""; }
        set resp.http.Set-Cookie = "ccsvs=ccs" + req.http.sticky + "; Expires=" + (now + 10d) + ";" + resp.http.Set-Cookie;
    }
    unset resp.http.X-Powered-By;
    unset resp.http.X-Drupal-Cache;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
    unset resp.http.X-Generator;
    set resp.http.Timing-Allow-Origin = "*";
    return (deliver);
}

###############################################################################
# SYNTHETIC RESPONSES (vcl_synth)
###############################################################################
sub vcl_synth {
    if (resp.status == 301 || resp.status == 302) {
        set resp.http.Location = resp.reason;
        set resp.reason = "Redirecting...";
        call generate_error_page;
        return (deliver);
    } else if (resp.status == 720) {
        set resp.http.Location = resp.reason;
        set resp.status = 301;
        return (deliver);
    } else if (resp.status == 721) {
        set resp.http.Location = resp.reason;
        set resp.status = 302;
        return (deliver);
    } else if (resp.status == 8201) {
        set resp.http.Access-Control-Allow-Origin = "*";
        set resp.http.Content-Type = "text/plain";
        synthetic(resp.reason);
        return (deliver);
    }
    if (resp.status == 429) { set resp.http.Retry-After = "60"; }
    call generate_error_page;
    return (deliver);
}

###############################################################################
# PURGE HANDLING (vcl_purge)
###############################################################################
sub vcl_purge {
    if (req.method != "PURGE") {
        set req.http.X-Purge = "Yes";
        return (restart);
    }
    return (synth(200, "Purged"));
}

###############################################################################
# PIPE & PASS MODES
###############################################################################
sub vcl_pipe {
    set bereq.http.Connection = "close";
    if (req.http.upgrade) { set bereq.http.upgrade = req.http.upgrade; }
    return (pipe);
}
sub vcl_pass { return (pass); }

###############################################################################
# (Optional) VCL_HIT for handling stale content
###############################################################################
sub vcl_hit {
    /* If the cached object is fresh, deliver it. Otherwise, if it is stale but within grace, deliver stale content. */
    if (obj.ttl >= 0s) { return (deliver); }
    if (std.healthy(req.backend_hint)) {
        if (obj.ttl + 10s > 0s) { return (deliver); }
    } else {
        if (obj.ttl + obj.grace > 0s) { return (deliver); }
    }
    return (miss);
}

###############################################################################
# (Optional) VCL_BACKEND_ERROR for serving a custom error page if backend is down
###############################################################################
sub vcl_backend_error {
    if (beresp.status == 503 && bereq.retries == 3) {
        synthetic(std.fileread("/etc/varnish/error503.html"));
        return (deliver);
    }
}

###############################################################################
# VCL FINI
###############################################################################
sub vcl_fini { return (ok); }
