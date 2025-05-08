# Moodle Serve Local Files Securely

A Moodle module used with Apache mod_rewrite to serve local files requiring Moodle Authentication 
Usage was to secure where hard links have been placed: 
eg: https://mydomain.moodle.com/media/pdfs/my.pdf

the Static files would live on the server somewhere like:
eg:
```bash
/mnt/nfs/media 
```



## Installation
install into the local directory of the moodle root:

```bash
[moodlewebroot]/local/securefiles 
```

You will need to set the location of where your files are  in the frontend of Moodle
## ModRewrite Rule to add to virtual 
Apache Server/Virtual Host Configuration: 
This is generally the best place for these rules. 
You'll need to restart or reload Apache after making changes.



```bash
RewriteEngine On

# Conditions: Only apply the rule if the request is not for an existing file or directory.
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d

# Rule:
# ^/nfs/(.*)$
#   ^                  : Matches the beginning of the path.
#   /nfs/    : Matches the literal string "/nfs/".
#                        The leading slash is typical for paths in server/vhost context.
#   (.*)               : Captures everything after "/workplace/nfs/" into the variable $1 (e.g., "test.pdf").
#
# /local/securefiles/serve.php?file=$1
#   This is the target path, relative to your DocumentRoot.
#   If DocumentRoot is /var/www/html, this resolves to /var/www/html/workplace/local/securefiles/serve.php.
#   file=$1            : Passes the captured filename as a GET parameter to your script.
#
# [L,QSA]
#   L                  : Last rule. If this rule matches, stop processing further rewrite rules.
#   QSA                : Query String Append. If the original URL had a query string, it's appended.
RewriteRule ^/?/nfs/(.*)$ /workplace/local/securefiles/serve.php?file=$1 [L,QSA]


```