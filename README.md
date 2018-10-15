# cms3
This is the 3rd iteration of my mod_perl2 response handler that acts as a CMS using Apache and PostgreSQL.


This commit version has a lot of changes.  Different dbname and dbuser as I had
someone suspend my domain, userconfig.cf   No notice, no warning.  All I do on
it is post notes about what I'm working on with cms3...  It must have been tasty
for someone to pull that.  No more using free domains from dot.tk for me.

So, new dbuser and dbname are cms3   Test domain is at cms3.perl-user.com
I changed the example httpd.conf with the new variables.

This is a pretty major increase of code, including a full rework and refactor
of my store_page subroutine.   It shouldn't stomp on version_num for a 
particular page now, even when the active page is rolled back to a previous 
version.

There was also a lot of changes to the database requiring a lot of queries to 
become multi table queries.   The database is normalized quite a bit better.
There is also a valid_domains table that gets initialized with the domain name
specified in init-tables.pl and a domain of 'ALL' for /api urls.   Most 
specifically, /api/login and /api/add_page get __DOMAIN__ tags replace with the current domain being accessed.

I will test out a idea I have to fix that on my next Arch test install.
The scripts should fix $body for each domain in the database.  Really need a domains table, perhaps
with each domain having a different user?   /api/delegate-domain, /api/add_domain come to mind.

And for a domain owner: /api/delegate-page-rw

New ideas for my TODO list on http://cms3.perl-user.com/


When installing, after httpd starts up with no errors in error_log, try these:

To Edit A URL (except /api/* as those urls are handled differently)
http://your-ip-or-domain/?edit

To Login As admin with password admin (can/should be changed in init script before installing)
http://your-ip-or-domain/api/login

To Verify Your Cookies:
http://your-ip-or-domain/api/show_my_cookies

To Logout:
http://your-ip-or-domain/api/logout

To Delete All The Cookies:
http://your-ip-or-domain/api/show_my_cookies


