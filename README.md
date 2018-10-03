# cms3
This is the 3rd iteration of my mod_perl2 response handler that acts as a CMS using Apache and PostgreSQL.


This commit version includes recent work on /api/login /api/logout etc
It also includes /api/register but I've left it disabled until other features are added.

I did notice a problem with my load-X.pl scripts.  I switched the two scripts to replace the UUID 
and DOMAIN tags with the configured user's uuid and the site domain in the init script.
Side effect, now the load-X.pl scripts need to find the uuid and domain and update the /api/X too

I will test out a idea I have to fix that on my next Arch test install.
The scripts should fix $body for each domain in the database.  Really need a domains table, perhaps
with each domain having a different user?   /api/delegate-domain, /api/add_domain come to mind.

And for a domain owner: /api/delegate-page-rw

New ideas for my TODO list on http://userconfig.cf/


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


