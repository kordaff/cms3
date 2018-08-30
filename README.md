# cms3
This will be the 3rd iteration of my mod_perl2 response handler that acts as a CMS using Apache and PostgreSQL.


There's a link to TODO's for this module linked off home page for http://perl-user.com   Shorter links are better...

Updated the virtualhost section for my test domain, userconfig.cf

Now http://userconfig.cf spits out a time string.
http://userconfig.cf/?debug shows a few debug variables including the dbh hash
that stays the same when getting the same httpd process PID.
This httpd.conf also includes the missing line to make the database connection
persistant and to allow the dbname and dbuser to be hardcoded into the httpd.conf, letting cms3.pm be a little more portable/drop-in.
