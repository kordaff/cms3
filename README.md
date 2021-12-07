# cms3
This is the 3rd iteration of my mod_perl2 response handler that acts as a CMS using Apache and PostgreSQL.

This is version 3.2

Implemented: url?delete function to deactivate unwanted pages.  To fully remove the pages from the 
database, use psql cms3 cms3
Then, DELETE FROM pages where not active;

Voila, all the previous versions of pages are permanently gone (for now, might want to save them 
for historical purposes without them being available to roll back to (once implemented)

Also implemented /api/change_pw to change either the login password or delete password (delete takes
a separate password just for fun - considering setting a cookie for the duration of the session so 
it only needs to be entered once per browser session)

This version still needs a complete run through with perlcritic -brutal...

I'm just about to the point where a full install on Arch will be doable, more or less.  Getting 
postgres to run commands under su has proven problematic.  I'm probably doing something wrong =)

I've also begun to try and learn docker.  This app would just work in Docker I think.  It needs an
/api/add_domain, /api/delete_domain, and maybe a few others before that though.  /api/change_domain
would be pretty doable too.  I started using the ~~dom~~ snippet in my pages so when i switch the
domain, the pages work just fine on the new domain.  Need to do that with my.css too, had to change
a bunch of pages that were looking for that on cms3.perl-user.com which I deactivated/removed.

I rolled posts and pages from cms3.perl-user.com into perl-user.com and moved it over to cms3 from
the previous version, Lynk2.pm (at least it was properly cased lol - perlcritic doesn't like 
cms3.pm as a module name).

Current TODO list:  todo

