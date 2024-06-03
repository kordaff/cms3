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

Current TODO list:  todo

