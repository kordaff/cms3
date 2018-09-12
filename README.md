# cms3
This will be the 3rd iteration of my mod_perl2 response handler that acts as a CMS using Apache and PostgreSQL.


There's a link to TODO's for this module linked off home page for http://perl-user.com   

Updated the virtualhost section for my test domain, userconfig.cf

=========================
Sept 12th
  - added /fonts section so Bootstrap3 on the landing page could find them.
  - improved init script
  - modified api-add-page.txt template
  - got /page?edit working (it uses the /api/add_page template to produce a textarea to edit the page
  -   or create a new one, if it didn't exist
  - got posts to /api/add_page working to store what is added in the edit screen...   Helps =)
  - about 140+ additional lines in cms3.pm today
   
=========================
