package MyApache2::cms3;
# starting with a very barebones response handler
# plus a couple extra modules I know it'll be using.

use strict;
use warnings;

use Apache2::RequestRec ();
use Apache2::RequestIO ();
use Apache2::Const qw(OK NOT_FOUND REDIRECT FORBIDDEN);
use APR::Table ();
use APR::UUID;
use DBD::Pg;
use DateTime;
use URI::Escape::XS qw/uri_escape uri_unescape/;
use Encode;
use utf8;  
use CGI qw/:standard/;
use CGI::Cookie;


sub handler
  {
  my $r = shift;
  $r->content_type('text/plain');
  $r->print("Now is: " . scalar(localtime) . "\n");
  return Apache2::Const::OK;
  }
1;
