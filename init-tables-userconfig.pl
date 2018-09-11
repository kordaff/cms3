#!/usr/bin/perl
#
use strict;
use warnings;
use DBD::Pg;
use APR::UUID;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt);
use Crypt::Random;

my $dbh = DBI->connect("dbi:Pg:dbname=userconfig",'userconfig','',{AutoCommit=>1})or die $!;
my (@r,$r,$sth,$query);

my $password = 'admin';
my $encrypted = encrypt_password($password);
my $del_passwd = 'abc123';#so user can delete pages/notes/comments by same user 
my $encrypt_delpw = encrypt_password($del_passwd);

my $uuid  = APR::UUID->new->format;
my $user  = 'admin';
my $email = 'root\@perl-user.com';

###    $sth=$dbh->do("drop table pages,comments,notes,user_data,access_log,api_endpoints") or die $!;

$sth=$dbh->do("CREATE TABLE pages (body text,url text,domain text,creation_time timestamp without time zone,username text,useruuid uuid,remote_addr text,active boolean,version_num integer,id SERIAL PRIMARY KEY);") or die $!;

$sth=$dbh->do("CREATE TABLE comments (body text,url text,domain text,comment_time integer,remote_addr text,username text,useruuid uuid,id SERIAL PRIMARY KEY); ") or die $!;

$sth=$dbh->do("CREATE TABLE notes (body text,url text,domain text,note_time integer,remote_addr text,username text,useruuid uuid,id SERIAL PRIMARY KEY); ") or die $!;

$sth=$dbh->do("CREATE TABLE access_log (url text, domain text,method text,access_time timestamp without time zone,remote_ip text,refer text,user_agent text,created timestamp without time zone,id SERIAL PRIMARY KEY); ") or die $!;

$sth=$dbh->do("CREATE TABLE user_data (username text,useruuid uuid,email text,user_created timestamp without time zone,id SERIAL PRIMARY KEY,password TEXT,delete_password TEXT); ") or die $!;

$sth=$dbh->do("INSERT INTO user_data (username, useruuid, email, user_created, password,delete_password) values('$user','$uuid','$email',now(),'$encrypted','$encrypt_delpw')");
print "Created user $user with uuid = $uuid\n";

$sth=$dbh->do("CREATE TABLE api_endpoints (url text); ") or die $!;

$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/add_page'   )");
$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/add_comment')");
$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/add_note'   )");
$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/login'      )");
$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/register'   )");
$sth=$dbh->do("INSERT INTO api_endpoints(url) values ('/api/delete_page')");

my $body;
{
  local $/ = undef;
  open(FILE,'<','api-add-page.txt') or die $!;
  $body = <FILE>;
  close FILE;
}
$body =~ s/USERUUID/$uuid/;
$sth=$dbh->do("INSERT INTO pages (body,url,domain,creation_time,username,useruuid,remote_addr,active,version_num) values ('$body','/api/add_page','userconfig.cf',now(),'admin','$uuid','72.201.204.99',true,1)");
print "created page /api/add_page with useruuid = $uuid\n";

{
  local $/ = undef;
  open(FILE,'<','api-login.txt') or die $!;
  $body = <FILE>;
  close FILE;
}
$sth=$dbh->do("INSERT INTO pages (body,url,domain,creation_time,username,useruuid,remote_addr,active,version_num) values ('$body','/api/login','userconfig.cf',now(),'admin','$uuid','72.201.204.99',true,1)");
print "created page /api/login with useruuid = $uuid\n";


sub encrypt_password
  {
  my $password = shift;
  my $salt = shift || salt() ;
  my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash( {
            key_nul => 1,
            cost => 8,
            salt => $salt,
    }, $password);

  return join('-', $salt, Crypt::Eksblowfish::Bcrypt::en_base64($hash));
  }

sub salt
  {
  return Crypt::Eksblowfish::Bcrypt::en_base64(Crypt::Random::makerandom_octet(Length=>12));
  }

sub check_password
  {
  my ($password, $hash) = @_;
  my ($salt) = split('-', $hash, 2);
  return length $salt == 16 && encrypt_password($password, $salt) eq $hash;
  }
