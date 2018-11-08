#!/usr/bin/perl
#
use strict;
use warnings;
use DBD::Pg;

my $dbh = DBI->connect("dbi:Pg:dbname=cms3",'cms3','',{AutoCommit=>1})or die $!;
my (@row,$sth,$query);
my $t     = time;

my $body;
{
  local $/ = undef;
  open(FILE,'<','api-delete-page.txt') or die $!;
  $body = <FILE>;
  close FILE;
}

$sth=$dbh->prepare("SELECT id from valid_domains where domain=?")or die $!;
$sth->execute('ALL');
@row=$sth->fetchrow_array;
my $domain_id=$row[0];

$sth=$dbh->prepare("SELECT url,active,id FROM pages where url=?")or die $!;
$sth->execute('/api/delete_page');
@row=$sth->fetchrow_array;
if ($#row <0)
  {
  $sth = $dbh->do( "INSERT INTO pages (body,url,domain_id,creation_time,userid,remote_addr,active,version_num) values ('$body','/api/delete_page','$domain_id','$t',1,'72.201.204.99','TRUE',1)") or die $!;
  print "created /api/delete_page\n";
  }
else
  {
  $sth=$dbh->do("UPDATE pages set body='$body' where url='/api/delete_page' and domain_id='$domain_id' ");
  print "updated /api/delete_page\n";
  }
