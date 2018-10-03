#!/usr/bin/perl
#
use strict;
use warnings;
use DBD::Pg;

my $dbh = DBI->connect("dbi:Pg:dbname=userconfig",'userconfig','',{AutoCommit=>1})or die $!;
my (@row,$sth,$query);

my $body;
{
  local $/ = undef;
  open(FILE,'<','api-login.txt') or die $!;
  $body = <FILE>;
  close FILE;
}
my $t=time;
$sth=$dbh->prepare("UPDATE pages set body=?, creation_time=? where url=? ");
$sth->execute($body,$t,'/api/login');