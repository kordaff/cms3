#!/usr/bin/perl
#
use strict;
use warnings;
use DBD::Pg;

my $dbh = DBI->connect("dbi:Pg:dbname=cms3",'cms3','',{AutoCommit=>1})or die $!;
my (@row,$sth,$query);

my $body;
{
  local $/ = undef;
  open(FILE,'<','api-add-page.txt') or die $!;
  $body = <FILE>;
  close FILE;
}

$sth=$dbh->do("UPDATE pages set body='$body' where url='/api/add_page' ");

