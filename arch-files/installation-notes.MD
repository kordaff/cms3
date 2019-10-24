# broke on newest ARCH, needs pacman -S perl-linux-pid
# also got to be sure to add user acct to sudo with visudo.   As visudo uses vi by default
# I added a Defaults editor=/usr/bin/vim to /etc/sudoers to avoid having to install vi
# although more often than not, i type vi instead of vim.

#!/bin/bash

# Start to finish, install Arch, install all these packages, reconfigure httpd, configure cms3

# configure PostgreSQL

# as postgres:
# initdb -D /var/lib/postgres/data

# as root (since postgres shouldn't have sudo access, start as root, su - postgres as needed)
# sudo systemctl enable postgresql
# sudo systemctl start postgresql
# Possibly - change data/pg_hba.conf to allow other machines/vm's on LAN to access db
#          - also change the listen line to listen: '*'  # in that case   

# as postgres again:
# createuser cms3 
# createdb cms3 -O cms3

# just to get this git clone, requires openssh, git, grub after the first pacstrap.

# ----  servers and utils  ----
# sudo pacman -S dnsutils ntp base-devel apache postgresql mlocate wget pkgfile net-tools perl-datetime perl-dbd-pg perl-email-address perl-inc-latest perl-mime-lite perl-module-build perl-par-dist perl-readonly perl-test-pod perl-test-pod-coverage perl-yaml 

# 
# ---- perl modules and mod_perl from AUR (these get installed by a user acct with sudo access)
# ---- be sure to have gpg keys setup 
# 

# as that user:
# gpg --full-gen-key
# gpg --recv-key AB34BA0040E92ECE
# to get Apache's Steve Hay's key installed for the mod_perl module.

mkdir ~/Downloads

for i in mod_perl perl-apache-dbi perl-cgi-cookie perl-class-mix perl-crypt-eksblowfish perl-crypt-random-source perl-uri-escape-xs
  do
    /home/USERNAME/bin/acquire-aur.sh $i
    # you can also add ~/bin to PATH in .bash_profile
  done

#  I got real tired of finding the snapshot in the AUR section of wiki.archlinux.org, downloading
#    it manually to ungzip and untar.  Then cd'ing in and makepkg -si
#    Thus: the acquire-aur.sh script.
#  I was trying to get starman to install at the time, lots more prereq's for that...

# -----------------------------------------------------------------------------
# -- More notes to follow once I do this install one more time by cloning the - 
# -- git repo.  Had to massively fix store_page in cms3.pm this time.         -
# -----------------------------------------------------------------------------

mkdir -p /var/www/default
mkdir /var/www/html
mkdir -p /var/www/cms3/js
mkdir /var/www/cms3/css
mkdir /var/www/cms3/images
mkdir /var/www/cms3/fonts

cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/orig.conf
cp httpd.conf /etc/httpd/conf/

# note, change the ServerAdmin email address
#       and the two (different) IP addresses to match what you have for public IP (or to same private
#       ip on your LAN)

ln -s /var/log/httpd /etc/httpd/logs

# this line is specific to Arch Linux
#   for other flavors, locate vendor_perl and create MyApache2 directory in it, and put cms3.pm
#   there.  You'll need to alter the httpd.conf to match, for Apache2::Reload
mkdir /usr/share/perl5/vendor_perl/MyApache2/

