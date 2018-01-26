#!/usr/bin/perl

##########################################################################
#                                                                        #
# Copyright 2011, Simon Andrews (simon.andrews@babraham.ac.uk)           #
#                                                                        #
# This file is part of Sierra.                                           #
#                                                                        #
# Sierra is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by   #
# the Free Software Foundation, either version 3 of the License, or      #
# (at your option) any later version.                                    #
#                                                                        #
# Sierra is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of         #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          #
# GNU General Public License for more details.                           #
#                                                                        #
# You should have received a copy of the GNU General Public License      #
# along with Sierra.  If not, see <http://www.gnu.org/licenses/>.        #
##########################################################################

use warnings;
use strict;
use lib "../";
use Sierra::Constants;


package Sierra::ResultFile;


sub new {

  my ($class,$name,$path,$type,$mime,$hidden) = @_;


  my $size = (stat($path))[7];

  my $suffix = 'bytes';

  if ($size > 1024) {
    $size /= 1024;
    $suffix = 'kB';
  }

  if ($size > 1024) {
    $size /= 1024;
    $suffix = 'MB';
  }

  if ($size > 1024) {
    $size /= 1024;
    $suffix = 'GB';
  }

  if ($hidden) {
    $hidden = 1; # Generic true value
  }

  $size = sprintf("%.2f",$size).' '.$suffix;

  return bless {
		name=>$name,
		path => $path,
		type => $type,
		size => $size,
		mime => $mime,
		hidden => $hidden,
	       };

}

sub set_info {
  my ($obj,$info) = @_;
  $obj->{info} = $info;
}

sub info {
  my $obj = shift;
  return $obj->{info};
}

sub name {
  my $obj=shift;
  return $obj->{name};
}

sub mime_type {
  my $obj=shift;

  if ($obj->{mime}) {
    return $obj->{mime};
  }
  return undef;
}

sub path {
  my $obj=shift;
  return $obj->{path};
}

sub hidden {
  my $obj=shift;
  return $obj->{hidden};
}

sub type {
  my $obj=shift;
  return $obj->{type};
}

sub size {
  my $obj=shift;
  return $obj->{size};
}

1;
