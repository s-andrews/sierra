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

package Sierra::IlluminaLane;

sub new {

  my ($class,$runobj,$lane) = @_;

#  if ($lane !~ /^\d+$/) {
#    die "Lane number must be a number, not '$lane'";
#  }


  my $lane_obj =  bless {
			 run => $runobj,
			 lane => $lane,
			};

  return $lane_obj;

}

sub get_lane {
  my $obj = shift;
  return $obj->{lane};
}


1;
