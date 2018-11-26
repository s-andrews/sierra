#!/usr/bin/perl

##########################################################################
#                                                                        #
# Copyright 2011-13, Simon Andrews (simon.andrews@babraham.ac.uk)        #
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
use Sierra::ResultFile;
use XML::Simple;


package Sierra::CasavaResultsFolder;

sub new {

  my ($class,$run,$folder) = @_;

  my $relative_path = $folder;
  my $run_folder = $run->get_run_folder();
  $relative_path =~ s/^\Q$run_folder\E\/?//;

  my @path_sections = split(/\//,$relative_path);

  foreach my $section (@path_sections) {
    $section =~ s/(-\d{4})_\w+/$1/;
  }

  my $name = join(" > ",@path_sections);

  my $obj = bless {
		   folder => $folder,
		   run => $run,
		   name => $name,
		  };


  return $obj;

}

sub name {
  my $obj = shift;
  return $obj->{name};
}

sub get_attributes_for_lane {

  my $obj = shift;
  my $laneobj = shift;

  # TODO: See if we can parse some useful attributes out of
  # any fastq files we find.

  return ();

}

sub get_files_for_lane {

  my $obj = shift;
  my $lane = shift;

  # For the type filter we still return these files, but
  # we don't add information to them since they're not going
  # to be presented to the user.  We need them returned since
  # they're used to collate possible lists of types to use for
  # future filters.
  my $type_filter = shift;
  my @barcodes = @_;

  # We find which files in this lane can be presented to the user
  my @files;

  # We'll initally make up a list of all files we're going to 
  # show which we'll then try to classify

  my $glob_pattern = $obj->{folder}."/*_L00".$lane->get_lane()."_*";
  my @files_to_show = glob($glob_pattern);

  if (@barcodes) {
    # Filter the files to show to include only those
    # which contain the barcode sequences in their names

    my @filtered_files;

    FILE: foreach my $file (@files_to_show) {
	my ($name) = (split(/\//,$file))[-1];
	foreach my $barcode (@barcodes) {
	  next FILE unless (index($name,"_${barcode}_") >=0 );
	}

	push @filtered_files,$file;
      }

    @files_to_show = @filtered_files;

  }

  # We'll then iterate through these files trying to classify them

  foreach my $file (@files_to_show) {

    my ($name) = (split(/\//,$file))[-1];

    # There are a couple of files we don't want to see
    next if ($name =~ /_finished\.txt$/);
    next if ($name =~ /_genomesize.xml$/);

    # Export files
    if ($name =~ /export.txt$/ or $name=~ /export.txt.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'Raw Mapped Sequence Data');
    }

    # Clusterflow run files
    elsif ($name =~ /\.run$/ || $name =~ /clusterFlow\.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Clusterflow file','text/plain');
    }

    # 10X Genomics result files
    elsif ($name =~ /genes\.tsv$/) {
	push @files, new Sierra::ResultFile($name,$file,'10X Genomics Results File','text/plain');
    }
    # compressed
    elsif ($name =~ /10X$/ || $name =~ /genes\.tsv/  || $name =~ /matrix\.mtx/ || $name =~ /barcodes\.tsv/) {
        push @files, new Sierra::ResultFile($name,$file,'10X Genomics Results File');
    }
    elsif ($name =~ /web_summary\.html/) {
        push @files, new Sierra::ResultFile($name,$file,'10X Genomics Results File','text/html');
    }

    # MultiQC HTML reports
    elsif ($name =~ /multiqc.*report\.html$/) {
        push @files, new Sierra::ResultFile($name,$file,'MultiQC QC Report','text/html');
    }

    # Barcode splitting results files
    # Clusterflow run files
    elsif ($name =~ /^barcode.*png$/) {
      push @files, new Sierra::ResultFile($name,$file,'Barcode Splitting Results','image/png');
    }
    elsif ($name =~ /^barcode.*txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Barcode Splitting Results','text/plain');
    }

    # QC files
    elsif (-d $file and $file =~ /fastqc$/) {

      my $fastqc_file = "$file/fastqc_report.html";

      if (-e $fastqc_file) {
	push @files, new Sierra::ResultFile($name,$fastqc_file,'FastQC QC Report','text/html');

	# We also need to add all of the files under the fastqc
	# folder as hidden files so we can allow the user to access
	# them, but without them showing up in the list of files
	my $fastqc_folder = $file;
	$fastqc_folder =~ s/\/fastqc_report.html$//;
	my @images = glob("$fastqc_folder/Images/*png");
	foreach my $image (@images) {
	  push @files, new Sierra::ResultFile(undef,$image,'FastQC Image','image/png',1);
	}
	@images = glob("$fastqc_folder/Icons/*png");
	foreach my $image (@images) {
	  push @files, new Sierra::ResultFile(undef,$image,'FastQC Image','image/png',1);
	}
      }
    }
  

    # QC archive files
    elsif ($name =~ /fastqc.*\.zip$/) {
      push @files, new Sierra::ResultFile($name,$file,'FastQC QC Archive');
    }

    # FastQC HTML reports
    elsif ($name =~ /fastqc\.html$/) {
            push @files, new Sierra::ResultFile($name,$file,'FastQC QC Report','text/html');

    }

    # FastQ Screen HTML reports
    elsif ($name =~ /screen\.html$/) {
            push @files, new Sierra::ResultFile($name,$file,'FastQ Screen Report','text/html');

    }

 

    # Screen files
    elsif ($name =~ /_screen.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Species Screen Results','text/plain');
    }

    # Screen images
    elsif ($name =~ /_screen.png$/) {
      push @files, new Sierra::ResultFile($name,$file,'Species Screen Graph','image/png');
    }

    # Tophat files
    elsif ($name =~ /tophat.*bam/i) {
      push @files, new Sierra::ResultFile($name,$file,'Tophat spliced mapped reads');
    }

    # Tophat summary files
    elsif ($name =~ /align_summary.txt$/ or $name =~ /alignment_summary.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Tophat Alignment Summary','text/plain');
    }

    # Bowtie files
    elsif ($name =~ /bowtie/) {
      push @files, new Sierra::ResultFile($name,$file,'Bowtie mapped reads');
    }

    # HiCUP report files
    elsif ($name =~ /hicup_summary_report.*\.html$/i) {
      push @files, new Sierra::ResultFile($name,$file,'HiCUP Summary Report','text/html');
    }

    # HiCUP classification files
    elsif ($name =~ /ditag_classification.png$/i or $name=~ /ditag_size_distribution.png$/ or $name=~ /uniques_cis-trans.png$/ ) {
      push @files, new Sierra::ResultFile($name,$file,'HiCUP Ditag Result','image/png');
    }


    # SiCUP report files
    elsif ($name =~ /sicup_report\.html$/i) {
      push @files, new Sierra::ResultFile($name,$file,'SiCUP Summary Report','text/html');
    }


    # Bismark report files
    elsif ($name =~ /Bismark_mapping_report.txt$/ || $name =~ /bismark.*_splitting_report.txt$/ || $name =~ /bismark.*deduplication_report.txt$/ || $name =~ /bismark.*[PS]E_report.txt$/ ) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark report file','text/plain');
    }

    # Bismark methylation call files
    elsif ($name =~ /C[Hp][GH]_O[TB].*bismark.*\.txt.gz$/ ) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark methylation calls file');
    }

    elsif ($name =~ /C[Hp][GH]_CTO[TB].*bismark.*\.txt.gz$/ ) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark methylation calls file');
    }

    # Bismark quantitation files
    elsif ($name =~ /bismark.*\.cov$/ || $name =~ /bismark.*\.bedGraph$/) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark quantitation file');
    }

    # Bismark MBias
    elsif ($name =~ /bismark.*\.M-bias/) {
      if ($name =~ /\.png$/) {
	push @files, new Sierra::ResultFile($name,$file,'Bismark M-bias file','image/png');
      }
      elsif ($name =~ /\.txt$/) {
	push @files, new Sierra::ResultFile($name,$file,'Bismark M-bias file','text/plain');
      }
    }


    # Bismark quantitation files
    elsif ($name =~ /bismark.*\.bam$/) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark aligned reads');
    }

    # Bismark quantitation files
    elsif ($name =~ /bismark.*\.alignment_overview.png$/) {
      push @files, new Sierra::ResultFile($name,$file,'Bismark alignment overview','image/png');
    }

    # Bismark files
    elsif ($name =~ /bismark/) {
      if ($name =~ /.png$/i) {
	push @files, new Sierra::ResultFile($name,$file,'Bismark results file','image/png');
      }
      elsif ($name =~ /.html?$/i) {
	push @files, new Sierra::ResultFile($name,$file,'Bismark report summary file','text/html');
      }
      else {
	push @files, new Sierra::ResultFile($name,$file,'Bismark results file');
      }
    }

    # Trimming reports
    elsif ($name =~ /trimming_report.txt$/) {
      push @files, new Sierra::ResultFile($name,$file,'Adapter trimming report','text/plain');
    }


    # ASAP files]
    elsif ($name =~ /ASAP/ and $name =~ /report/) {
      push @files, new Sierra::ResultFile($name,$file,'ASAP differential mapping report','text/plain');
    }


    # ASAP files
    elsif ($name =~ /ASAP/) {
      push @files, new Sierra::ResultFile($name,$file,'ASAP differentially mapped reads');
    }

    # BAM files
    elsif ($name =~ /\.bam$/) {
      push @files, new Sierra::ResultFile($name,$file,'BAM format mapped reads');
    }

    # SAM files
    elsif ($name =~ /\.sam/ or $name =~ /\.sam\.gz$/) {
      push @files, new Sierra::ResultFile($name,$file,'SAM format mapped reads');
    }

    # FastQ files
    elsif ($name =~ /\.fastq$/ or $name =~ /\.fastq.gz$/ or $name =~ /\.fq.gz$/ or $name =~ /\.fq$/) {
      push @files, new Sierra::ResultFile($name,$file,'FastQ sequence file');
    }

    # Generic Image files (mostly to get the right mime-type)
    elsif ($name =~ /.png$/) {
      push @files, new Sierra::ResultFile($name,$file,'PNG Image','image/png');
    }

    else {
      push @files, new Sierra::ResultFile($name,$file,'Results file');
    }
  }

  # Count how many valid files there are
  my $files_to_type = 0;
  foreach my $file (@files) {
    next if ($file ->hidden());
    if ($type_filter) {
      ++$files_to_type if ($file->type() eq $type_filter);
    }
    else {
      ++$files_to_type;
    }
  }

  # Add command info to each file
  foreach my $file (@files) {


    # Don't do lookups if there are huge numbers of files
    if ($files_to_type >= 100) {
      $file->set_info("Too many files to do information lookup");
      next;
    }

    # Don't do lookups on files which don't pass the type filter
    if ($type_filter and !($file->type() eq $type_filter)) {
      next;
    }

    my $path = $file->path();
    if ($path =~ /\.bam$/i) {
      $file->set_info(scalar(`$Sierra::Constants::SAMTOOLS_PATH view -H $path | grep \@PG`));
    }
    elsif ($path =~ /fastqc_report.html$/) {
      my @fail;
      my @warn;

      my $summary = $path;
      $summary =~ s/fastqc_report\.html/summary.txt/;
      open (IN,$summary) or next;

      while (<IN>) {
	my ($status,$module) = split(/\t/);
	push @fail, $module if ($status eq 'FAIL');
	push @warn, $module if ($status eq 'WARN');
      }
      close (IN);

      my $info;

      if (@fail) {
	$info = "Failures:\n";
	$info .= join("\n",@fail);
      }

      if (@warn) {
	$info .= "\n" if ($info);
	$info = "Warnings:\n";
	$info .= join("\n",@warn);
      }
      unless ($info) {
	$info = "All tests passed";
      }

      $file->set_info($info);
    }
    elsif ($path =~ /trimming_report\.txt$/) {
      my $info;
      open (IN,$path) or next;
      while (<IN>) {
	if (/^cutadapt version/) {
	  $info.=$_;
	  while (<IN>) {
	    last unless (/\w+/);
	    $info .= $_;
	  }
	  last;
	}
      }
      close (IN);
      $file -> set_info($info);
    }
    elsif ($path =~ /align_summary\.txt$/ or $path =~ /alignment_summary\.txt$/) {
      my $info;
      open (IN,$path) or next;
      while (<IN>) {
	if (/overall read alignment rate/) {
	  $file -> set_info($_);
	  close(IN);
	  last;
	}
      }
    }
    elsif ($path =~ /hicup_summary_report.*.html$/i) {
      my $info;
      open (IN,$path) or next;
      my $total;
      my $paired;
      while (<IN>) {
	if (/<th>Total Reads<\/th>/) {
	  $total = <IN>;
	  chomp $total;
	  $total =~ s/<.*?>//g;
	  $total =~ s/\s+//g;
	}
	if (/<th>Paired<\/th>/) {
	  $paired = <IN>;
	  chomp $paired;
	  $paired =~ s/<.*?>//g;
	  $paired =~ s/\s+//g;

	  close (IN);

	  my $percent = sprintf("%.1f",(($paired/$total)*100));

	  $file -> set_info("Total Reads = $total\nPaired Reads = $paired\nSuccess Percent=$percent");
	  last;
	}
      }
    }
    elsif ($path =~ /bismark.*splitting_report.txt$/i or $path =~ /bismark.*[PS]E_report.txt$/i) {
      my $info;
      open (IN,$path) or next;
      while (<IN>) {
	if (/C methylated in CpG context/) {
	  $info = $_;
	  while (<IN>) {
	    $info .= $_ if (/\S/);
	  }
	}
      }
      close (IN);
      $file -> set_info($info);
    }

    elsif ($path =~ /bismark.*deduplication_report.txt$/i) {
      my $info;
      open (IN,$path) or next;
      while (<IN>) {
	if (/Total count of deduplicated leftover sequences/) {
	  $file -> set_info($_);
	  close (IN);
	  last;
	}
      }
    }
  }

  return @files;

}



1;
