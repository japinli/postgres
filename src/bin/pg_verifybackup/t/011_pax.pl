# Copyright (c) 2026, PostgreSQL Global Development Group

# Test parsing of PAX extended headers, including malformed input.

use strict;
use warnings FATAL => 'all';
use File::Copy;
use File::Path qw(make_path rmtree);
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('primary');
$node->init(allows_streaming => 1);
$node->start;

# Take a tar backup, mostly to get a valid backup_manifest to use with our
# synthetic archives.
my $backup = $node->backup_dir . '/pax';
$node->command_ok(
	[
		'pg_basebackup',
		'--pgdata' => $backup,
		'--no-sync',
		'--checkpoint' => 'fast',
		'--format' => 'tar'
	],
	'tar backup ok');
my $manifest = "$backup/backup_manifest";
ok(-f $manifest, 'backup manifest exists');

# Build a traditional tar header.  We use the POSIX checksum format.
sub tar_header
{
	my ($name, $size, $type) = @_;
	my $header = "\0" x 512;

	substr($header, 0, length($name)) = $name;
	substr($header, 100, 8) = sprintf("%07o ", 0644);
	substr($header, 108, 8) = sprintf("%07o ", 0);
	substr($header, 116, 8) = sprintf("%07o ", 0);
	substr($header, 124, 12) = sprintf("%011o ", $size);
	substr($header, 136, 12) = sprintf("%011o ", time);
	substr($header, 148, 8) = "        ";
	substr($header, 156, 1) = $type;
	substr($header, 257, 6) = "ustar\0";
	substr($header, 263, 2) = "00";
	substr($header, 265, 8) = "postgres";
	substr($header, 297, 8) = "postgres";

	my $sum = 0;
	$sum += $_ for unpack("C*", $header);
	substr($header, 148, 8) = sprintf("%06o\0 ", $sum);

	return $header;
}

sub padding
{
	my ($len) = @_;

	return "\0" x ((512 - ($len % 512)) % 512);
}

# Construct a well-formed PAX record, computing the length iteratively.
sub pax_record
{
	my ($key, $value) = @_;
	my $body = " $key=$value\n";
	my $len = length($body) + 1;

	while (length($len) + length($body) != $len)
	{
		$len = length($len) + length($body);
	}

	return "$len$body";
}

sub file_member
{
	my ($name, $contents) = @_;

	return tar_header($name, length($contents), '0')
	  . $contents
	  . padding(length($contents));
}

sub write_archive
{
	my ($path, @parts) = @_;

	open my $fh, '>:raw', $path
	  or die "could not create $path: $!";
	print $fh $_ for @parts;
	print $fh "\0" x 1024;
	close $fh;
}

my $combined_path = pax_record('path', 'paxpath');
my $combined_linkpath = pax_record('linkpath', 'paxlink');
my $combined_payload = $combined_path . $combined_linkpath;

my @cases = (
	{
		name => 'bad_record_length',
		parts => [
			tar_header('PaxHeader', 13, 'x'),
			"999 path=foo\n",
			padding(13)
		],
		fails_like => qr/record length exceeds payload/,
	},
	{
		name => 'missing_equals',
		parts => [
			tar_header('PaxHeader', 14, 'x'),
			"14 notarecord\n",
			padding(14)
		],
		fails_like => qr/malformed key\/value record/,
	},
	{
		name => 'missing_newline',
		parts => [
			tar_header('PaxHeader', 12, 'x'),
			"12 path=fooX",
			padding(12)
		],
		fails_like => qr/does not end with newline/,
	},
	{
		name => 'nul_in_path',
		parts => [
			tar_header('PaxHeader', length(pax_record('path', "foo\0bar")), 'x'),
			pax_record('path', "foo\0bar"),
			padding(length(pax_record('path', "foo\0bar")))
		],
		fails_like => qr/NUL in value/,
	},
	{
		name => 'pax_without_member',
		parts => [
			tar_header('PaxHeader', length(pax_record('path', 'foo')), 'x'),
			pax_record('path', 'foo'),
			padding(length(pax_record('path', 'foo')))
		],
		fails_like => qr/pax extended header was pending/,
	},
	{
		name => 'global_pax',
		parts => [ tar_header('GlobalHeader', 0, 'g') ],
		fails_like => qr/global pax extended headers are not supported/,
	},
	{
		name => 'consecutive_pax',
		parts => [
			tar_header('PaxHeader', length(pax_record('path', 'foo')), 'x'),
			pax_record('path', 'foo'),
			padding(length(pax_record('path', 'foo'))),
			tar_header('PaxHeader', length(pax_record('path', 'bar')), 'x'),
			pax_record('path', 'bar'),
			padding(length(pax_record('path', 'bar')))
		],
		fails_like => qr/consecutive pax extended headers are not supported/,
	},
	{
		name => 'pax_too_large',
		parts => [ tar_header('PaxHeader', 4097, 'x') ],
		fails_like => qr/pax extended header is too large/,
	},
	{
		name => 'unknown_key_ignored',
		parts => [
			tar_header('PaxHeader',
				length(pax_record('ctime', '1234567890')), 'x'),
			pax_record('ctime', '1234567890'),
			padding(length(pax_record('ctime', '1234567890'))),
			file_member('unknownfile', "contents\n")
		],
		fails_like => qr/not in the manifest/,
	},
	{
		name => 'long_record_length',
		parts => [
			tar_header('PaxHeader',
				length(pax_record('path', 'a' x 91)), 'x'),
			pax_record('path', 'a' x 91),
			padding(length(pax_record('path', 'a' x 91))),
			file_member('unknownfile', "contents\n")
		],
		fails_like => qr/not in the manifest/,
	},
	{
		name => 'combined_path_and_linkpath',
		parts => [
			tar_header('PaxHeader', length($combined_payload), 'x'),
			$combined_payload,
			padding(length($combined_payload)),
			file_member('unknownfile', "contents\n")
		],
		fails_like => qr/not in the manifest/,
	},
);

for my $case (@cases)
{
	my $dir = $node->backup_dir . '/pax_' . $case->{name};

	rmtree($dir);
	make_path($dir);
	copy($manifest, "$dir/backup_manifest")
	  or die "could not copy manifest: $!";
	write_archive("$dir/base.tar", @{ $case->{parts} });

	command_fails_like(
		[ 'pg_verifybackup', '-F', 't', '-n', $dir ],
		$case->{fails_like},
		"pax parser rejects or handles: $case->{name}");

	rmtree($dir);
}

done_testing();
