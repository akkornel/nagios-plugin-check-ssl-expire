#!/usr/bin/perl -wT

# /usr/lib/nagios/plugins/check_ssl_cert_expire
# nagios-plugin-check-ssl-expire

# Test:
# A good certificate, still valid
# A good certificate, expired
# A cert that is missing the issuer CN, still valid
# A cert that is missing the issuer CN, expired
# A cert that is missing the subject CN, still valid
# A cert that is missing the subject CN, expired
# Check missing W
# Check missing C
# Check C=W
# Check C>W
# Check invalid F
# Check file malformed

use strict;
use DateTime;
use DateTime::Format::RFC3339;
use Net::SSLeay q(1.43);

# Map output code to status
my %OUTPUT_CODE_MAP = (
    0 => 'OK',
    1 => 'WARNING',
    2 => 'CRITICAL',
    3 => 'UNKNOWN',
);


# Start up SSLeay
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::ENGINE_load_builtin_engines();
Net::SSLeay::ENGINE_register_all_complete();
Net::SSLeay::randomize();

# Our output (assuming no errors) goes here
my $output = '';
my @perfdata = ();
my $output_code = 0;

# Get the cert to read
my $FILE = shift;
push @perfdata, 'file_name=' . $FILE;

# Check and open the file
$FILE =~ m/^(.+)$/xims;
$FILE = $1;
my $bio = Net::SSLeay::BIO_new_file($FILE, 'r');
if (!$bio) {
    $output_code = 3;
    $output = 'Error opening cert file for reading';
    send_output_and_exit($output_code, $output, \@perfdata);
}
my $cert = Net::SSLeay::PEM_read_bio_X509($bio);
if (!$cert) {
    $output_code = 3;
    $output = "Error reading cert from file";
    send_output_and_exit($output_code, $output, \@perfdata);
}

# Get the expiration date
my $expiration_asn1 = Net::SSLeay::X509_get_notAfter($cert);
if (!defined($expiration_asn1)) {
    $output_code = 3;
    $output = "Could not find an expiration date for certificate!\n";
    send_output_and_exit($output_code, $output, \@perfdata);
}
my $expiration_isotime = Net::SSLeay::P_ASN1_TIME_get_isotime($expiration_asn1);
push @perfdata, 'expiration_isotime:' . $expiration_isotime;

# Calculate the remaining lifetime
my $dtf = DateTime::Format::RFC3339->new();
my $expires_dt = $dtf->parse_datetime($expiration_isotime);
my $now_dt = DateTime->now();
if ($now_dt >= $expires_dt) {
    $output .= 'EXPIRED';
    push @perfdata, 'expiration_remaining=P0W';
    $output_code = 2;
} else {
    my $expires_dur = $expires_dt->subtract_datetime($now_dt);
    my $day_string =   $expires_dur->years . 'y'
                     . $expires_dur->months . 'm'
                     . $expires_dur->days . 'd';
    my $time_string =   $expires_dur->hours . 'h'
                      . $expires_dur->minutes . 'm'
                      . $expires_dur->seconds . 's';
    $output .= 'Expires in ' . $day_string . ' ' . $time_string;
    push @perfdata, 'expiration_remaining='
                    . 'P' . uc($day_string)
                    . 'T' . uc($time_string);
}

# Get the subject CN
my $subject = Net::SSLeay::X509_get_subject_name($cert);
if (!defined($subject)) {
    $output_code = 3;
    $output = "Could not find any subject names for certificate!\n";
    send_output_and_exit($output_code, $output, \@perfdata);
}
my $subject_cn = get_cn_from_name($subject);
my $subject_oneline = Net::SSLeay::X509_NAME_oneline($subject);
$output .= ', certificate for ' . $subject_cn;
push @perfdata, 'subject=' . $subject_oneline;

# Get the issuer CN
my $issuer = Net::SSLeay::X509_get_issuer_name($cert);
if (!defined($issuer)) {
    $output_code = 3;
    $output = "Could not find any issuer names for certificate!";
    send_output_and_exit($output_code, $output, \@perfdata);
}
my $issuer_cn = get_cn_from_name($issuer);
my $issuer_oneline = Net::SSLeay::X509_NAME_oneline($issuer);
$output .= ' issued by ' . $issuer_cn;
push @perfdata, 'issuer=' . $issuer_oneline;

# Free our objects
Net::SSLeay::X509_free($cert);
Net::SSLeay::BIO_free($bio);

# Done!
send_output_and_exit($output_code, $output, \@perfdata);


# get_cn_from_name: Given an X509_NAME structure, get and return the CN field.
# 
# Takes one parameter:
# * A Net::SSLeay X509_NAME reference.
#
# Returns a string, the contents of the CN attribute.  It may be empty.
sub get_cn_from_name {
    my ($name) = @_;

    # Get our count, and start an index
    my $i = 0;
    my $count = Net::SSLeay::X509_NAME_entry_count($name);
    if (!$count) {
        print "Name section has no entries!\n";
        exit 3;
    }

    # Check the entries looking for our CN
    while ($i < $count) {
        # Get our current entry, and it's NID
        my $entry = Net::SSLeay::X509_NAME_get_entry($name, $i);
        my $object_asn1 = Net::SSLeay::X509_NAME_ENTRY_get_object($entry);
        my $object_nid = Net::SSLeay::OBJ_obj2nid($object_asn1);

        # At this point, we can see if the object we have is what we want
        if ($object_nid == Net::SSLeay::NID_commonName()) {
            my $data_asn1 = Net::SSLeay::X509_NAME_ENTRY_get_data($entry);
            my $data_string = Net::SSLeay::P_ASN1_STRING_get($data_asn1);
            return $data_string;
        }

        # We didn't find the field we want, so try the next one
        ++$i;
    }

    # If we didn't find anything, return an empty string
    return '';
}


# send_output_and_exit: Used to exit the program.
#
# The parameters are:
# * The exit code, zero through three (inclusive).
# * A string of output to send to standard output.
# * A list ref of Nagios perfdata to append to standard output.
#
# Does not return.
sub send_output_and_exit {
    my ($output_code, $output, $perfdata_ref) = @_;

    print $OUTPUT_CODE_MAP{$output_code};
    print ': ', $output, join('|', '', @$perfdata_ref), "\n";
    exit $output_code;
}

__END__

=pod 

=head1 NAME

check_ssl_cert_expire - Alert if an SSL certificate is close to expiration

=head1 SYNOPSIS

check_ssl_cert_expire -f file_identifier -w warn_days -c critical_days

=head1 DESCRIPTION

This Nagios plugin performs checks on locally-installed SSL certificates, and 
returns status based on how close they are to expiration.  It works with any 
type of SSL certificate that OpenSSL can process, including client 
certificates.

The human-readable output includes the time until expiration, the certificate 
CN (common name), and the issuer CN.  Perfdata output includes the local path 
to the certificate file; the expiation date and time until expiration; and the 
full certificate issuer and subject.

For security reasons, the list of certificates that can be checked is specified 
in a local configuration file.  See the L</"CERTIFICATE FILE"> section for 
details.

The configuration file is located at F</etc/nagios3/check_ssl_cert_list.conf>.

Because the plugin runs locally, it must be executed by something else, such as 
L<NRPE|https://exchange.nagios.org/directory/Addons/Monitoring-Agents/NRPE--2D-Nagios-Remote-Plugin-Executor/details> 
or L<remctl|https://www.eyrie.org/~eagle/software/remctl/>.  You could also 
write a harness that triggers checks automatically, and sends the results back 
using a mechanism like 
L<NSCA|https://exchange.nagios.org/directory/Addons/Passive-Checks/NSCA--2D-Nagios-Service-Check-Acceptor/details>.

This plugin must be able to access both its configuration file, as well as the 
certificates themselves.  Certificates do not normally contain private data, 
but the directories where the certificates live may be inaccessible to the 
account that is running the check.  If the check is unable to read a file, a 
WARNING status is returned.

The output of this check follows the L<Nagios plugin 
API|https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/pluginapi.html>
for Nagios Core version 3.  See the L</"PLUGIN OUTPUT"> section for more 
details, along with the list of performance data items returned.

=head1 OPTIONS

Each execution of C<check_ssl_cert_expire> must have at least the C<-f> option 
set.  The other two options are optional.

=over 4

=item -f file_identifier

This is the unique identifier of the certificate to check.  See the 
L</"CERTIFICATE FILE"> section for more details.

=item -w warn_days

Once the remaining life of the certificate has reached (or gone below) this 
number of days, the check returns a WARNING status.

This must be a positive number.  If not specified, this defaults to 30 days.

=item -c critical_days

Once the remaining life of the certificate has reached (or gone below) this 
number of days, the check returns a CRITICAL status.

This must be a non-negative number.  It may be zero, but that is a bad idea.
This must also be less than C<warn_days> (described above).  If not specified,
this defaults to 15 days.

=back

=head1 DISCUSSION

All SSL certificates B<must> have their expiration dates checked regularly.  
There are many Nagios plugins already in the world that check SSL certificate 
expiration.  Not only that, this is definitely not the easiest way to check for 
certificate expiration.  The easiest way to check for SSL certificate 
expiration is to use Nagios plugins like
L<check_ssl_certificate|https://exchange.nagios.org/directory/Plugins/Network-Protocols/HTTP/check_ssl_certificate/details>
and L<check_ssl_cert|https://exchange.nagios.org/directory/Plugins/Network-Protocols/HTTP/check_ssl_certificate/details>.
If you have a service that uses an SSL certificate and is reachable by your 
monitoring server, then you should use one of those plugins instead.

This Nagios plugin is meant for cases where checking a certificate remotely is 
diffucult.  Examples include...

=over 4

=item Server certificates used by weird stuff.

=item Client certificates.

=back

In the case of server certificates, there are various protocols in the world 
that rely on SSL certificates, but do not have coverage by existing tools.  
Examples include database protocols, SIP, etc..  Also for some protocols, a 
certain amount of communication is required before the SSL/TLS session is 
started (at which point the certificate is available to check), so simple 
checks would not work.

In addition, the behavior of some Nagios checks may be viewed as malicious.  
For example, if a check connects to a server, goes as far as retrieving the 
server certificate, and then disconnects, the server may see that as a probe by 
an unknown agent, trying to see if a particular service is available.

In the case of client certificates, this is very difficult to check remotely, 
unless you are able to hook into the server that the client is already using.

This Nagios plugin exists to serve the certificates that can not be checked 
easily remotely.

=head1 CERTIFICATE FILE

This Nagios plugin involves reading various files on the system, and passing 
full paths to the plugin (most likely remotely) is dangerous for several 
reasons:

=over 4

=item Escapes

The path will always include various special characters, which must be properly 
escaped throughout the entire path from the monitoring server to this system.

=item Information Leakage

If a full path were provided, this plugin could be leveraged to provide 
information on which files exist on a system, plus which are certificates.  
Also, OpenSSL is used to parse the files.  If an attacker were able to place a 
file on a system that is known to crash OpenSSL, and if this plugin were to 
accept full paths remotely, then this plugin could be used to trigger an 
OpenSSL crash, which could then be exploited.

=back

To prevent these issues, a configuration file must exist on the system where 
this plugin is running.  The file contains lines of the following format:

=over 4

# A comment

identifier  /path/to/certificate

=back

Empty lines, and lines starting with a C<#> (a hash mark) are ignored.  All 
other lines must contain the following:

=over 4

=item An identifier, consisting only of ASCII letters, numbers, and 
underscores.

=item At least one character of whitespace (such as a space or a tab).

=item The full path to the corresponding certificate.

=back

The file format is such that configuration-management systems should be able to 
maintain it.  For example, Puppet users can use 
L<file_line|https://forge.puppetlabs.com/puppetlabs/stdlib>.

If B<any> identifier appears more than once, then the check will return an 
UNKNOWN result.  If B<any> part of the file can not be parsed, then the check 
will return an UNKNOWN result.

=head1 PLUGIN OUTPUT

This plugin outputs results meant for Nagios Core version 3.  The format looks 
like this:

=over 4

STATUS: Human-readable message|perfdata1|perfdata2

=back

C<STATUS> is either C<OK>, C<WARNING>, C<CRITICAL>, or C<UNKNOWN>.  The 
human-readable message takes this form:

=over 4

Expires in 1y3m5d 10h5m10s, certificate for mywebsite.com issued by Some CA

=back

In this example, the certificate expires in approximately one year and three 
months.

If the certificate has expired, everything before the comma is replaced 
with the word C<EXPIRED>.

After the expiration, the output lists the Common Name (CN) of the certificate 
subject and the certificate issuer.  Although the Common Name is a standard 
attribute for certificates, it is not mandatory.  If a certificate is checked 
that is missing a CN for either the issuer or the subject, that part of the 
output is left empty.

In the perfdata section, there are a number of items which will appear, 
depending on how far the plugin was able to proceed.

=over 4

=item file_name

This is the string that was provided with the C<-f> option.  It will appear in 
the perfdata as long as you provided something for the C<-f> option.

=item file_path

This is the absolute path to the certificate file.  It will appear in the 
perfdata as long as the C<file_name> was found in the configuration file.

=item subject

This is all of the fields from the Subject section of the certificate.  Fields 
are separated with a C</> (a forward-slash), and an C<=> (an equals sign) is 
used to separate the key from the value.

The C<CN> (common name) field is what is used in the human-readable output.

It will appear in the perfdata as long as the file loaded was actually a 
certificate.

=item issuer

This is all of the fields from the Issuer section of the certificate.  The 
format is the same as with the C<subject> section.

It will appear in the perfdata as long as the file loaded was actually a 
certificate.

=item expiration_isotime

This is the certificate expiration date, in L<RFC 
3339|https://www.ietf.org/rfc/rfc3339.txt> format.  It will appear in the 
perfdata if the file loaded was actually a certificate, and if it has an 
expiration date (also known as a C<notAfter> date).

=item expiration_remaining

This is the amount of time remaining before expiration, in ISO 8601 duration 
format.  The form is "PnYnMnDTnHnMnS" (so, similar to the human-readable 
output, but with everything upper-case, and the letters 'P' and 'T').

If the certificate has already expired, then the output is simply "P0W", 
meaning there are zero weeks remaining before expiration.

It will appear in the perfdata under the same conditions as
C<expiration_isotime>.

=back

=head1 PREREQUISITES

There are three Perl module distributions required by this software:

=over 4

=item Net-SSLeay

This is the interface to OpenSSL, so you B<must> use a L<Net::SSLeay> that was 
built with the version of OpenSSL that is installed on the local system.

At least version 1.43 is required, because that introduced some of the methods 
we use.  There is also a requirement of OpenSSL at least version 0.9.8, which 
should be available on any relatively-modern system.

=item DateTime

This is used for all of the expiration-date math.

=item DateTime-Format-RFC3339

The L<DateTime::Format::RFC3339> module, which ships separately from 
L<DateTime>, is used to parse the dates provided by L<Net::SSLeay>.

=back

=head1 AUTHOR

A. Karl Kornel, L<akkornel@stanford.edu|mailto:akkornel@stanford.edu>
