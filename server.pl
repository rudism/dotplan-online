#!/usr/bin/env perl

use utf8;
use strict;
use warnings;
use open qw(:std :utf8);

######################
# Server Configuration
######################

my $server_port = 4227;
my $pid_file = './dotplan.pid';

#########################################
# dotplan.online Reference Implementation
#########################################

{
  package DotplanApi;
  use base qw(HTTP::Server::Simple::CGI);

  use DBD::SQLite;
  use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64 de_base64);
  use POSIX qw(strftime);
  use JSON qw(encode_json decode_json);
  use HTML::Entities qw(encode_entities);

  ###############
  # Common Errors
  ###############

  my $not_found = encode_json({error => 'Not found.'});
  my $not_implemented = encode_json({error => 'Not implemented yet.'});
  my $not_allowed = encode_json({error => 'HTTP method not supported.'});

  my $resp_header = {
    200 => 'OK',
    404 => 'Not Found',
    501 => 'Not Implemented',
    405 => 'Method Not Allowed'
  };

  #################
  # Request Routing
  #################

  sub handle_request {
    my ($self, $cgi) = @_;
    my $path = $cgi->path_info();
    my $method = $cgi->request_method();

    if ($method eq 'GET') {
      if ($path =~ /^\/users\/([^\/]*)$/) {
        validate_email($1, $cgi);
      } elsif ($path =~ /^\/users\/([^\/]*)\/token$/) {
        get_token($1, $cgi);
      } elsif ($path =~ /^\/users\/([^\/]*)\/pwtoken$/) {
        get_pwtoken($1, $cgi);
      } elsif ($path =~ /^\/plan\/(.*)$/) {
        get_plan($1, $cgi);
      } else {
        print_response(404, $not_found);
      }
    } elsif ($method eq 'POST') {
      if ($path =~ /^\/users\/([^\/]*)$/) {
        create_user($1, $cgi);
      } elsif ($path =~ /^\/verify\/([^\/]*)$/) {
        verify_plan($1, $cgi);
      } elsif ($path =~ /^\/multi$/) {
        multi_plan($cgi);
      } else {
        print_response(404, $not_found);
      }
    } elsif ($method eq 'PUT') {
      if ($path =~ /^\/users\/([^\/]*)$/) {
        update_password($1, $cgi);
      } elsif ($path =~ /^\/plan\/(.*)$/) {
        update_plan($1, $cgi);
      } else {
        print_response(404, $not_found);
      }
    } elsif ($method eq 'DELETE') {
      if ($path =~ /^\/users\/([^\/]*)\/token$/) {
        delete_token($1, $cgi);
      } else {
        print_response(404, $not_found);
      }
    } else {
      print_response(405, $not_allowed);
    }
  }

  ##################
  # Response Handler
  ##################

  sub print_response {
    my ($code, $body, $type) = @_;
    my $header = $resp_header->{$code};
    if (!defined $type) {
      $type = 'application/json';
    }
    my $length = length($body);
    my $date = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time()));
    print <<EOF;
HTTP/1.0 $code $header
Server: DotplanApi
Date: $date
Content-Type: $type
Content-Length: $length
EOF
    print "\n$body";
  }

  ####################
  # API Implementation
  ####################

  ##### POST /users/{email}
  sub create_user { print_response(501, $not_implemented); }

  ##### GET /users/{email}?token={token}
  sub validate_email { print_response(501, $not_implemented); }

  ##### GET /users/{email}/token
  sub get_token { print_response(501, $not_implemented); }

  ##### DELETE /users/{email}/token
  sub delete_token { print_response(501, $not_implemented); }

  ##### GET /users/{email}/pwtoken
  sub get_pwtoken { print_response(501, $not_implemented); }

  ##### PUT /users/{email}
  sub update_password { print_response(501, $not_implemented); }

  ##### PUT /plan/{email}
  sub update_plan { print_response(501, $not_implemented); }

  ##### GET /plan/{email}
  sub get_plan {
    my ($email, $cgi) = @_;

    my $plan = util_get_plan($email);

    if (defined $plan) {
      # found plan, render response

      my $accept = $cgi->http('Accept');
      my $format = lc($cgi->param('format') || $cgi->http('Accept'));
      my $body;
      if ($format eq 'json' || $format eq 'application/json') {
        $format = 'application/json';
        $body = encode_json($plan);
      } elsif ($format eq 'html' || $format eq 'text/html') {
        $format = 'text/html';
        $body = encode_entities($plan->{'plan'});
      } else {
        $format = 'text/plain';
        $body = $plan->{'plan'};
      }

      print_response(200, $body, $format);
    } else {
      print_response(404, $not_found);
    }
  }

  ##### POST /verify/{email}
  sub verify_plan { print_response(501, $not_implemented); }

  ##### POST /multi
  sub multi_plan { print_response(501, $not_implemented); }

  ###################
  # Utility Functions
  ###################

  sub util_get_plan {
    my $email = shift;
    # return {plan => 'I have no plans & aspirations in life. </sarcasm>'};
    return undef;
  }
}

# start server in background
my $pid = DotplanApi->new($server_port)->background();
open(my $pidout, '>', $pid_file) || die "Error writing pid: $!";
print $pidout "$pid";
close($pidout);
print "Use 'kill $pid' to stop server.\n";
