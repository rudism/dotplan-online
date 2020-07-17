#!/usr/bin/env perl

use utf8;
use strict;
use warnings;
use open qw(:std :utf8);

######################
# Server Configuration
######################

my $server_port = 4227;

#########################################
# dotplan.online Reference Implementation
#########################################

{
  package DotplanApi;
  use base qw(HTTP::Server::Simple::CGI);
  use POSIX qw(strftime);
  use JSON qw(encode_json decode_json);
  use HTML::Entities qw(encode_entities);

  ###############
  # Common Errors
  ###############

  my $not_found = encode_json({error => 'Not found.'});
  my $not_implemented = encode_json({error => 'Not implemented yet.'});

  #################
  # Request Routing
  #################

  sub handle_request {
    my ($self, $cgi) = @_;
    my $path = $cgi->path_info();
    my $method = $cgi->request_method();

    if ($method eq 'GET') {
      if ($path =~ /^\/plan\/(.*)$/) {
        get_plan($1, $cgi);
      } elsif ($path =~ /^\/users\/([^\/]*)$/) {
        verify_email($1, $cgi);
      } elsif ($path =~ /^\/users\/([^\/]*)\/token$/) {
        get_token($1, $cgi);
      } else {
        print_response(404, $not_found);
      }
    } elsif ($method eq 'POST') {
      if ($path =~ /^\/users\/?$/) {
        create_user($cgi);
      } else {
        print_response(404, $not_found);
      }
    } elsif ($method eq 'PUT') {
      if ($path =~ /^\/plan\/(.*)$/) {
        update_plan($cgi);
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
      print_response(405, encode_json({error => 'Not supported.'}));
    }
  }

  ##################
  # Response Handler
  ##################

  sub print_response {
    my ($code, $body, $type) = @_;
    if (!defined $type) {
      $type = 'application/json';
    }
    my $length = length($body);
    my $date = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time()));
    print <<EOF;
HTTP/1.0 200 OK
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

  ##### GET /plan/{email}
  sub get_plan {
    my ($email, $cgi) = @_;

    my $plan = {plan => 'my plan & goals in life </sarcasm>'};

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
  }

  ##### GET /users/{email}?token={token}
  sub verify_email { print_response(501, $not_implemented); }

  ##### GET /users/{email}/token
  sub get_token { print_response(501, $not_implemented); }

  ##### POST /users
  sub create_user { print_response(501, $not_implemented); }

  ##### PUT /plan/{email}
  sub update_plan { print_response(501, $not_implemented); }

  ##### DELETE /users/{email}/token
  sub delete_token { print_response(501, $not_implemented); }
}

# start server in background
my $pid = DotplanApi->new($server_port)->background();
print "Use 'kill $pid' to stop server.\n";
