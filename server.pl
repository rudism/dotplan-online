#!/usr/bin/env perl

use local::lib;
use utf8;
use strict;
use warnings;
use open qw(:std :utf8);

######################
# Server Configuration
######################

my $server_port = $ENV{'PORT'} || 4227;
my $pid_file = $ENV{'PID_FILE'} || './data/dotplan.pid';
my $log_file = $ENV{'LOG_FILE'} || './data/dotplan.log';
my $database = $ENV{'DATABASE'} || './data/users.db';
my $plan_dir = $ENV{'PLAN_DIR'} || './data/plans';
my $cache_dir = $ENV{'CACHE_DIR'} || './data/cache';
my $sendmail = $ENV{'SENDMAIL'};
my @sendmail_args = defined $ENV{'SENDMAIL_ARGS'} ? split(/,/, $ENV{'SENDMAIL_ARGS'}) : ();

my $pw_token_expiration_minutes = $ENV{'PW_TOKEN_EXPIRATION_MINUTES'} || 10;
my $auth_token_default_expiration_minutes = $ENV{'AUTH_TOKEN_DEFAULT_EXPIRATION_MINUTES'} || 5;
my $minimum_password_length = $ENV{'MINIMUM_PASSWORD_LENGTH'} || 8;
my $minimum_email_length = $ENV{'MINIMUM_EMAIL_LENGTH'} || 6;
my $maximum_email_length = $ENV{'MAXIMUM_EMAIL_LENGTH'} || 120;
my $maximum_plan_length = $ENV{'MAXIMUM_PLAN_LENGTH'} || 4096;
my $maximum_signature_length = $ENV{'MAXIMUM_SIGNATURE_LENGTH'} || 1024;
my $maximum_pubkey_length = $ENV{'MAXIMUM_PUBKEY_LENGTH'} || 5125;

my $hostname = $ENV{'HOSTNAME'} || '';
my $from_address = $ENV{'MAIL_FROM'} || "do-not-reply\@$hostname";
my $localdomains = {};
if (defined $ENV{'LOCAL_DOMAINS'}) {
  $localdomains->{$_}++ for (split(/,/, $ENV{'LOCAL_DOMAINS'}));
}

#########################################
# dotplan.online Reference Implementation
#########################################

{
  package DotplanApi;
  use base qw(HTTP::Server::Simple::CGI);
  sub net_server { 'Net::Server::Fork' }
  my $webroot = './static';

  use Cache::FileCache;
  use HTTP::Server::Simple::Static;
  use IPC::Run;
  use DBI;
  use File::Temp qw(tempfile);
  use Fcntl qw(:flock);
  use Net::DNS::Resolver;
  use Crypt::Random qw(makerandom_itv);
  use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);
  use MIME::Base64 qw(decode_base64);
  use POSIX qw(strftime);
  use JSON qw(encode_json decode_json);
  use HTTP::Accept;
  use URI::Escape qw(uri_escape uri_unescape);
  use File::Spec::Functions qw(catfile);
  use HTML::Entities qw(encode_entities);

  ########
  # Caches
  ########

  # cache plans by email
  my $_plancache = Cache::FileCache->new({cache_root => $cache_dir, namespace => 'plan', default_expires_in => 3600});

  # cache SRV records by domain
  my $_srvcache = Cache::FileCache->new({cache_root => $cache_dir, namespace => 'srv', default_expires_in => 3600});

  # cache static responses
  my $_staticcache = Cache::FileCache->new({cache_root => $cache_dir, namespace => 'static', default_expires_in => 3600});

  ###############
  # Common Errors
  ###############

  my $resp_header = {
    200 => 'OK',
    301 => 'Moved Permanently',
    304 => 'Not Modified',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    406 => 'Not Acceptable',
    429 => 'Too Many Requests',
    500 => 'Internal Server Error'
  };

  my $resp_body = {
    301 => 'Redirecting to the appropriate server for that plan.',
    401 => 'The authorization details provided did not match our records.',
    403 => 'The requested plan signature could not be verified with the specified public key.',
    404 => 'The requested resource was not found.',
    405 => 'The server does not support the specified request method.',
    406 => 'The server does not support any of the requested Content-Types.',
    500 => 'An unexpected error occurred.'
  };

  #################
  # Request Routing
  #################
  #
  my $routes = [
    {
      path => qr/^\/plan\/([^\/]{$minimum_email_length,$maximum_email_length})$/,
      methods => {
        GET => {handler => \&get_plan, valid_types => ['application/json', 'text/plain']},
        HEAD => {handler => \&get_plan, valid_types => ['application/json', 'text/plain']},
        PUT => {handler => \&update_plan, valid_types => ['application/json']}
      }
    },
    {
      path => qr/^\/token$/,
      methods => {
        GET => {handler => \&get_token, valid_types => ['application/json']},
        DELETE => {handler => \&delete_token, valid_types => ['application/json']}
      }
    },
    {
      path => qr/^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})\/pwchange$/,
      methods => {
        GET => {handler => \&get_pwtoken, valid_types => ['application/json']},
        PUT => {handler => \&update_password, valid_types => ['application/json']}
      }
    },
    {
      path => qr/^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})$/,
      methods => {
        POST => {handler => \&create_user, valid_types => ['application/json']},
        PUT => {handler => \&validate_email, valid_types => ['application/json']}
      }
    },
    {
      path => qr/^\/js\/([^\/]{$minimum_email_length,$maximum_email_length})$/,
      methods => {
        GET => {handler => \&get_plan_js, valid_types => ['application/javascript']}
      }
    }
  ];

  sub handle_request {
    my ($self, $cgi) = @_;
    # assign a random request id for anonymous logging
    my $req_id = util_token(12);
    $cgi->param('request_id', $req_id);
    my $path = $cgi->path_info();
    $path =~ s{^https?://([^/:]+)(:\d+)?/}{/};
    $cgi->{'.path_info'} = '/index.html' if $path eq '/';
    my $method = $cgi->request_method();
    my $accept = HTTP::Accept->new($cgi->http('Accept'));
    $cgi->param('accept', $accept);
    my $body = $cgi->param('POSTDATA') || $cgi->param('PUTDATA');
    if (defined $body) {
      eval {
        $cgi->param('json-body', decode_json($body));
      };
      if ($@) {
        print_json_response($cgi, 400, {error => 'Unable to parse json payload.'});
        return;
      }
    } else {
      $cgi->param('json-body', {});
    }

    eval {
      util_log("REQ $req_id $method $path");

      # check for matching handler
      foreach my $route(@$routes) {
        if ($path =~ $route->{'path'}) {
          my $param = $1;
          if (defined $route->{'methods'}->{$method}) {
            if ($accept->match(@{$route->{'methods'}->{$method}->{'valid_types'}})) {
              $route->{'methods'}->{$method}->{'handler'}->($cgi, $param);
              return;
            } else {
              print_response($cgi, 406);
              return;
            }
          } else {
            print_response($cgi, 405);
            return;
          }
        }
      }

      # if no handler, check for static file
      if (!cached_static_file($self, $cgi, $path)) {
        print_response($cgi, 404);
      }
    };
    if ($@) {
      util_log("ERR $req_id $@");
      print_response($cgi, 500);
    }
  }

  sub cached_static_file {
    my ($server, $cgi, $path) = @_;
    my $cached = $_staticcache->get($path);
    if (!defined $cached) {
      open local(*STDOUT), '>', \$cached;
      if (!serve_static($server, $cgi, $webroot)) {
        $cached = 0;
      }
      $_staticcache->set($path, $cached);
    }
    print $cached if $cached;
    return $cached;
  }

  ###################
  # Response Handlers
  ###################

  sub print_response {
    my ($cgi, $code, $headers, $body) = @_;
    my $req_id = $cgi->param('request_id');
    my $path = $cgi->path_info();
    my $method = $cgi->request_method();
    util_log("RES($code) $req_id $method $path");

    $headers = {} if !defined $headers;
    $headers->{'Content-Type'} = $cgi->param('accept')->match(qw(application/json text/plain)) || 'application/json' if !defined $headers->{'Content-Type'};

    my $code_description = $resp_header->{$code};
    if (!defined $body && defined $resp_body->{$code}) {
      $body = $headers->{'Content-Type'} eq 'application/json'
        ? encode_json({error => $resp_body->{$code}})
        : $resp_body->{$code};
    }
    my $length = defined $body ? length($body) : 0;
    $body = '' if !defined $body || $cgi->request_method() eq 'HEAD';
    my $length_header = '';
    if ($length > 0) {
      $length_header = "\nContent-Length: $length";
    }
    my $now = time;
    my $date = HTTP::Date::time2str($now);
    my $extra_headers = '';
    foreach my $header(keys %$headers) {
      my $val = $headers->{$header};
      $extra_headers .= "\n$header: $val";
    }
    print <<EOF;
HTTP/1.1 $code $code_description
Server: DotplanApi
Date: $date$extra_headers$length_header
EOF
    print "\n$body";
  }

  sub print_json_response {
    my ($cgi, $code, $data, $headers) = @_;
    if (!defined $headers) {
      $headers = {};
    };
    $headers->{'Content-Type'} = 'application/json';
    print_response($cgi, $code, $headers, encode_json($data));
  }

  ####################
  # API Implementation
  ####################

  ##### POST /users/{email}
  sub create_user {
    my ($cgi, $email) = @_;
    if ($email !~ /^[^\@]+\@[^\@\.]+\.[^\@]+$/) {
      print_json_response($cgi, 400, {error => 'Only email addresses of the form {local}@{domain.tld} are supported by this server.'});
      return;
    }
    my $user = util_get_user($email);
    if (defined $user && $user->{'verified'}) {
      print_json_response($cgi, 400, {error => 'User already exists.'});
      return;
    }
    if (defined $user && defined $user->{'pw_token_expires'} && $user->{'pw_token_expires'} >= time) {
      print_json_response($cgi, 429, {error => "Wait $pw_token_expiration_minutes minutes between this type of request."});
      return;
    }
    my $password = $cgi->param('json-body')->{'password'};
    if (!defined $password || length($password) < $minimum_password_length) {
      print_json_response($cgi, 400, {error => "Password must be at least $minimum_password_length characters long."});
      return;
    }
    my $query = (defined $user)
      ? "UPDATE users SET password=?, pw_token=?, pw_token_expires=datetime('now', '+$pw_token_expiration_minutes minutes') WHERE email=?"
      : "INSERT INTO users (password, pw_token, pw_token_expires, email) values (?, ?, datetime('now', '+$pw_token_expiration_minutes minutes'), ?)";
    my $crypted = util_bcrypt($password);
    my $sth = util_get_dbh()->prepare($query);
    my $token = util_token(24);
    $sth->execute($crypted, $token, $email);
    die $sth->errstr if $sth->err;
    util_sendmail($cgi, $email, '[DOTPLAN] Verify your email',
      "Please verify your email address.\n" .
      "Your verification token is: $token\n" .
      "Run this (or equivalent) in a terminal:\n\n" .
      "    curl -H 'Content-Type: application/json' \\\n" .
      "      -XPUT -d '{\"token\":\"$token\"}' \\\n" .
      "      https://$hostname/users/$email");
    print_json_response($cgi, 200, {email => $email});
  }

  ##### PUT /users/{email}
  sub validate_email {
    my ($cgi, $email) = @_;
    my $token = $cgi->param('json-body')->{'token'};
    if (!defined $token) {
      print_json_response($cgi, 400, {error => 'Missing token.'});
      return;
    }
    my $user = util_get_user($email);
    if (!defined $user || $user->{'verified'}) {
      print_response($cgi, 404);
      return;
    }
    if ($user->{'pw_token'} ne $token) {
      print_response($cgi, 401);
      return;
    }
    my $sth = util_get_dbh()->prepare('UPDATE users SET verified=1, pw_token=null, pw_token_expires=null WHERE email=?');
    $sth->execute($email);
    die $sth->errstr if $sth->err;
    print_json_response($cgi, 200, {success => 1});
  }

  ##### GET /token
  sub get_token {
    my $cgi = shift;
    my $user = util_get_authenticated($cgi);
    if (!defined $user) {
      print_response($cgi, 401);
      return;
    }
    my $sth = util_get_dbh()->prepare("UPDATE users SET token=?, token_expires=datetime('now', ?) WHERE email=?");
    my $token = util_token(24);
    my $expires = $cgi->param('expires');
    my $minutes = $auth_token_default_expiration_minutes;
    if (defined $expires && $expires =~ /^\d+$/) {
      $minutes = int($expires);
      if ($minutes <= 0) {
        $minutes = $auth_token_default_expiration_minutes;
      }
    }
    $sth->execute($token, "+$minutes minutes", $user->{'email'});
    die $sth->errstr if $sth->err;
    print_json_response($cgi, 200, {token => $token});
  }

  ##### DELETE /token
  sub delete_token {
    my $cgi = shift;
    my $user = util_get_authenticated($cgi);
    if (!defined $user) {
      print_response($cgi, 401);
      return;
    }
    my $sth = util_get_dbh()->prepare('UPDATE users SET token=null, token_expires=null WHERE email=?');
    $sth->execute($user->{'email'});
    die $sth->errstr if $sth->err;
    print_json_response($cgi, 200, {success => 1});
  }

  ##### GET /users/{email}/pwchange
  sub get_pwtoken {
    my ($cgi, $email) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_response($cgi, 404);
      return;
    }
    if (defined $user->{'pw_token_expires'} && $user->{'pw_token_expires'} >= time) {
      print_json_response($cgi, 429, {error => "Wait $pw_token_expiration_minutes between this type of request."});
      return;
    }
    my $token = util_token(24);
    my $sth = util_get_dbh()->prepare("UPDATE users SET pw_token=?, pw_token_expires=datetime('now', '+10 minutes') WHERE email=?");
    $sth->execute($token, $email);
    die $sth->errstr if $sth->err;
    util_sendmail($cgi, $email, '[DOTPLAN] Password reset request',
      "Someone (hopefully you) has requested to change your password.\n" .
      "If it wasn't you, you can ignore and delete this email.\n\n" .
      "Your password change token is: $token\n\n" .
      "Run this (or equivalent) in a terminal after adding your desired\n" .
      "password to the appropriate field in the JSON payload:\n\n" .
      "    curl -H 'Content-Type: application/json' \\\n" .
      "      -XPUT -d '{\"password\":\"\",\"token\":\"$token\"}' \\\n" .
      "      https://$hostname/users/$email/pwchange");
    print_json_response($cgi, 200, {success => 1});
  }

  ##### PUT /users/{email}/pwchange
  sub update_password {
    my ($cgi, $email) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_response($cgi, 404);
      return;
    }
    my $body = $cgi->param('json-body');
    my $password = $body->{'password'};
    my $pwtoken = $body->{'token'};
    if (!defined $pwtoken || !defined $user->{'pw_token'} || !defined $user->{'pw_token_expires'} || $pwtoken ne $user->{'pw_token'} || $user->{'pw_token_expires'} < time) {
      print_json_response($cgi, 400, {error => 'Bad or expired token.'});
      return;
    }
    if (!defined $password || length($password) < $minimum_password_length) {
      print_json_response($cgi, 400, {error => "Password must be at least $minimum_password_length characters long."});
      return;
    }
    my $crypted = util_bcrypt($password);
    my $sth = util_get_dbh()->prepare('UPDATE users SET password=?, pw_token=null, pw_token_expires=null, token=null, token_expires=null WHERE email=?');
    $sth->execute($crypted, $email);
    die $sth->errstr if $sth->err;
    print_json_response($cgi, 200, {success => 1});
  }

  ##### PUT /plan/{email}
  sub update_plan {
    my ($cgi, $email) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_response($cgi, 404);
      return;
    }
    my $body = $cgi->param('json-body');
    my $plan = $body->{'plan'};
    my $signature = $body->{'signature'};
    my $token = $body->{'auth'};
    if (!defined $user->{'token'} || !defined $user->{'token_expires'} || !defined $token || $token ne $user->{'token'} || $user->{'token_expires'} < time) {
      print_response($cgi, 401);
      return;
    }
    if (defined $plan && length($plan) > $maximum_plan_length) {
      print_json_response($cgi, 400, {error => "Plan exceeds maximum length of $maximum_plan_length."});
      return;
    }
    if (defined $signature && length($signature) > $maximum_signature_length) {
      print_json_response($cgi, 400, {error => "Signature exceeds maximum length of $maximum_signature_length."});
      return;
    }
    util_save_plan($email, $plan, $signature);
    print_json_response($cgi, 200, {success => 1});
  }

  ##### GET /plan/{email}
  sub get_plan {
    my ($cgi, $email) = @_;

    my $plan = util_get_plan($email);
    my $format = $cgi->param('accept')->match(qw(text/plain application/json));

    if (defined $plan && defined $plan->{'redirect'}) {
      # found external plan service, redirect request
      print_response($cgi, 301, {Location => $plan->{'redirect'}});
      return;
    }
    if (!defined $plan) {
      my $body = $format eq 'text/plain' ? 'No Plan.' : encode_json({error => 'No Plan.'});
      print_response($cgi, 404, {'Content-Type' => $format}, $body);
      return;
    }
    my $pubkey = $cgi->http('X-Dotplan-Pubkey');
    if ((defined $pubkey && !defined $plan->{'signature'}) ||
      (defined $pubkey && !util_verify_plan($email, $pubkey))) {
      print_response($cgi, 403);
      return;
    }
    # check modified time
    my $now = time;
    my $mtime = $plan->{'mtime'};
    my $ifmod = $cgi->http('If-Modified-Since');
    my $ifmtime = HTTP::Date::str2time($ifmod) if defined $ifmod;
    if (defined $mtime && defined $ifmtime && $ifmtime <= $now && $mtime <= $ifmtime) {
      print_response($cgi, 304);
      return;
    }
    # render response
    my $body;
    delete $plan->{'mtime'};
    if ($format eq 'application/json') {
      $body = encode_json($plan);
    } else {
      $body = $plan->{'plan'};
    }
    my $headers = {
      'Content-Type' => $format,
      'Last-Modified' => HTTP::Date::time2str($mtime)
    };
    if (defined $pubkey) {
      $headers->{'X-Dotplan-Verified'} = 'true';
    }
    print_response($cgi, 200, $headers, $body);
  }

  ##### GET /js/{email}
  sub get_plan_js {
    my ($cgi, $email) = @_;

    my $plan = util_get_plan($email);
    my $format = $cgi->param('accept')->match(qw(application/javascript));

    if (!defined $plan || defined $plan->{'redirect'}) {
      # js can only be requested for locally served plans
      print_response($cgi, 404);
      return;
    }
    my $pubkey = $cgi->http('X-Dotplan-Pubkey');
    if ((defined $pubkey && !defined $plan->{'signature'}) ||
      (defined $pubkey && !util_verify_plan($email, $pubkey))) {
      print_response($cgi, 403);
      return;
    }
    # check modified time
    my $now = time;
    my $mtime = $plan->{'mtime'};
    my $ifmod = $cgi->http('If-Modified-Since');
    my $ifmtime = HTTP::Date::str2time($ifmod) if defined $ifmod;
    if (defined $mtime && defined $ifmtime && $ifmtime <= $now && $mtime <= $ifmtime) {
      print_response($cgi, 304);
      return;
    }
    # render response
    delete $plan->{'mtime'};
    my $escapedPlan = encode_entities($plan->{'plan'});
    $escapedPlan =~ s/'/\\'/g;
    $escapedPlan =~ s/\n/\\n/g;
    my $body = "document.getElementById('dotplan').innerHTML = '$escapedPlan';";
    my $headers = {
      'Content-Type' => 'application/javascript',
      'Last-Modified' => HTTP::Date::time2str($mtime)
    };
    if (defined $pubkey) {
      $headers->{'X-Dotplan-Verified'} = 'true';
    }
    print_response($cgi, 200, $headers, $body);
  }

  ###################
  # Utility Functions
  ###################

  # get a database connection
  my $_dbh = undef;
  sub util_get_dbh {
    if (!defined $_dbh) {
      $_dbh = DBI->connect("DBI:SQLite:dbname=$database", '', '', { RaiseError => 1 }) or die $DBI::errstr;
    }
    return $_dbh;
  }

  # print a line to the log
  my $_log = undef;
  sub util_log {
    my $msg = shift;
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime(time()));
    if (!defined $_log) {
      open($_log, '>>', $log_file) or die $!;
      binmode($_log, ':unix');
    }
    print $_log "$timestamp $msg\n";
  }

  # send an email
  sub util_sendmail {
    my ($cgi, $recipient, $subject, $body) = @_;

    my $email = <<EOF;
To: $recipient
From: $from_address
Subject: $subject

$body
EOF

    if (defined $sendmail) {
      eval {
        my @arg = ($sendmail);
        push @arg, @sendmail_args;
        push @arg, $recipient;
        IPC::Run::run \@arg, \$email or die "sendmail exited with $?";
      };
      if ($@) {
        my $req_id = $cgi->param('request_id');
        util_log("ERR(sendmail) $req_id $@");
      }
    }
  }

  # encrypt a password with a provided or random salt
  sub util_bcrypt {
    my ($password, $salt) = @_;
    if (!defined $salt) {
      $salt = util_salt();
    }
    my $hash = bcrypt_hash({
      key_nul => 1,
      cost => 8,
      salt => $salt
    }, $password);
    return join('-', $salt, en_base64($hash));
  }

  # verify a plaintext password against a password hash
  sub util_verify_password {
    my ($password, $crypted) = @_;
    my ($salt) = split(/-/, $crypted);
    my $check = util_bcrypt($password, $salt);
    return $check eq $crypted;
  }

  # generate a random salt for bcrypt
  sub util_salt {
    my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    my $salt = '';
    $salt .= substr($itoa64,int(makerandom_itv(Strength => 0, Upper => 64)),1) while length($salt) < 16;
    return $salt;
  }

  # validate authorization header and return user from the database
  sub util_get_authenticated {
    my $cgi = shift;
    my $encoded = $cgi->http('Authorization');
    if (!defined $encoded || $encoded !~ /^Basic (\S+)/) {
      return undef;
    }
    $encoded =~ s/^Basic //;
    my $auth = undef;
    eval {
      $auth = decode_base64($encoded);
    };
    if ($@ || !defined $auth) {
      return undef;
    }
    my ($email, $password) = split(/:/, $auth, 2);
    if (!defined $email || !defined $password) {
      return undef;
    }
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      return undef;
    }
    return util_verify_password($password, $user->{'password'})
      ? $user
      : undef;
  }

  # generate an authorization token
  sub util_token {
    my $length = shift;
    my $chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    my $token = '';
    $token .= substr($chars,int(makerandom_itv(Strength => 0, Upper => 62)),1) while length($token) < $length;
    return $token;
  }

  # get a user from the database by email
  sub util_get_user {
    my $email = shift;
    my $sth = util_get_dbh()->prepare("SELECT email, password, token, strftime('%s', token_expires) AS token_expires, pw_token, strftime('%s', pw_token_expires) AS pw_token_expires, verified, strftime('%s', created) AS created, strftime('%s', updated) AS updated FROM users WHERE email=?");
    $sth->execute($email);
    die $sth->errstr if $sth->err;
    my $user = $sth->fetchrow_hashref;
    return (keys %$user > 0) ? $user : undef;
  }

  # save a plan by email
  sub util_save_plan {
    my ($email, $plan, $signature) = @_;
    my $basename = catfile($plan_dir, $email);

    if (defined $plan) {
      open(my $plan_file, '>', "$basename.plan") or die $!;
      flock($plan_file, LOCK_EX);
      print $plan_file $plan;
      close($plan_file);
    } elsif (-f "$basename.plan") {
      unlink "$basename.plan";
    }

    if (defined $plan && defined $signature) {
      open(my $sig_file, '>', "$basename.sig") or die $!;
      flock($sig_file, LOCK_EX);
      print $sig_file $signature;
      close($sig_file);
    } elsif (-f "$basename.sig") {
      unlink "$basename.sig";
    }

    # invalidate cache
    $_plancache->remove($email);
  }

  # read a plan from cache or disk
  sub util_read_plan {
    my $email = shift;
    my $cached = $_plancache->get($email);
    if (!defined $cached) {
      my $basename = catfile($plan_dir, $email);

      if (-f "$basename.plan") {
        $cached = {};
        open(my $plan_file, '<', "$basename.plan") or die $!;
        flock($plan_file, LOCK_SH);
        my $mtime = (stat($plan_file))[9];
        my $timestamp = HTTP::Date::time2str($mtime);
        $cached->{'mtime'} = $mtime;
        $cached->{'timestamp'} = $timestamp;
        local $/;
        $cached->{'plan'} = <$plan_file>;
        close($plan_file);

        if (-f "$basename.sig") {
          open(my $sig_file, '<', "$basename.sig") or die $!;
          flock($sig_file, LOCK_SH);
          local $/;
          $cached->{'signature'} = <$sig_file>;
          close($sig_file);
        }

        $_plancache->set($email, $cached);
      }
    }
    return $cached;
  }

  # retrieve a plan by email
  sub util_get_plan {
    my $email = shift;
    my ($local, $domain) = split(/\@/, $email, 2);
    if (!$localdomains->{$domain}) {
      my $cached = $_srvcache->get($domain);
      if (!defined $cached) {
        my $dns = Net::DNS::Resolver->new();
        my $reply = $dns->query("_dotplan._tcp.$domain", 'SRV');
        if (defined $reply && $reply->answer > 0) {
          my @answer = $reply->answer;
          my (undef, undef, $port, $svchost) = split(/\s+/, $answer[0]->rdstring, 4);
          $svchost =~ s/\.$//;
          if ($hostname ne $svchost) {
            $cached = $port == 80
              ? "http://$svchost"
              : $port == 443
                ? "https://$svchost"
                : "https://$svchost:$port";
            $_srvcache->set($domain, $cached);
          } else {
            $cached = 0;
          }
        } else {
          $cached = 0;
        }
      }
      if ($cached) {
        my $encoded = uri_escape($email);
        return {redirect => "$cached/plan/$encoded"};
      } else {
        return util_read_plan($email);
      }
    } else {
      return util_read_plan($email);
    }
  }

  # verify a plan signature with a pubkey
  sub util_verify_plan {
    my ($email, $pubkey) = @_;

    my $basename = catfile($plan_dir, $email);
    if(IPC::Run::run ['minisign', '-Vm', "$basename.plan", '-x', "$basename.sig", '-P', "$pubkey"], '>', '/dev/null', '2>>', '/dev/null') {
      return 1;
    }
    return 0;
  }
}

# only supports one optional argument -d to daemonize
my $daemonize = $ARGV[0] eq '-d' if @ARGV == 1;

# start server and fork process as current user
my ($user, $passwd, $uid, $gid) = getpwuid $<;
my $group = getgrgid $gid;
if ($daemonize) {
  DotplanApi->new($server_port)->background(
    pid_file => $pid_file,
    user => $user,
    group => $group
  );
} else {
  DotplanApi->new($server_port)->run(
    pid_file => $pid_file,
    user => $user,
    group => $group
  );
}
