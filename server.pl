#!/usr/bin/env perl

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
my $sendmail = $ENV{'SENDMAIL'} || '/usr/bin/sendmail';

my $pw_token_expiration_minutes = $ENV{'PW_TOKEN_EXPIRATION_MINUTES'} || 10;
my $auth_token_default_expiration_minutes = $ENV{'AUTH_TOKEN_DEFAULT_EXPIRATION_MINUTES'} || 5;
my $minimum_password_length = $ENV{'MINIMUM_PASSWORD_LENGTH'} || 8;
my $minimum_email_length = $ENV{'MINIMUM_EMAIL_LENGTH'} || 6;
my $maximum_email_length = $ENV{'MAXIMUM_EMAIL_LENGTH'} || 120;
my $maximum_plan_length = $ENV{'MAXIMUM_PLAN_LENGTH'} || 4096;
my $maximum_signature_length = $ENV{'MAXIMUM_SIGNATURE_LENGTH'} || 1024;
my $maximum_pubkey_length = $ENV{'MAXIMUM_PUBKEY_LENGTH'} || 5125;

my $hostname = $ENV{'HOSTNAME'};
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

  # Caching DNS resolver
  {
    package Net::DNS::Resolver;
    my %cache;
    sub query {
      my $self = shift;
      $cache{"@_"} ||= $self->SUPER::query(@_);
    }
  }

  use IPC::Run;
  use DBI;
  use File::Temp qw(tempfile);
  use Fcntl qw(:flock);
  use Net::DNS::Resolver;
  use Crypt::Eksblowfish::Bcrypt qw(bcrypt_hash en_base64);
  use MIME::Base64 qw(decode_base64);
  use POSIX qw(strftime);
  use JSON qw(encode_json decode_json);
  use URI::Escape qw(uri_escape);
  use HTML::Entities qw(encode_entities);
  use String::ShellQuote qw(shell_quote);

  ###############
  # Common Errors
  ###############

  my $not_found = encode_json({error => 'Not found.'});
  my $not_implemented = encode_json({error => 'Not implemented yet.'});
  my $not_allowed = encode_json({error => 'HTTP method not supported.'});
  my $not_authorized = encode_json({error => 'Not authorized.'});

  my $resp_header = {
    200 => 'OK',
    301 => 'Moved Permanently',
    308 => 'Permanent Redirect',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    429 => 'Too Many Requests',
    501 => 'Not Implemented',
    500 => 'Internal Server Error'
  };

  #################
  # Request Routing
  #################

  sub handle_request {
    my ($self, $cgi) = @_;
    # assign a random request id for anonymous logging
    my $req_id = util_req_id();
    $cgi->param('request_id', $req_id);
    my $path = $cgi->path_info();
    my $method = $cgi->request_method();
    my $host = $cgi->http('X-Forwarded-For') || $cgi->remote_addr();

    eval {
      util_log("REQ $req_id $method $path");
      if ($method eq 'GET') {
        if ($path =~ /^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          validate_email($1, $cgi);
        } elsif ($path =~ /^\/token$/) {
          get_token($cgi);
        } elsif ($path =~ /^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})\/pwtoken$/) {
          get_pwtoken($1, $cgi);
        } elsif ($path =~ /^\/plan\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          get_plan($1, $cgi);
        } else {
          print_response($cgi, 404, $not_found);
        }
      } elsif ($method eq 'POST') {
        if ($path =~ /^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          create_user($1, $cgi);
        } elsif ($path =~ /^\/verify\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          verify_plan($1, $cgi);
        } else {
          print_response($cgi, 404, $not_found);
        }
      } elsif ($method eq 'PUT') {
        if ($path =~ /^\/users\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          update_password($1, $cgi);
        } elsif ($path =~ /^\/plan\/([^\/]{$minimum_email_length,$maximum_email_length})$/) {
          update_plan($1, $cgi);
        } else {
          print_response($cgi, 404, $not_found);
        }
      } elsif ($method eq 'DELETE') {
        if ($path =~ /^\/token$/) {
          delete_token($cgi);
        } else {
          print_response($cgi, 404, $not_found);
        }
      } else {
        print_response($cgi, 405, $not_allowed);
      }
    };
    if ($@) {
      print_json_response($cgi, 500, {error => 'An unexpected error occurred.'});
      util_log("ERR $req_id $@");
    }
  }

  ##################
  # Response Handler
  ##################

  sub print_response {
    my ($cgi, $code, $body, $type, $redirect) = @_;
    my $req_id = $cgi->param('request_id');
    my $path = $cgi->path_info();
    my $method = $cgi->request_method();
    my $host = $cgi->http('X-Forwarded-For') || $cgi->remote_addr();
    util_log("RES($code) $req_id $method $path");

    my $header = $resp_header->{$code};
    if (!defined $type) {
      $type = 'application/json';
    }
    my $length = length($body);
    my $date = strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time()));
    my $redirect_header = '';
    if (defined $redirect) {
      $redirect_header = "\nLocation: $redirect";
    }
    print <<EOF;
HTTP/1.1 $code $header
Server: DotplanApi
Date: $date
Content-Type: $type
Content-Length: $length$redirect_header
EOF
    print "\n$body";
  }

  sub print_json_response {
    my ($cgi, $code, $data) = @_;
    print_response($cgi, $code, encode_json($data));
  }

  sub print_html_response {
    # TODO: external template
    my ($cgi, $code, $content) = @_;
    print_response($cgi, $code, <<EOF
<!doctype html>
<html lang='en'>
  <head>
    <title>Dotplan Online</title>
    <meta charset='utf-8'>
  </head>
  <body>
  <p>$content</p>
  </body>
</html>
EOF
    , 'text/html');
  }

  ####################
  # API Implementation
  ####################

  ##### POST /users/{email}
  sub create_user {
    my ($email, $cgi) = @_;
    if ($email !~ /^[^\@]+\@[^\@\.]+\.[^\@]+$/) {
      print_json_response($cgi, 400, {error => 'Only email addresses of the form {local}@{domain.tld} are supported.'});
    } else {
      my $user = util_get_user($email);
      if (defined $user && $user->{'verified'}) {
        print_json_response($cgi, 400, {error => 'User already exists.'});
      } elsif (defined $user && defined $user->{'pw_token_expires'} && $user->{'pw_token_expires'} >= time) {
        print_json_response($cgi, 429, {error => "Please wait up to $pw_token_expiration_minutes minutes and try again."});
      } else {
        my $password = util_json_body($cgi)->{'password'};
        if (!defined $password || length($password) < $minimum_password_length) {
          print_json_response($cgi, 400, {error => "Password must be at least $minimum_password_length characters long."});
        } else {
          my $query = (defined $user)
            ? "UPDATE users SET password=?, pw_token=?, pw_token_expires=datetime('now', '+$pw_token_expiration_minutes minutes') WHERE email=?"
            : "INSERT INTO users (password, pw_token, pw_token_expires, email) values (?, ?, datetime('now', '+$pw_token_expiration_minutes minutes'), ?)";
          my $crypted = util_bcrypt($password);
          my $sth = util_get_dbh()->prepare($query);
          $sth->execute($crypted, util_token(), $email);
          die $sth->errstr if $sth->err;
          # TODO: send email
          print_json_response($cgi, 200, {email => $email});
        }
      }
    }
  }

  ##### GET /users/{email}?token={token}
  sub validate_email {
    my ($email, $cgi) = @_;
    my $token = $cgi->param('token');
    if (!defined $token) {
      print_html_response($cgi, 400, 'No token found in request.');
    } else {
      my $user = util_get_user($email);
      if (!defined $user || $user->{'verified'}) {
        print_html_response($cgi, 404, 'User not found.');
      } elsif ($user->{'pw_token'} ne $token) {
        print_html_response($cgi, 400, 'Bad or expired token.');
      } else {
        my $sth = util_get_dbh()->prepare('UPDATE users SET verified=1, pw_token=null, pw_token_expires=null WHERE email=?');
        $sth->execute($email);
        die $sth->errstr if $sth->err;
        print_html_response($cgi, 200, 'Your email address has been verified.');
      }
    }
  }

  ##### GET /token
  sub get_token {
    my $cgi = shift;
    my $user = util_get_authenticated($cgi);
    if (!defined $user) {
      print_response($cgi, 401, $not_authorized);
    } else {
      my $sth = util_get_dbh()->prepare("UPDATE users SET token=?, token_expires=datetime('now', ?) WHERE email=?");
      my $token = util_token();
      my $expires = $cgi->param('expires');
      my $minutes = $auth_token_default_expiration_minutes;
      if ($expires =~ /^\d+$/) {
        $minutes = int($expires);
        if ($minutes <= 0) {
          $minutes = $auth_token_default_expiration_minutes;
        }
      }
      $sth->execute($token, "+$minutes minutes", $user->{'email'});
      die $sth->errstr if $sth->err;
      print_json_response($cgi, 200, {token => $token});
    }
  }

  ##### DELETE /token
  sub delete_token {
    my $cgi = shift;
    my $user = util_get_authenticated($cgi);
    if (!defined $user) {
      print_response($cgi, 401, $not_authorized);
    } else {
      my $sth = util_get_dbh()->prepare('UPDATE users SET token=null, token_expires=null WHERE email=?');
      $sth->execute($user->{'email'});
      die $sth->errstr if $sth->err;
      print_json_response($cgi, 200, {success => 1});
    }
  }

  ##### GET /users/{email}/pwtoken
  sub get_pwtoken {
    my ($email, $cgi) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_html_response($cgi, 404, 'User not found.');
    } elsif (defined $user->{'pw_token_expires'} && $user->{'pw_token_expires'} >= time) {
      print_html_response($cgi, 429, "Please wait up to $pw_token_expiration_minutes minutes and try again.");
    } else {
      my $token = util_token();
      my $sth = util_get_dbh()->prepare("UPDATE users SET pw_token=?, pw_token_expires=datetime('now', '+10 minutes') WHERE email=?");
      $sth->execute($token, $email);
      die $sth->errstr if $sth->err;
      # TODO: send email
      print_html_response($cgi, 200, 'Check your email and follow the instructions to change your password.');
    }
  }

  ##### PUT /users/{email}
  sub update_password {
    my ($email, $cgi) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_response($cgi, 404, $not_found);
    } else {
      my $body = util_json_body($cgi);
      my $password = $body->{'password'};
      my $pwtoken = $body->{'pwtoken'};
      if (!defined $pwtoken || !defined $user->{'pw_token'} || !defined $user->{'pw_token_expires'} || $pwtoken ne $user->{'pw_token'} || $user->{'pw_token_expires'} < time) {
        print_json_response($cgi, 400, {error => 'Bad or expired token.'});
      } elsif (!defined $password || length($password) < $minimum_password_length) {
        print_json_response($cgi, 400, {error => "Password must be at least $minimum_password_length characters long."});
      } else {
        my $crypted = util_bcrypt($password);
        my $sth = util_get_dbh()->prepare('UPDATE users SET password=?, pw_token=null, pw_token_expires=null, token=null, token_expires=null WHERE email=?');
        $sth->execute($crypted, $email);
        die $sth->errstr if $sth->err;
        print_json_response($cgi, 200, {success => 1});
      }
    }
  }

  ##### PUT /plan/{email}
  sub update_plan {
    my ($email, $cgi) = @_;
    my $user = util_get_user($email);
    if (!defined $user || !$user->{'verified'}) {
      print_response($cgi, 404, $not_found);
    } else {
      my $body = util_json_body($cgi);
      my $plan = $body->{'plan'};
      my $signature = $body->{'signature'};
      my $token = $body->{'auth'};
      if (!defined $user->{'token'} || !defined $user->{'token_expires'} || !defined $token || $token ne $user->{'token'} || $user->{'token_expires'} < time) {
        print_response($cgi, 401, $not_authorized);
      } elsif (length($plan) > $maximum_plan_length) {
        print_json_response($cgi, 400, {error => "Plan exceeds maximum length of $maximum_plan_length."});
      } elsif (length($signature) > $maximum_signature_length) {
        print_json_response($cgi, 400, {error => "Signature exceeds maximum length of $maximum_signature_length."});
      } else {
        util_save_plan($email, $plan, $signature);
        print_json_response($cgi, 200, {success => 1});
      }
    }
  }

  ##### GET /plan/{email}
  sub get_plan {
    my ($email, $cgi) = @_;

    my $format = util_get_response_format($cgi);
    my $plan = util_get_plan($email);

    if (defined $plan && defined $plan->{'redirect'}) {
      # found external plan service, redirect request
      print_response($cgi, 301, encode_json({location => $plan->{'redirect'}}), 'application/json', $plan->{'redirect'});
    } elsif (defined $plan) {
      # found local plan, render response
      my $body;
      if ($format eq 'application/json') {
        $body = encode_json($plan);
      } elsif ($format eq 'text/html') {
        $body = encode_entities($plan->{'plan'});
        $body =~ s/\n/<br>\n/g;
      } else {
        $body = $plan->{'plan'};
      }
      print_response($cgi, 200, $body, $format);
    } else {
      if ($format eq 'application/json') {
        print_response($cgi, 404, $not_found);
      } elsif ($format eq 'text/html') {
        print_html_response($cgi, 404, 'No plan found.');
      } else {
        print_response($cgi, 404, '', 'text/plain');
      }
    }
  }

  ##### POST /verify/{email}
  sub verify_plan {
    my ($email, $cgi) = @_;

    my $plan = util_get_plan($email);

    if (defined $plan && defined $plan->{'redirect'}) {
      # found external plan service, redirect request
      print_response($cgi, 308, encode_json({location => $plan->{'redirect'}}), 'application/json', $plan->{'redirect'});
    } elsif (defined $plan) {
      my $pubkey = util_json_body($cgi)->{'pubkey'};
      if (!defined $pubkey || !defined $plan->{'signature'}) {
        print_json_response($cgi, 200, {verified => 0});
      } elsif (length($pubkey) > $maximum_pubkey_length) {
        print_json_response($cgi, 400, {error => "Pubkey exceeds maximum length of $maximum_pubkey_length."});
      } else {
        my ($keyfh, $keyfile) = tempfile('tmpXXXXXX', TMPDIR => 1);
        print $keyfh $pubkey;
        close($keyfh);
        my $basename = "$plan_dir/" . shell_quote($email);
        if(
          (IPC::Run::run ['gpg2', '--dearmor'], '<', $keyfile, '>', "$keyfile.gpg", '2>>', '/dev/null') &&
          (IPC::Run::run ['gpg2', '--no-default-keyring', '--keyring', "$keyfile.gpg", '--verify', "$basename.asc", "$basename.plan"], '>', '/dev/null', '2>>', '/dev/null')
        ) {
          print_json_response($cgi, 200, {
            plan => $plan->{'plan'},
            verified => 1
          });
        } else {
          print_json_response($cgi, 200, {verified => 0});
        }
      }
    } else {
      print_response($cgi, 404, $not_found);
    }
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
      open($_log, '>>', $log_file);
      binmode($_log, ':unix');
    }
    print $_log "$timestamp $msg\n";
  }

  sub util_get_response_format {
    my $cgi = shift;
    my $accept = $cgi->http('Accept');
    my $format = lc($cgi->param('format') || $cgi->http('Accept'));
    if ($format eq 'json' || $format eq 'application/json') {
      return 'application/json';
    } elsif ($format eq 'html' || $format eq 'text/html') {
      return 'text/html';
    }
    return 'text/plain';
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
    $salt .= substr($itoa64,int(rand(64)),1) while length($salt) < 16;
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
    my $itoa62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    my $token = '';
    $token .= substr($itoa62,int(rand(62)),1) while length($token) < 24;
    return $token;
  }

  # generate a random request id
  sub util_req_id {
    my $itoa36 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    my $id = '';
    $id .= substr($itoa36,int(rand(36)),1) while length($id) < 8;
    return $id;
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
  my $_plancache = {};
  sub util_save_plan {
    my ($email, $plan, $signature) = @_;
    my $basename = "$plan_dir/" . shell_quote($email);

    if (defined $plan) {
      open(my $plan_file, '>', "$basename.plan");
      flock($plan_file, LOCK_EX);
      print $plan_file $plan;
      close($plan_file);
    } elsif (-f "$basename.plan") {
      unlink "$basename.plan";
    }

    if (defined $plan && defined $signature) {
      open(my $sig_file, '>', "$basename.asc");
      flock($sig_file, LOCK_EX);
      print $sig_file $signature;
      close($sig_file);
    } elsif (-f "$basename.asc") {
      unlink "$basename.asc";
    }

    # invalidate cache
    delete $_plancache->{$email} if $_plancache->{$email};
  }

  # read a plan from cache or disk
  sub util_read_plan {
    my $email = shift;
    if (!defined $_plancache->{$email}) {
      my $basename = "$plan_dir/" . shell_quote($email);

      if (-f "$basename.plan") {
        my $details = {};
        open(my $plan_file, '<', "$basename.plan");
        flock($plan_file, LOCK_SH);
        local $/;
        $details->{'plan'} = <$plan_file>;
        close($plan_file);

        if (-f "$basename.asc") {
          open(my $sig_file, '<', "$basename.asc");
          flock($sig_file, LOCK_SH);
          local $/;
          $details->{'signature'} = <$sig_file>;
          close($sig_file);
        }

        $_plancache->{$email} = $details;
      }
    }
    return $_plancache->{$email};
  }

  # retrieve a plan by email
  my $_dns = new Net::DNS::Resolver();
  sub util_get_plan {
    my $email = shift;
    my ($local, $domain) = split(/\@/, $email, 2);
    if (!$localdomains->{$domain}) {
      my $reply = $_dns->query("_dotplan._tcp.$domain", 'SRV');
      if (defined $reply && $reply->answer > 0) {
        my @answer = $reply->answer;
        my ($pri, $wgt, $port, $svchost) = split(/\s+/, $answer[0]->rdstring, 4);
        $svchost =~ s/\.$//;
        my $encoded = uri_escape($email);
        if ($hostname ne $svchost) {
          return {
            redirect => $port == 80
              ? "http://$svchost/$encoded"
              : $port == 443
                ? "https://$svchost/$encoded"
                : "https://$svchost:$port/$encoded"
          };
        } else {
          return util_read_plan($email);
        }
      } else {
        return util_read_plan($email);
      }
    } else {
      return util_read_plan($email);
    }
  }

  # decode json post data to an object
  sub util_json_body {
    my $cgi = shift;
    my $json = $cgi->param('POSTDATA') || $cgi->param('PUTDATA');
    return decode_json($json);
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
