package POE::Component::Client::HTTP::RequestStore; 
use strict;
use warnings;

use constant {
  CS_REQUEST_BY_EXT_REQUEST           => 0,
  CS_REQUEST_BY_WHEEL_ID              => 1,
  CS_REQUEST_BY_ID                    => 2,
  
  CS_WHEEL_BY_ID                      => 3,
  CS_WHEEL_BY_CONNECTION              => 4,
  CS_WHEEL_BY_SSL_PROXY_HOST_PAIR     => 5,
  
  CS_CONNECTION_BY_REQUEST            => 6,
  CS_CONNECTION_BY_WHEEL              => 7,
  CS_CONNECTION_BY_SSL_PROXY_SOCK     => 8,
  _CS_MAX                             => 9,
  
  DEBUG                               => $ENV{POCO_HTTP_DEBUG} || 0,
};

my @HAS_REQUEST_VALUES = (
  CS_REQUEST_BY_EXT_REQUEST,
  CS_REQUEST_BY_ID,
  CS_REQUEST_BY_WHEEL_ID,
);

my @HAS_WHEEL_VALUES = (
  CS_WHEEL_BY_ID,
  CS_WHEEL_BY_CONNECTION,
  CS_WHEEL_BY_SSL_PROXY_HOST_PAIR,
);

my @HAS_CONNECTION_VALUES = (
  CS_CONNECTION_BY_WHEEL,
  CS_CONNECTION_BY_REQUEST,
);

use POE::Component::Client::HTTP::Request qw(:states :fields);
use Data::Dumper;

sub get_proxy_ssl_key {
  my $request = shift;
  return join('-*-',(
      $request->host(), #Host 
      $request->port(), #And port which we are physically connected to
      $request->http_request->header('Host'),
    ) #and the host which the proxy tunnels
  );
}

sub new {
  my $cls = shift;
  my $self = [];
  for (0.._CS_MAX-1) {
    push @$self, {};
  }
  return bless $self, $cls;
}

sub _delete_by_value {
  #Need some careful handling to ensure that our old references are not
  #stringified...
  
  my ($self,$val,$indices) = @_;
  foreach my $i (@$indices) {
    while (1) {
      my %tmp = reverse %{ $self->[$i] };
      last if (!exists $tmp{$val});
      my $k = delete $tmp{$val};
      delete $self->[$i]->{$k};
    }
  }
}

sub register_request {
  my ($self,$request,$http_request) = @_;
  $self->[CS_REQUEST_BY_ID]->{$request->ID} = $request;
  $self->associate_ext_request_with_internal_request($request, $http_request);
  DEBUG and warn
    "CS: Registered request $request with ID ".$request->ID." And tied to ".$http_request;
}

sub register_connparams {
  #this should store lots of connection data we will need..
  DEBUG and warn "CS: Registering connection...";
  my ($self,%opts) = @_;
  my ($wheel,$connection,$request,$sslified) =
    delete @opts{qw(wheel connection request sslified)};
  die "Unknown parameters " . join(',', keys %opts) if (keys %opts);
  if (defined $wheel) {
    $self->[CS_WHEEL_BY_ID]->{$wheel->ID} = $wheel;
    if (defined $request) {
      $self->[CS_REQUEST_BY_WHEEL_ID]->{$wheel->ID} = $request;
      DEBUG and warn "CS: Associated wheel ".$wheel->ID." With request ".$request->ID;
    }
    if (defined $connection) {
      $self->[CS_WHEEL_BY_CONNECTION]->{$connection} = $wheel;
      $self->[CS_CONNECTION_BY_REQUEST]->{$request} = $connection;
      $self->[CS_CONNECTION_BY_WHEEL]->{$wheel} = $connection;
    }
    if ($sslified) {
      #Assume we have a request!
      my $k = get_proxy_ssl_key($request);
      #assume wheel eq request->wheel
      die "Wheel conflict!" if ($wheel ne $request->wheel);
      $self->[CS_WHEEL_BY_SSL_PROXY_HOST_PAIR]->{$k} = $wheel;
      DEBUG and warn
        "CS: Registered persistent wheel id ".$wheel->ID." for ssl proxy key".$k;
      if (defined $connection) {
        DEBUG and warn "CS: Deleting old connection references";
        $self->_delete_by_value($connection, \@HAS_CONNECTION_VALUES);
        DEBUG and warn "CS: Storing connection object for HTTPS proxy socket";
        $self->[CS_CONNECTION_BY_SSL_PROXY_SOCK]->{
          $wheel->get_input_handle} = $connection;
      }
    }
  }
}

sub nuke_wheel {
  my ($self,$wheel) = @_;
  DEBUG and warn sprintf(
    "CS: Shutting down wheel %d for I/O", $wheel->ID);
  $wheel->shutdown_input();
  $wheel->shutdown_output();
  $self->_delete_by_value($wheel, \@HAS_WHEEL_VALUES);
  my $connection = $self->[CS_CONNECTION_BY_WHEEL]->{$wheel};
  if (defined $connection) {
    DEBUG and warn "CS: Closing associated connection for wheel ". $wheel->ID;
    $connection->close();
    $self->_delete_by_value($connection, \@HAS_CONNECTION_VALUES);
  }
  if (delete $self->[CS_CONNECTION_BY_SSL_PROXY_SOCK]->{$wheel->get_input_handle}) {
    DEBUG and warn "CS: Deleted referenced connection for wheel " . $wheel->ID;
  }
}

sub unregister_wheel {
  my ($self,$wheel) = @_;
  $self->_delete_by_value($wheel, \@HAS_WHEEL_VALUES);
}

sub nuke_request_with_connection {
  #this should tear down a request and its related connections...
  my ($self,$request, %opts) = @_;
  my ($wheel,$connection);
  DEBUG and warn
    sprintf("CS: Nuking connected object for request %d", $request->ID);
  
  $wheel = $request->wheel;
  $self->unregister_request($request);
  $self->nuke_wheel($wheel) if defined $wheel;
}

sub free_connection_for_request {
  my ($self, $request) = @_;
  my $connection = delete $self->[CS_CONNECTION_BY_REQUEST]->{$request};

  #We can sometimes have a request without an associated connection, in which
  #our CS manages sslified proxy wheels..
  
  # If there's a connection, then our socket is not SSLified (otherwise it would
  # have been dropped. In that case, remove the wheel as well...
  if ($connection) {
    my $wheel = $request->wheel;
    if ($wheel ne $connection->wheel) {
      die "WHEEL MISMATCH!!!!";
    }
    DEBUG and warn sprintf(
      "CS: Freeing connection with wheel %d", $wheel->ID);
    $self->_delete_by_value($wheel, \@HAS_WHEEL_VALUES);
    $self->_delete_by_value($connection, \@HAS_CONNECTION_VALUES);
    if (DEBUG) {
      foreach my $i (0.._CS_MAX-1) {
        my $s = "";
        while ( my ($k,$v) = each %{$self->[$i]} ) {
          $s .= " ($k, $v) ";
        }
        warn "CS: i=$i: $s" if $s;
      }
    }
    undef $connection;
    undef $wheel;
  } else {
    DEBUG and warn "CS: Couldn't find connection..."
  }
}

sub unregister_request {
  my ($self,$request) = @_;
  DEBUG and warn
    sprintf("CS: unregistering request ID %d", $request->ID);
  $request->remove_timeout();
  $self->_delete_by_value($request, \@HAS_REQUEST_VALUES);
  $self->free_connection_for_request($request);
  $request->wheel(undef);
}

sub request_by_id {
  my ($self,$id) = @_;
  my $ret = $self->[CS_REQUEST_BY_ID]->{$id};
  DEBUG and warn "CS: Returning $ret for $id\n";
  return $ret;
}

sub request_by_http_request {
  my ($self,$hr) = @_;
  return $self->[CS_REQUEST_BY_EXT_REQUEST]->{$hr};
}

sub request_by_wheel_id {
  my ($self,$wid) = @_;
  return $self->[CS_REQUEST_BY_WHEEL_ID]->{$wid};
}

sub connection_by_request {
  my ($self,$req) = @_;
  return $self->[CS_CONNECTION_BY_REQUEST]->{$req};
}

sub wheel_by_id {
  my ($self,$wid) = @_;
  return $self->[CS_WHEEL_BY_ID]->{$wid};
}

sub all_requests {
  my $self = shift;
  return (values %{ $self->[CS_REQUEST_BY_ID] });
}

sub associate_ext_request_with_internal_request {
  my ($self,$request,$http_request) = @_;
  # Associate a new HTTP::Request object,
  # Useful for redirects, where the user code may want to cancel based on
  # the original request, which is no longer the current request.
  DEBUG and warn sprintf("CS: Associating HTTP::Request %s with internal request %d",
                         $http_request, $request->ID);
  $self->[CS_REQUEST_BY_EXT_REQUEST]->{$http_request} = $request;
}

sub sslified_wheel_for_int_request {
  my ($self,$request) = @_;
  my $key = get_proxy_ssl_key($request);
  DEBUG and warn "CS: Got request for key $key";
  return $self->[CS_WHEEL_BY_SSL_PROXY_HOST_PAIR]->{$key};
}

################################# END RequestStore ##########################
1;