package Qpsmtpd::Plugin;
use strict;

my %hooks = map { $_ => 1 } qw(
    config  queue  data  data_post  quit  rcpt  mail  ehlo  helo
    auth auth-plain auth-login auth-cram-md5
    connect  reset_transaction  unrecognized_command  disconnect
);

sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  bless ({}, $class);
}

sub register_hook {
  my ($plugin, $hook, $method, $unshift) = @_;
  
  die $plugin->plugin_name . " : Invalid hook: $hook" unless $hooks{$hook};

  # I can't quite decide if it's better to parse this code ref or if
  # we should pass the plugin object and method name ... hmn.
  $plugin->qp->_register_hook($hook, { code => sub { local $plugin->{_qp} = shift; $plugin->$method(@_) },
				       name => $plugin->plugin_name,
				     },
				     $unshift,
			     );
}

sub _register {
  my $self = shift;
  my $qp = shift;
  local $self->{_qp} = $qp;
  $self->register($qp, @_);
}

sub qp {
  shift->{_qp};
}

sub log {
  my $self = shift;
  $self->qp->log(shift, $self->plugin_name . " plugin: " . shift, @_);
}

sub transaction {
  # not sure if this will work in a non-forking or a threaded daemon
  shift->qp->transaction;
}

sub connection {
  shift->qp->connection;
}

sub wrap_plugin {
  my ($self, $plugin_file, @args) = @_;

  # Wrap all of the methods in an existing plugin so that functions
  # can easily be replaced.  Yes, we could use something like
  # Hook::Lexwrap isntead, but since it's only 15 lines of code, might
  # as well do it ourself.

  # Static methods in plugins will probably not work right in this
  # scheme.

  # Load the new plugin under our namespace.
  my $newPackage = __PACKAGE__."::_wrap_";
  Qpsmtpd::_compile($self->plugin_name, $newPackage, $plugin_file)
      unless defined &{"${newPackage}::register"};

  no strict 'refs';
  my $currentPackage = ref $self;
  local *{${newPackage}."::register_hook"} = sub {
    if (defined &{ $currentPackage . "::$_[2]"}) {
      # We're wrapping this hook.  Store the old value in $self-{_wrap_FUNC}
      $self->{"_wrap_".$_[2]} = \&{${newPackage}."::$_[2]"};
    } else {
      # We're not wrapping this hook.  Alias it into our namespace.
      *{$currentPackage."::$_[2]"} = \&{${newPackage}."::$_[2]"};
    }
    $self->register_hook($_[1],$_[2]);
  };

  $self->{_wrapped_package} = $newPackage;
  $newPackage->register($self->{_qp},@args);
}

1;
