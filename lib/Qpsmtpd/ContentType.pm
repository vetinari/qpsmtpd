
=head1 NAME 

Qpsmtpd::ContentType - parse and access the contents of the Content-Type header

=head1 DESCRIPTION

This plugin parses the contents of the given I<Content-Type:> header according
to RFC 1521 ``MIME (Multipurpose Internet Mail Extensions) Part One:
Mechanisms for Specifying and Describing the Format of Internet Message Bodies''

=head1 SYNOPSIS

 sub hook_data_post {
    my ($self,$transaction) = @_;
    my $ct = $transaction->notes('Content-Type');
    unless ($ct) {
         my $ct_head = $transaction->header->get('Content-Type');
         $ct         = Qpsmtpd::ContentType->parse($ct_head);
         $transaction->notes('Content-Type', $ct);
    }
    if ($ct->type eq 'text') {
        return (DENY, "HTML only mails not accepted here")
          if ($ct->subtype eq 'html');
        [... do something else ... ]
    }
    return (DECLINED);
 } 

=head1 API

=head2 parse( $value_of_Content_Type_header )

Parses the contents of the I<Content-Type:> header and returns an object
where the fields can be accessed. 

=head2 illegal( )

True, if an error occured.

=head2 error( )

The error message if B<illegal()> returned true.

=head2 type( )

The main type of the MIME-Type, e.g. B<text> for a I<text/plain> type.

=head2 subtype( )

The subtype if the MIME-Type, e.g. B<plain> for a I<text/plain> type.

=head2 param(NAME [,VALUE]) 

Returns the value of the parameter NAME or I<undef()> if not present in
the Content-Type header.
If a VALUE is given, it sets the parameter NAME to VALUE, useful with 
C<format()>.

=head2 format( )

Returns a string, which may be used to replace the current C<Content-Type>
header 

  $transaction->header->replace("Content-Type", $ct->format);

=cut 

package Qpsmtpd::ContentType;

# In the Augmented BNF notation of RFC 822, a Content-Type header field
# value is defined as follows:
#
#   content  :=   "Content-Type"  ":"  type  "/"  subtype  *(";"
#   parameter)
#             ; case-insensitive matching of type and subtype
#
#   type :=          "application"     / "audio"
#             / "image"           / "message"
#             / "multipart"  / "text"
#             / "video"           / extension-token
#             ; All values case-insensitive
#
#   extension-token :=  x-token / iana-token
#
#   iana-token := <a publicly-defined extension token,
#             registered with IANA, as specified in
#             appendix E>
#
#   x-token := <The two characters "X-" or "x-" followed, with
#               no intervening white space, by any token>
#
#   subtype := token ; case-insensitive
#
#   parameter := attribute "=" value
#
#   attribute := token   ; case-insensitive
#
#   value := token / quoted-string
#
#   token  :=  1*<any (ASCII) CHAR except SPACE, CTLs,
#                 or tspecials>
#
#   tspecials :=  "(" / ")" / "<" / ">" / "@"
#              /  "," / ";" / ":" / "\" / <">
#              /  "/" / "[" / "]" / "?" / "="
#             ; Must be in quoted-string,
#             ; to use within parameter values

sub parse {
    my $me   = shift;
    my $ct   = shift;
    my $self = {};
    bless $self, $me;

    $self->illegal(0);

    my $tspecials = '\(\)<>@,;:\\"/\[\]?=';
    my $tclass    = "[^\x00-\x1F\x7F-\xFF $tspecials]";
    my $token     = qr#$tclass(?:$tclass)*#;
    my $x_token    = qr#X-$token#;              # will match X- and x- tokens :)
    my $iana_token = qr#$token#;                # is this true?
    my $ext_token  = qr#($x_token|$iana_token)#;
    my $parameter = qr# *($token) *= *($token|(['"]).+?\3)(?:( *;|$))#;
    my $type      = qr#($token|$ext_token)#;
    my $sub       = qr#($token|(["']).+\2)(?:( *;|$))#;

    $ct =~ s/(\n\s)/ /gs if $ct;
    $ct =~ s/^ *//       if $ct;
    unless ($ct) {
        $ct = "text/plain; charset=us-ascii";
    }

    # print STDERR "Content-Type: $ct\n";
    if ($ct =~ s#^$type/##i) {
        $self->{' _type'} = lc $1;
        if ($ct =~ s#^$sub##i) {
            $self->{' _sub'} = lc $1;
        }
        else {
            $self->error("No SUBTYPE in Content-Type");
            return $self;
        }
    }
    else {

        # Note also that a subtype specification is MANDATORY.
        # There are no default subtypes.
        $self->error("No TYPE/ in Content-Type");
        return $self;
    }

    while ($ct =~ s/^$parameter//i) {
        my ($k, $v) = (lc $1, $2);
        $v =~ s/^(['"])?(.+)\1$/$2/;
        $self->{$k} = $v;
    }

    if ($self->type eq 'text') {
        $self->param('charset', (lc $self->param('charset') || 'us-ascii'));
        return $self;
    }

    if ($self->type eq 'multipart') {
        my $bcharsnospace = qr#[0-9a-zA-Z'()+_,-./:=?]#;
        my $boundary = $self->param('boundary') || "";
        $boundary =~ s/\s*$//;
        if ($boundary =~ m#^( |$bcharsnospace){0,69}$bcharsnospace$#) { ##vim# 
            $self->param('boundary', $boundary);
        }
        else {
            $self->error("illegal boundary parameter");
        }
        return $self;
    }

    if ($self->type eq 'message') {
        if ($self->subtype eq 'partial') {
            unless ($self->param('id') and $self->param('number')) {

                # luckily:
                # Note that part numbering begins with 1, not 0.
                $self->error("no ID or NUMBER parameter");
                return $self;
            }
            unless ($self->param('number') =~ /^\d+$/) {
                $self->error("value of NUMBER not just digits");
                return $self;
            }
            if ($self->param('total') && $self->param('total') !~ /^\d+$/) {
                $self->error("value of TOTAL not just digits");
                return $self;
            }
            return $self;
        }
        elsif ($self->subtype eq 'external-body') {
            unless ($self->param('access-type')) {
                $self->error("no ACCESS-TYPE parameter");
                return $self;
            }
            $self->param('access-type', lc $self->param('access-type'));
            if ($self->param('access-type') =~ /^(anon-|t)?ftp$/) {
                unless ($self->param('name') && $self->param('site')) {
                    $self->error("no NAME or SITE parameter");
                    return $self;
                }

                if ($self->param('access-type') =~ /^(anon-)?ftp$/) {
                    $self->param('mode', ($self->param('mode') || 'ascii'));
                }
                else {
                    $self->param('mode', ($self->param('mode') || 'netascii'));
                }
            }
            elsif ($self->param('access-type') =~ /^(local-file|afs)$/) {
                unless ($self->param('name')) {
                    $self->error("no NAME parameter");
                    return $self;
                }
            }
            elsif ($self->param('access-type') eq 'mail-server') {
                unless ($self->param('server')) {
                    $self->error("no SERVER parameter");
                    return $self;
                }
            }
        }
        return $self;
    }

    return $self;
}

sub error {
    my ($self, $msg) = @_;
    if (defined $msg) {
        $self->{' _error'} = $msg;
        $self->illegal(1);
    }
    return $self->{' _error'};
}

sub illegal { $_[1] ? ($_[0]->{' _illegal'} = $_[1]) : $_[0]->{' _illegal'}; }
sub type    { $_[0]->{' _type'} }
sub subtype { $_[0]->{' _sub'} }

sub param {
    my ($self, $key, $value) = @_;
    if (defined $value) {
        $self->{lc $key} = $value;
    }
    return ($self->{$key} || undef);
}

sub format {
    my $self = shift;
    my $str  = $self->type . '/' . $self->subtype;
    foreach (keys %{$self}) {
        next if /^ /;
        $str .= "; $_=\"" . $self->param($_) . "\"";
    }
    return $str;
}

1;
# vim: ts=4 sw=4 expandtab syn=perl
