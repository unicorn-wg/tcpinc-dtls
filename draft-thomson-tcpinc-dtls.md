---
title: A DTLS Extension for TCP
abbrev: DTLS for TCP
docname: draft-thomson-tcpinc-dtls-latest
date: 2014
category: std

ipr: trust200902
area: TSV
workgroup: TCPINC
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

normative:
  RFC2119:
  RFC1122:
  RFC0793:
  RFC2460:
  RFC5246:
  RFC6347:
  RFC2780:
  RFC5226:

informative:
  RFC1323:
  RFC2018:
  RFC7258:
  I-D.bittau-tcp-crypt:
  I-D.ietf-tcpm-fastopen:
  I-D.bellovin-tcpsec:


--- abstract

Opportunistic security is provided for TCP using a modified DTLS.


--- middle


# Introduction {#intro}

TCP {{RFC0793}} is a widely used protocol.

As part of a general "secure all the things" effort, the IETF is defining
opportunistic security options for all the protocols it maintains.
Opportunistic security ensures that we accelerate the eventual heat death of the
universe, and discourages certain classes of attack {{RFC7258}}.

Opportunistic approaches are the most practical way to ensure wider deployment
of security because they don't immediately depend on solving hard problems like
authentication.

In that spirit, reusing existing security protocols reduces the cost to
implement, deploy and analyse new protocol modifications.  TLS {{RFC5246}} and
DTLS {{RFC6347}} represent the current best in class security protocols.

This specification defines how DTLS can be used to protect TCP.  This addresses
the requirements outlined in {{I-D.bellovin-tcpsec}}.  A small modification to
the TCP record layer allows for the protection of the TCP pseudo header, with an
allowance for NAPT (editor: why does Bellovin even suggest that protection of
IP/port is even feasible?) and per-option opt-out.

In addition, all the features of DTLS are made available:

* Cipher suite negotiation and agility

* Years of security analysis

* Downgrade protection in the handshake

* Session bindings

* Optional peer authentication

* A range of available extensions

In addition to this, new upgrades to DTLS can be trivially added.  Thus,
improvements to algorithms or the DTLS handshake are entirely portable.


## Terminology

The usual. {{RFC2119}} explains what those are.


# DTLS Layering {#overview}

This extension to TCP places a continuous sequence of DTLS records as the
payload of TCP.  These records provide confidentiality and integrity protection
for their content, plus integrity protection for the TCP header and
pseudoheader.

An option negotiates the use of this extension.  This option is added to the SYN
message to indicate support, and to the ACK message to indicate acceptance.

Once enabled, all DTLS records, including handshake messages, are carried as TCP
data.  The data for the protected TCP stream is the concatenated content of DTLS
messages.

TCP clients are automatically entered into the DTLS client role; and TCP servers
automatically enter the DTLS server role.  Where TCP simultaneous open is used,
a lottery determines the roles {{simultaneous-open}}.


# DTLS Record Protection Option {#option}

This option is used to negotiate the use of DTLS.  It is assigned a TCP option
kind of 0xTBD {{iana}}.

The format of the DTLS record protection option is a single octet flags field,
followed by a list of protected option kinds.


## DTLS Record Protection Flags {#flags}

The content of the flags field is a bit pattern of features.  The following features
are defined in this document:

* FORBID_NAPT: Bit 0 (the first and most significant bit of the first octet)
  being set indicates that DTLS protection is to be extended to addressing
  elements, see {{forbid-napt}}.

A client can set these bits to request the defined alterations to the protocol.
A server can accept these alterations by including these in its ACK message, or
it can reject the alterations by clearing the bit.

All bits in this option MUST be set to zero unless they are explicitly
understood.  A sender MUST remove trailing octets that have all zero values from
the option.

An IANA registry is established to maintain these bits {{iana-flags}}.


## Protection Option Kinds {#protected-options}

The DTLS record protection option includes a list of the TCP options that are
covered by DTLS integrity protection, each occupying a single octet.  Just as
TCP options are terminated by a zero octet, this list is terminated by a zero
value.

Any data following this list is reserved for extension and MUST be ignored.


# Modified DTLS AEAD Operation

This mechanism MUST be used with an Authenticated Encryption with Additional
Data (AEAD) mode.  The DTLS record layer is modified to provide integrity
protection for the TCP pseudoheader and header by including this as part of the
additional data.

An important characteristic of this is that records are protected as though each
individual DTLS record is part of a unique TCP segment.  This ensures that
repacketization by middleboxes does not result in records being marked as
invalid.

TCP middleboxes can, and sometimes do, split or coalesce TCP segments.  This
affects the calculation of the authenticated data that is input to the AEAD
protection.

To prevent this from invalidating integrity checks unnecessarily, the associated
data passed to the AEAD algorithm contains a modified value of the TCP header
and pseudoheader.

For a sender that transmits a single DTLS record in each TCP segment with only
protected TCP options, this demands no additional calculation.  However, a
receiver needs to construct the TCP header and pseudoheader.  The length of this
packet is based on the length of the DTLS record, with the value of protected
TCP options being extracted from the TCP header of the segment that carries the
first byte of the DTLS record.

In TLS and DTLS, the additional data that is protected by the AEAD function
is {{RFC5246}}:

    additional_data = seq_num + TLSCompressed.type +
                      TLSCompressed.version + TLSCompressed.length;

where "+" denotes concatenation.

This specification expands the fields that are protected to include a
constructed TCP pseudoheader and header as follows:

    tcp_additional_data = pseudoheader + tcp_header +
                          additional_data;


Construction of the `pseudoheader` and `tcp_header` portions of the
authenticated data are described in the following sections.


## TCP Pseudoheader Construction {#pseudoheader}

The pseudoheader that is used for AEAD input depends on the IP version in use,
for IPv4 {{RFC0793}}, with length of fields in bits shown in parentheses:

    pseudoheader_v4 = source_address(32) + destination_address(32) +
                       zero(8) + protocol(8) + tcp_length(16)

Or for IPv6 {{RFC2460}}:

    pseudoheader_v6 = source_address(128) + destination_address(128) +
                      tcp_length(32) + zero(24) + protocol(8)

In both cases, the value for `tcp_length` is derived by constructing a TCP
header as described in {{tcp-header}}.

The values for `source_address` and `destination_address` are replaced with zero
bits, unless the FORBID_NAPT flag is enabled.  Setting these values to zero
permits the use of NAPT devices.


## TCP Header Construction {#tcp-header}

In order to ensure that the protocol is robust in the presence of middleboxes,
unprotected TCP options are removed from the TCP header before applying protection.

    tcp_header = source_port(16) + destination_port(16) +
                 sequence_number(32) + acknowledgement_number(32) +
                 data_offset(4) + flags(12) + window(16) +
                 checksum(16) + urgent_pointer(16) + options(?)

The following construction rules apply:

source_port and destination_port:

: These fields MUST be replaced with zero bits unless the FORBID_NAPT flag is
  enabled for the session.  Setting these values to zero permits the use of port
  translation.

sequence_number:

: This field MUST be set to the sequence number corresponding to the first octet
  of the DTLS record.

acknowledgement_number and window:

: These fields MUST be replaced with zero bits.  Removing the acknowledgement
  and congestion window from integrity protection does provide some
  opportunities to an on-path attacker {{security-ack-window}}.

data_offset:

: The data offset MUST be set to the size of the modified TCP header.

flags:

: The reserved and flags part of the TCP header is protected.

checksum:

: This field MUST be replaced with zero bits, just as it is when the TCP
  checksum is calculated.

urgent_pointer:

: The urgent pointer is protected.

options:

: The set of options that are included under protection are included.  Options
  that are not protected are removed.  {{protected-options}} described how
  options are selected for protection.  The list of options is terminated with
  an option of kind 0x0 and padding to a multiple of 32 bits with zero octets.
  {: br}


This construction permits the addition and removal of options by middleboxes, as
long as they are not in the list of options that are protected.  It also permits
repacketization and acknowledgment.


## Forbid NAPT {#forbid-napt}

The DTLS record protection option {{option}} contains a FORBID_NAPT bit that can
be used to signal that network address and port translation (NAPT) is forbidden.

If the FORBID_NAPT option is not set, addressing information is replaced with
zero values.  This is the IP (v4 or v6) address fields in the pseudoheader, and
the source and destination port numbers.

Why anyone in their right mind would do this is beyond me, but it's in the
requirements and this would seem to be sufficient to address those, albeit by
making the whole mechanism more complex.


# DTLS Role Selection {#simultaneous-open}

Ordinarily, the role of DTLS client is assumed by the peer that sends the first
TCP SYN packet (the TCP client), and the role of DTLS server is assumed by the
peer that responds (the TCP server).

Peers that perform a TCP simultaneous open - that is, where both peers
simultaneously send SYN packets to open a connection, often to work around
middlebox limitations - are assigned client and server roles in DTLS based on
the following rules.

If only one peer provides a DTLS handshake in TCP fast open data
{{I-D.ietf-tcpm-fastopen}}, then that peer becomes the client.

If neither or both peers provide the DTLS handshake option, then the peer that
selects the numerically highest value for their ClientRandom assumes the client
role.  In the absence of the DTLS handshake option, role allocations are not
determined until a ClientHello message is exchanged.


# Design Characteristics

This section outlines a number of considerations that allow this protocol to
actually be implemented.


## Zero Length DTLS Data

{{RFC5246}}, Section 6.2 notes that the TLS record layer protects non-zero
length blocks.  This use of DTLS requires that frames be permitted to be empty,
relying solely on integrity protection of the associated data.

> This does not mean that the TCP segment contains no data, since it will
  contain the DTLS record header (including the explicit nonce, if any, and any
  bits produced by the AEAD cipher to ensure integrity).


## Unauthenticated Acknowledgments

TCP segments that only acknowledge receipt of data, or update the receive window
do not require authentication, since the corresponding fields are not protected.
These frames can be accepted and processed, as long as only the receive window
is updated.

By the same logic, protection of the TCP window scaling option {{RFC1323}} and
the selective acknowledgment (SACK) option {{RFC2018}} are not made
mandatory.  These SHOULD NOT be added to the list of protected options
{{protected-options}}.


## Interaction with DTLS Replay Protection

TCP segment retransmission and reassembly requires that a sender be able to
retransmit.  These frames will be retransmitted with the same data, including
the DTLS serial number.  To avoid having retransmissions erroneously discarded,
any DTLS replay protection needs to allow for replay of records that appear in
unacknowledged segments.


## TCP Keep-Alive

This protocol does not protect TCP keep-alive segments {{RFC1122}}; that is,
segments that are sent purely to ensure that the connection is maintained
through middleboxes.  These can contain a single junk byte from just prior to
the start of the congestion window.  These segments are discarded without being
validated.

This differs from {{I-D.bittau-tcp-crypt}}, which protects keep-alive segments.
Protection ensures that an attacker is unable to prolong the lifetime of a
connection that is otherwise unwanted.

Since an unwanted connection can be terminated with an authenticated segment
that bears a FIN or RST bit, this concern is unwarranted.


## Unprotected RST Segments

Existing TCP implementations, particularly middleboxes rely TCP RST to terminate
connections that are .  An implementation MAY choose to respect an
unauthenticated RST to permit these uses.

(Note: we may want to provide an option that the middlebox can include in a RST
to prove that it is on-path to make this a little easier to accept.)


## Cipher Suite Selection

Implementations MUST support the TLS_BLAH_WITH_BLAH_BLAH cipher suite.

Implementations MUST NOT offer non-AEAD modes and MUST terminate the connection
if a non-AEAD mode if one is erroneously offered.


# Security Considerations {#security}

None of this document mandates any level of authentication for peers, which
opens up all sorts of active attacks.


## NAPT

The choice to protect a TCP connection from addressing modification prevents
network address and port translation from altering the addressing information on
a connection.  Unfortunately, this is a procedure that much of the Internet
relies on.  Enabling this feature is likely to break a lot of uses, but failure
to use it exposes the connection to trivial re-routing attacks.

In the absence of peer authentication, and where there is a high level of
assurance that no NAPT is being used for a communications path, this protection
might be used.  Of course, any protection this provides is trivially
circumvented by an on-path attacker.


## Acknowledgments and Congestion Window Protection {#security-ack-window}

This design permits a middlebox to generate acknowledgments and to perform
repacketization.  This opens a number of denial of service avenues for malicious
middleboxes.  Falsifying window advertisements can cause a sender to send more
packets than might otherwise be sent.  Similarly, sending a reduced
acknowledgment sequence number can cause excessive retransmission.  In a similar
fashion, retransmissions can be suppressed by sending inflated acknowledgment
sequence numbers.

These are options that are already available to an on-path attacker.


## Traffic Redirection

Without the FORBID_NAPT flag enabled, it's possible for a middlebox to rewrite
addressing information so that this flow.  If only authenticated RST and FIN
segments are accepted by the TCP stack, the target of this flow - who doesn't
have access to the traffic keys - is unable to do anything to end the flow of
data.

This isn't particularly interesting as an attack, since we have to assume that
any middlebox capable of this is also capable of just generating the same volume
of packets toward the victim.


## Peer Authentication

In order to have this deployed, peers will have to avoid relying on
authentication.  That means that this is open to active attacks.

Implementations might consider using some form of key continuity.  Clients
SHOULD avoid key continuity for different servers to avoid tracking by
correlating keying material.  Full continuity might be more applicable for
servers, where key continuity does not create any special tracking ability.

(This probably needs work.)


# IANA Considerations {#iana}

This document registers a new TCP option kind, and establishes a registry to
maintain its contents.


## Registration of DTLS Record Protection Option Kind

This document registers the DTLS record protection option with a TCP option kind
of 0xTBD.

The format of this option is described in {{option}}


## Registry for DTLS Record Protection Flags {#iana-flags}

IANA will maintain a registry of "TCP DTLS Record Protection Flags" under the
"Service Names and Transport Protocol Port Numbers" group of registries.

This registry controls a contiguous space starting from bit 0 to 2023
(inclusive).  New registrations in this registry require IETF review
{{RFC5226}}, with the following information:

Bit Number:

:  The bit number being assigned

Purpose:

:  A brief description of the feature.

Specification:

:  A reference to the specification that defines the feature.
{: br}

The initial contents of this registry are:

Bit Number:

: 0

Purpose:

: Enables protection of addressing information.

Specification:

: This document.
{: br}

--- back
