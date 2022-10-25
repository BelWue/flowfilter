## Flow Filter

This is the initial experiment on having a simple filtering DSL for flows. The
`cmd/flowdump.go` utility is a first demo for how a tcpdump style command could
be implemented with this.

It is meant as a base for user-provided filters and alerts within the bwNet
platform, or also just as an addition to goflows protobuf format.

### Setup

Configuration of the flowdump script is done using environment vars only and
highly specific to the current bwNet setup. Copy the follwing bash/fish script
to `.authdata.env` and run `source .authdata.env` before attempting to test
with `go run cmd/flowdump.go` or any `./flowdump` precompiled binary.

```bash
#!/usr/bin/bash
export KAFKA_SERVER=kafka-server:port
export KAFKA_SASL_USER=yourname
export KAFKA_SASL_PASS=yourpass123
export KAFKA_TOPIC=flows
export KAFKA_CONSUMER_GROUP=yourname-any-suffix-you-like
```

```fish
#!/usr/bin/fish
set -x KAFKA_SERVER kafka-server:port
set -x KAFKA_SASL_USER yourname
set -x KAFKA_SASL_PASS yourpass123
set -x KAFKA_TOPIC flows
set -x KAFKA_CONSUMER_GROUP yourname-any-suffix-you-like
```

### Syntax

This paragraph will describe the filter syntax in what I consider the most understandable manner.

#### Overall Structure

Every valid input constitutes an Expression. An Expression consists of a number
of Statements combined using the Conjunctions `and` and `or`. Statements are
either a Match, or another Expression in parenthesis. Statements can be negated
using the `not` keyword. These following examples will illustrate the general
filter structure:

```
match foo
match foo or match bar
match foo and (match bar or match baz)
match foo and not match bar
match foo and not (match bar or match baz)
```

#### Matches

Each Match falls in one of two categories: It either accepts a directional
modifier (`src` and `dst`) or it does not. Their implementation is largely
equivalent, except that Match Statements that accept a direction keyword
compute both eventualities, counting on the selection of one of their results
at a later point. If there is no direction provided for a directional field, it
is equivalent to the expression `src match foo or dst match bar`.

#### Literals

Matches use different literals in different constellations, and some matches accept further keywords/magic strings.

|  Literal   | Syntax                                                                               |
| ----------:| ------------------------------------------------------------------------------------ |
|  `address` | IP address, as accepted by `net.IP`.
|   `string` | Anything wrapped in either `"` or `'`.
|      `int` | Unsigned Integer. In addition to decimal, `0x` and `0b` prefixes are allowed.
|    `range` | `[<\|>]<int>\|<int>-<int>`, i.e. `4`, `4-10`, `<4` or `>4` are acceptable.
|       `cc` | Any ISO3166 country code, no quotes.
|    `etype` | `ipv6`, `ipv4`, `arp`
|    `proto` | `icmp`, `tcp`, `udp`, `icmpv6`, `ipip`, `vrrp`
|       `ds` | `ce`, `ect0`, `ect1`
|   `status` | `forwarded`, `dropped`, `acldeny`, `acldrop`, `policerdrop`, `unroutable`, `consumed`
| `tcpflags` | `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `synack`, `cwr`, `ece`
|     `rpki` | `valid`, `invalid`, `notfound`, `unknown`

#### Directional Matches

| Keyword             | Syntax         | Examples                                                            | Notes                                                     |
| -------------------:| -------------- | ------------------------------------------------------------------- | --------------------------------------------------------- |
|           `address` | `<address>[/<int>]` | `10.0.0.0/8` (private space)                                        | Anything recognized by `net.IP`. CIDR netmask is optional.
|       `i[nter]face` | `<int>`             |                                                                     | Shorthand for the next command.
|    `i[nter]face id` | `<int>`             |                                                                     | Refers to the interface SNMP ID as reported in Netflow.
|  `i[nter]face name` | `<string>`          | `hu` (via 100G interface, matches `Hu0/1/1/1`)                      | Refers to the interface name (if applicable).
|  `i[nter]face desc` | `<string>`          | `IX` (desc mentions exchanges), `tunnel` (indicates a pseudowire)   | Refers to the interface description (if applicable).
| `i[nter]face speed` | `<range>`           | `100` (see `iface name` example)                                    | Refers to the interface speed (if applicable).
|              `port` | `<range>`           | `<1000` (privileged), `22` (ssh), `9100-9999` (prometheus exporter) |
|               `asn` | `<range>`           | `553` (ourselves), `64512-65534` (private asn)                      |
|           `netsize` | `<range>`           | `<24` (BGP filtered)                                                |
|               `cid` | `<range>`           | `<20000` (only university networks)                                 | Customer ID is an enriched field, matches only if applicable.
|               `vrf` | `<range>`           |                                                                     |

#### Regular Matches

| Keyword             | Syntax               | Examples                                                       | Notes                                                                                           |
| -------------------:| -------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
|            `router` | `<address>`          |                                                                | See `address` match. Refers to the router the Netflow originated on, aka the sampler address.
|           `nexthop` | `<address>`          |                                                                | See `address` match.
|        `nexthopasn` | `<int>`              |                                                                |
|             `bytes` | `<range>`            |                                                                | Refers to the bytes transported by the flow.
|           `packets` | `<range>`            |                                                                | Refers to the packets transported by the flow.
|           `country` | `<cc>`               | `DE` (Germany), `US` (US)                                      | Refers to the remote addresses country code as added to the flow by some lookup (if applicable).
|         `direction` | `incoming\|outgoing` |                                                                | Refers to the direction as reported in the flow.
|          `incoming` |                      |                                                                | Shorthand for `direction`.
|          `outgoing` |                      |                                                                | Shorthand for `direction`.
|        `normalized` |                      |                                                                | Normalization status in regard to a flow's sampling rate (if applicable).
|          `duration` | `<range>`            | `>0` (longer flows)                                            | Time between a flows start and its end, in seconds.
|             `etype` | `<int>\|<etype>`     | `ipv6`, `0x86DD` (IPv6)                                        |
|             `proto` | `<int>\|<proto>`     | `tcp`, `6` (TCP)                                               |
|            `status` | `<int>\|<status>`    | `dropped` (any drop), `0b10000000` (dropped unknown only)      | Literal Intergers match exactly, magic strings match as a bit mask.
|          `tcpflags` | `<int>\|<tcpflags>`  | `ack` (ack in >0 packets), `0b010000` (just ack-only packets)  | Literal Intergers match exactly, magic strings match as a bit mask.
|             `iptos` | `<range>`            |                                                                |
|              `dscp` | `<int>\|<dscp>`      | `default` (no class, i.e. 0), `0b0` (same)                     | All matches are exact, against `IPTos>>2`.
|               `ecn` | `<int>\|<ecn>`       | `ce` (congestion exp. in >0 packets), `0b11` (CE packets only) | All matches are exact, against `IPTos&0b11`.
|      `samplingrate` | `<range>`            | `<512` (only consider good sampling rate flows)                |
|         `icmp type` | `<int>`              | `3` (destination unreachable)                                  | Also ensures `proto icmp`. Calculation based on destination port (Netflow v9).
|         `icmp code` | `<int>`              | `icmp type 3 and icmp code 3` (port unreachable)               | Also ensures `proto icmp`. Calculation based on destination port (Netflow v9).
|               `bps` | `<range>`            | `>1048576` (>1Mbps), `>1073741824` (>1Gbps)                    | Calculated as average based on byte count and flow duration.
|               `pps` | `<range>`            | `>1000000` (>1Mpps), `>1000000000` (>1Gpps)                    | Calculated as average based on packet count and flow duration.
|               `med` | `<range>`            | `<200`                                                         |
|         `localpref` | `<range>`            | `>100`                                                         |
|              `rpki` | `<rpki>`             | `valid`, `invalid`                                             |
|    `passes-through` | `<int> ...`          | `100 102` (string of ASNs, in order), `553`                    | Can be specified multiple times, to denote a segment of ASNs that occur in a path.

#### Examples

Some examples, the first two with their full (redacted) output.

##### All flows to Liberty Global with at least 1Mbps

```
$ ./flowdump 'dst asn 6830 and bps >1048576'
2021/03/25 15:39:10 Kafka Consumer: Connecting to xxxxx.belwue.de:9093
2021/03/25 15:39:13 Kafka Consumer: Connection established.
15:10:15: xx.xx.xx.46:993 -> xx.xx.xx.67:42203, TCP, 1s, 1.920256 Mbps, 192 pps
15:10:35: xx.xx.xx.60:1194 -> xx.xx.xx.47:31201, UDP, 60s, 1.888405 Mbps, 288 pps
15:10:38: xx.xx.xx.10:80 -> xx.xx.xx.4:59357, TCP, 60s, 2.687479 Mbps, 230 pps
15:10:14: xx.xx.xx.180:443 -> xx.xx.xx.133:55166, TCP, 1s, 2.498048 Mbps, 224 pps
15:10:16: xx.xx.xx.180:443 -> xx.xx.xx.133:55168, TCP, 1s, 9.03936 Mbps, 800 pps
15:10:36: xx.xx.xx.228:443 -> xx.xx.xx.118:32456, UDP, 57s, 2.057588 Mbps, 177 pps
```

##### Detect possible congestion

```
$ ./flowdump 'status policerdrop or dsfield ce'
2021/03/25 15:49:37 Kafka Consumer: Connecting to xxxxx.belwue.de:9093
2021/03/25 15:49:37 Kafka Consumer: Connection established.
15:48:51: xx.xx.xx.5:12067 -> xx.xx.xx.12:443, TCP, 1s, 4.736 Mbps, 400 pps
15:48:52: xx.xx.xx.5:4334 -> xx.xx.xx.12:443, TCP, 1s, 4.736 Mbps, 400 pps
15:48:52: xx.xx.xx.5:37164 -> xx.xx.xx.12:443, TCP, 1s, 7.104 Mbps, 600 pps
15:48:57: xx.xx.xx.40:52824 -> xx.xx.xx.13:8080, TCP, 1s, 11.776 kbps, 32 pps
15:48:58: xx.xx.xx.239:33114 -> xx.xx.xx.9:22, TCP, 1s, 25.6 kbps, 32 pps
15:49:06: xx.xx.xx.39:51234 -> xx.xx.xx.40:22, TCP, 1s, 44.032 kbps, 64 pps
15:49:08: xx.xx.xx.40:52824 -> xx.xx.xx.47:8080, TCP, 1s, 11.776 kbps, 32 pps
15:49:07: xx.xx.xx.40:52824 -> xx.xx.xx.216:8080, TCP, 1s, 11.776 kbps, 32 pps
```

The first match tries to find traffic our own routers dropped, differentiated
services congestion experienced is set on an end-to-end basis and just
traverses.

##### Find substantial TCP traffic that's never seen an ACK or FIN

```
bps >1000000 and proto tcp and not (tcpflags ack or tcpflags fin)`
```

##### Find stuff we don't want to see from our peers

```
incoming and (iface desc "IX" or iface desc "PNI") and (address 10.0.0.0/8 or address 192.168.0.0/16)
```

This assumes that github.com/bwNetFlow/processor_enricher was used to enrich
the flows with interface descriptions from SNMP and that network engineers use
some variant of `IX` and `PNI` in their descriptions somewhere.
