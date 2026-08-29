##! Trawl's Zeek base configuration.
##!
##! Scripts themselves live on the mounted content volume and are loaded from
##! there, so this file configures behaviour rather than carrying detection
##! logic.

# JSON output. Trawl's sensor parses these logs, and Zeek's default TSV format
# would mean maintaining a column-order parser that breaks whenever a script
# adds a field.
@load policy/tuning/json-logs

# Community ID is what makes an exact pivot between Zeek and Suricata records
# possible (FR-011).
@load policy/protocols/conn/community-id-logging

redef Communityid::seed = 0;
# base64 matches Suricata's community-id encoding. A mismatch here would produce
# two different strings for the same flow and silently break every
# cross-analyzer correlation, which is the kind of failure that looks like "the
# pivot found nothing" rather than an error.
redef Communityid::do_base64 = T;

# Logs are written where the sensor tails them.
redef Log::default_rotation_interval = 1hr;
redef LogAscii::use_json = T;

# The site overlay, if the content volume carries one. Loading it last is what
# makes custom content able to override base behaviour rather than the reverse.
@load-sigs-ignore-errors /var/lib/trawl/content/Zeek/site

# No packet writing. Packet capture belongs to CaptureJob, under its own
# authorization and retention boundary; a Zeek-side trace would put packet data
# outside that boundary with no retention and no audit trail.
redef Pcap::snaplen = 0;
