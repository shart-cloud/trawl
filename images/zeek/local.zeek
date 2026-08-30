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

# The module is CommunityID, not Communityid. Zeek rejects a redef of an
# unknown identifier and exits at startup, so the misspelling did not degrade
# correlation - it stopped the analyzer from running at all.
redef CommunityID::seed = 0;
# base64 matches Suricata's community-id encoding. A mismatch here would produce
# two different strings for the same flow and silently break every
# cross-analyzer correlation, which is the kind of failure that looks like "the
# pivot found nothing" rather than an error.
redef CommunityID::do_base64 = T;

# Stock community-id-logging adds the field to Conn::Info alone, while Suricata
# stamps it on every EVE event. Trawl's exact pivot (FR-011) depends on both
# analyzers agreeing about a flow's identity in every record, not just the
# connection summary.
@load ./community-id-all.zeek

# File hashes. Without this, files.log carries metadata but no sha256, and
# Trawl's file observations promise hash lookup (config/grafana/queries -
# file_transfers) that nothing could answer.
@load ./file-hashing.zeek

# Logs are written where the sensor tails them.
redef Log::default_rotation_interval = 1hr;
redef LogAscii::use_json = T;

# The site overlay is loaded last - so custom content overrides base behaviour
# rather than the reverse - but it is loaded from the command line, by
# entrypoint.sh. Zeek resolves @load at parse time and fails fatally on a
# missing path, and the overlay is optional: a NetworkTap that declares no
# custom content mounts no overlay directory. Only the entrypoint can ask
# whether the path exists before naming it.

# No packet writing. Packet capture belongs to CaptureJob, under its own
# authorization and retention boundary; a Zeek-side trace would put packet data
# outside that boundary with no retention and no audit trail.
redef Pcap::snaplen = 0;
