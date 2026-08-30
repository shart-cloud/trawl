#!/bin/sh
# Translates Trawl's analyzer arguments into a Zeek invocation.
#
# The controller renders one argument set for every analyzer
# (--interface/--content-dir/--log-dir, see internal/controller/networktap_workload.go)
# because the arguments describe the tap, not the tool. Zeek and Suricata spell
# every one of those differently, so each image carries the translation rather
# than the controller carrying a per-analyzer special case.
set -eu

interface=""
content_dir=""
log_dir=""

for arg in "$@"; do
	case "$arg" in
	--interface=*) interface=${arg#*=} ;;
	--content-dir=*) content_dir=${arg#*=} ;;
	--log-dir=*) log_dir=${arg#*=} ;;
	*)
		echo "zeek entrypoint: unrecognized argument: $arg" >&2
		exit 2
		;;
	esac
done

if [ -z "$interface" ]; then
	echo "zeek entrypoint: --interface is required" >&2
	exit 2
fi
if [ -z "$log_dir" ]; then
	echo "zeek entrypoint: --log-dir is required" >&2
	exit 2
fi

# Zeek writes its logs to the working directory, and has no flag to redirect
# them. The sensor tails this directory, so the two must agree.
mkdir -p "$log_dir"
cd "$log_dir"

# local.zeek loads the site overlay from an absolute path, because Zeek resolves
# @load at parse time and cannot read it from the environment. That path and the
# volume the controller mounts have to agree, and nothing else checks it: a
# mismatch would mean custom detection content is silently ignored, which looks
# exactly like content that matched nothing.
expected_content_dir=/var/lib/trawl/content
if [ -n "$content_dir" ] && [ "$content_dir" != "$expected_content_dir" ]; then
	echo "zeek entrypoint: --content-dir=$content_dir but local.zeek loads $expected_content_dir" >&2
	exit 2
fi

# -C ignores checksum validation, and on a Kubernetes node it is required
# rather than a tuning choice. Every interface Trawl taps is a veth or a bridge
# member, where the NIC's checksum offload means the kernel hands Zeek packets
# whose checksums have not been computed yet. Zeek discards those by default,
# and its own reporter describes the result:
#
#   "Your interface is likely receiving invalid TCP checksums, most likely from
#    NIC checksum offloading."
#
# The observed symptom is not an error but silence: connections log with
# conn_state OTH and zero packets, and no protocol analyzer ever engages, so
# dns.log, http.log and ssl.log are never created at all. Trawl inspects traffic
# it did not transmit and cannot repair a checksum it never saw, so validating
# them here buys nothing and costs every protocol observation.
set -- -i "$interface" -C /usr/local/zeek/share/zeek/site/local.zeek

# The site overlay, when the NetworkTap declared custom content. It is named
# last so it overrides base behaviour rather than the reverse. Zeek fails
# fatally on a missing @load path, so the existence check has to happen out
# here: a tap with no custom content mounts no overlay, and that is normal
# rather than an error.
overlay="${expected_content_dir}/Zeek/site"
if [ -d "$overlay" ]; then
	set -- "$@" "$overlay"
fi

exec zeek "$@"
