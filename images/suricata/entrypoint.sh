#!/bin/sh
# Translates Trawl's analyzer arguments into a Suricata invocation.
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
		echo "suricata entrypoint: unrecognized argument: $arg" >&2
		exit 2
		;;
	esac
done

if [ -z "$interface" ]; then
	echo "suricata entrypoint: --interface is required" >&2
	exit 2
fi
if [ -z "$log_dir" ]; then
	echo "suricata entrypoint: --log-dir is required" >&2
	exit 2
fi

# suricata.yaml names the EVE path absolutely, because the sensor tails a path
# it is configured with rather than one it discovers. If the controller ever
# mounts the log volume somewhere else, the two would disagree silently: the
# analyzer would run, write EVE where nobody reads it, and report healthy.
expected_log_dir=/var/log/trawl
if [ "$log_dir" != "$expected_log_dir" ]; then
	echo "suricata entrypoint: --log-dir=$log_dir but suricata.yaml writes under $expected_log_dir" >&2
	exit 2
fi

expected_content_dir=/var/lib/trawl/content
if [ -n "$content_dir" ] && [ "$content_dir" != "$expected_content_dir" ]; then
	echo "suricata entrypoint: --content-dir=$content_dir but suricata.yaml reads rules from $expected_content_dir" >&2
	exit 2
fi

# Suricata does not create the EVE output directory, and exits if it is absent.
mkdir -p "$log_dir/suricata"

# --af-packet=<iface> rather than -i: it selects the AF_PACKET runmode
# explicitly, so the cluster-type, tpacket-v3 and checksum-checks settings in
# suricata.yaml's af-packet block are the ones that apply. With -i, Suricata
# picks a capture method itself and those settings may not take effect.
exec suricata \
	-c /etc/suricata/suricata.yaml \
	--af-packet="$interface" \
	-l "$log_dir"
