##! Community ID on every Zeek log that describes a flow.
##!
##! Zeek's stock policy/protocols/conn/community-id-logging adds community_id to
##! Conn::Info alone. Suricata, by contrast, stamps it on every EVE event. That
##! asymmetry silently breaks the exact pivot FR-011 promises: an analyst
##! pivoting from an alert would reach the connection record and nothing else,
##! and the failure looks like "the pivot found nothing" rather than an error.
##!
##! community_id_v1 takes a bare conn_id, and every one of these logs already
##! carries the flow's conn_id as its `id` field. So the value is computed at
##! log time from what the record already holds, rather than by threading the
##! connection through each protocol analyzer.

@load base/protocols/conn
@load base/frameworks/files
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/frameworks/notice
@load base/frameworks/notice/weird
@load policy/protocols/conn/community-id-logging

module TrawlCommunityID;

redef record DNS::Info += { community_id: string &optional &log; };
redef record HTTP::Info += { community_id: string &optional &log; };
redef record SSL::Info += { community_id: string &optional &log; };
redef record Notice::Info += { community_id: string &optional &log; };
redef record Weird::Info += { community_id: string &optional &log; };
redef record Files::Info += { community_id: string &optional &log; };

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}

hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}

hook Notice::log_policy(rec: Notice::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}

hook Weird::log_policy(rec: Weird::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}

hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( rec?$id )
		rec$community_id = community_id_v1(rec$id, CommunityID::seed, CommunityID::do_base64);
	}
