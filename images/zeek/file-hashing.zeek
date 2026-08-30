##! SHA-256 hashing for observed files.
##!
##! Zeek's stock policy/frameworks/files/hash-all-files computes MD5 and SHA1
##! only. Trawl's file observation records a sha256 (internal/observation
##! model.File), and the file_transfers query exists so an analyst can look a
##! file up by hash - neither of which a files.log carrying md5 and sha1 can
##! answer. The stock script would leave that field empty in every record.
##!
##! MD5 and SHA1 are not computed. Both are collision-broken, so neither can
##! establish that two files are the same, and computing a hash Trawl does not
##! store would spend time on every observed file for nothing.
##!
##! Hashing is metadata about content, not content. The bytes are never written:
##! packet and file capture belong to CaptureJob, under its own authorization
##! and retention boundary.

@load base/files/hash

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
	}
