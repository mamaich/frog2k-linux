# Validate the machine-readable SF2000 cache-model report.
#
# This is intentionally a semantic check rather than a field-count check.  A
# positional printf can compile successfully while assigning a valid integer to
# the wrong key.  The rec/helper decomposition below is an invariant of the
# model and catches that class of drift.  Unsupported core/native aliases are
# rejected so a future report cannot quietly resurrect the old misleading
# schema.

BEGIN {
	bad = 0
	header_version = 0
	frame_reports = 0
	required = "sample kind label instructions scope coverage recbase recbase_configured recbase_status recbase_evidence_pc frame frame_samples frame_avg_cycles frame_p95_cycles frame_p98_cycles frame_p99_cycles frame_p999_cycles frame_max_cycles i_accesses i_misses d_accesses d_lines d_bytes d_size1 d_size2 d_size4 d_size8p d_misses rec_i_accesses rec_i_misses rec_i_invalidations rec_d_accesses rec_d_lines rec_d_bytes rec_d_size1 rec_d_size2 rec_d_size4 rec_d_size8p rec_d_misses helper_instructions helper_i_accesses helper_i_misses helper_i_miss_ppm helper_i_miss_share_ppm helper_d_accesses helper_d_lines helper_d_bytes helper_d_size1 helper_d_size2 helper_d_size4 helper_d_size8p helper_d_misses helper_d_miss_ppm helper_d_miss_share_ppm est_cycles delta_instructions delta_i_misses delta_d_misses delta_est_cycles"
	required_count = split(required, required_keys, " ")
}

function report_error(message) {
	print "cache-model report check: " message > "/dev/stderr"
	bad = 1
}

function require_key(key) {
	if (!(key in field)) {
		report_error("missing " key)
	}
}

function equal_sum(name, left, right) {
	if ((field[name] + 0) != (left + right)) {
		report_error(name " decomposition mismatch: " field[name] " != " (left + right))
	}
}

$0 ~ /^# sf2000-cache-model version=/ {
	if (match($0, /version=[0-9]+/)) {
		header_version = substr($0, RSTART + 8, RLENGTH - 8) + 0
	}
	next
}

$2 == "kind=frame" {
	delete field
	for (i = 1; i <= NF; i++) {
		separator = index($i, "=")
		if (!separator) {
			continue
		}
		key = substr($i, 1, separator - 1)
		value = substr($i, separator + 1)
		if (key in field) {
			report_error("duplicate " key)
		}
		field[key] = value
	}
	for (i = 1; i <= required_count; i++) {
		require_key(required_keys[i])
	}
	if ("core_instructions" in field || "native_instructions" in field ||
		"core_i_accesses" in field || "native_d_accesses" in field) {
		report_error("unsupported core/native aliases present")
	}
	equal_sum("instructions", field["rec_i_accesses"],
		field["helper_instructions"])
	equal_sum("i_accesses", field["rec_i_accesses"],
		field["helper_i_accesses"])
	equal_sum("i_misses", field["rec_i_misses"],
		field["helper_i_misses"])
	equal_sum("d_accesses", field["rec_d_accesses"],
		field["helper_d_accesses"])
	equal_sum("d_lines", field["rec_d_lines"],
		field["helper_d_lines"])
	equal_sum("d_bytes", field["rec_d_bytes"],
		field["helper_d_bytes"])
	equal_sum("d_misses", field["rec_d_misses"],
		field["helper_d_misses"])
	equal_sum("d_size1", field["rec_d_size1"],
		field["helper_d_size1"])
	equal_sum("d_size2", field["rec_d_size2"],
		field["helper_d_size2"])
	equal_sum("d_size4", field["rec_d_size4"],
		field["helper_d_size4"])
	equal_sum("d_size8p", field["rec_d_size8p"],
		field["helper_d_size8p"])
	frame_reports++
}

END {
	if (header_version != 14) {
		report_error("expected report version 14, got " header_version)
	}
	if (!frame_reports) {
		report_error("no kind=frame report found")
	}
	if (bad) {
		exit 1
	}
	print "cache-model report check: OK frames=" frame_reports
}
