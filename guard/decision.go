package guard

// Reason 是可区分的准入判定（拒绝）原因。
type Reason string

const (
	ReasonAllow                    Reason = ""
	ReasonPolicyLoadSyntax         Reason = "policy_syntax_error"
	ReasonPolicyLoadMissing        Reason = "policy_missing_field"
	ReasonPolicyConflict           Reason = "policy_conflict"
	ReasonPolicyUnavailable        Reason = "policy_unavailable"
	ReasonNoMatchingRule           Reason = "no_matching_rule"
	ReasonExplicitDeny             Reason = "explicit_deny"
	ReasonManifestNotFound         Reason = "manifest_not_found"
	ReasonManifestMissingField     Reason = "manifest_missing_field"
	ReasonManifestVersionIncompat  Reason = "manifest_version_incompatible"
	ReasonSignatureMissing         Reason = "signature_missing"
	ReasonSignatureVerifyFailed    Reason = "signature_verification_failed"
	ReasonSigningKeyRevoked        Reason = "signing_key_revoked"
	ReasonSigningKeyUnknown        Reason = "signing_key_unknown"
	ReasonDigestAlgorithmMismatch  Reason = "digest_algorithm_mismatch"
	ReasonDigestAlgorithmUnsupport Reason = "digest_algorithm_unsupported"
	ReasonAttestationMissing       Reason = "attestation_missing"
	ReasonAttestationInvalid       Reason = "attestation_invalid"
)

// Decision 是一次准入评估的结论。
type Decision struct {
	Allowed       bool
	ImageID       string
	Reason        Reason
	Detail        string
	PolicyVersion int
	MatchedRule   string
}
