package storage

import (
	"fmt"

	"github.com/distribution/distribution/v3"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// validateSubject checks that a subject descriptor is structurally valid for
// use as a referrer subject. It must be called during manifest verification
// (verifyManifest), not during parse (UnmarshalJSON). UnmarshalJSON fires on
// every deserialize — pull, referrers enumeration, internal reads — so placing
// strict digest/size validation there would re-validate already-stored content
// on every read and could reject lenient legacy manifests that pre-date this
// check. verifyManifest runs only in Put (push), so the validation is
// push-time and pre-storage without affecting the read path.
func validateSubject(subject *v1.Descriptor) error {
	if subject == nil {
		return nil
	}
	if subject.MediaType == "" {
		return fmt.Errorf("subject.mediaType is required")
	}
	if !distribution.ManifestMediaTypeSupported(subject.MediaType) {
		return fmt.Errorf("subject.mediaType must be a manifest, not %q", subject.MediaType)
	}
	if err := subject.Digest.Validate(); err != nil {
		return fmt.Errorf("subject.digest invalid: %w", err)
	}
	return nil
}
