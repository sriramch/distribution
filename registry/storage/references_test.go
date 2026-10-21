package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/cache/memory"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func newTestReferenceService(t *testing.T) (*manifestStoreTestEnv, ReferenceService) {
	t.Helper()

	repoName, _ := reference.WithName("foo/bar")
	env := newManifestStoreTestEnv(t, repoName, "thetag",
		BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)))

	manifests, err := env.repository.Manifests(env.ctx)
	if err != nil {
		t.Fatalf("unexpected error getting manifest service: %v", err)
	}
	return env, manifests.(*manifestStore).references
}

func TestUnlinkRemovesExistingLink(t *testing.T) {
	ctx := context.Background()
	env, refSvc := newTestReferenceService(t)
	artifactType := "application/vnd.dsse.envelope.v1+json"

	// Push a real referring manifest so the existence check the read path
	// relies on actually passes.
	mfst, err := createRandomImage(t, t.Name(), v1.MediaTypeImageManifest, env.repository.Blobs(ctx))
	if err != nil {
		t.Fatalf("unexpected error generating random image: %v", err)
	}
	manifests, err := env.repository.Manifests(ctx)
	if err != nil {
		t.Fatalf("unexpected error getting manifest service: %v", err)
	}
	referrer, err := manifests.Put(ctx, mfst)
	if err != nil {
		t.Fatalf("unexpected error putting referrer manifest: %v", err)
	}

	subject := digest.FromBytes([]byte("subject-unlink-existing"))

	if err := refSvc.Link(ctx, artifactType, referrer, subject); err != nil {
		t.Fatalf("unexpected error linking referrer to subject: %v", err)
	}

	// Sanity check: the link is visible via the read path before Unlink runs.
	// This guards against the assertions below passing vacuously.
	descriptors, err := refSvc.Referrers(ctx, subject, artifactType)
	if err != nil {
		t.Fatalf("unexpected error enumerating referrers before unlink: %v", err)
	}
	if len(descriptors) != 1 || descriptors[0].Digest != referrer {
		t.Fatalf("expected exactly one referrer %s before unlink, got %v", referrer, descriptors)
	}

	if err := refSvc.Unlink(ctx, artifactType, referrer, subject); err != nil {
		t.Fatalf("unexpected error unlinking referrer from subject: %v", err)
	}

	// Assert the native link path itself is gone, independent of Referrers()'
	// own filtering, so this test still fails if Unlink stops deleting it.
	linkPath, err := subjectReferrerLinkPath("foo/bar", artifactType, referrer, subject)
	if err != nil {
		t.Fatalf("unexpected error building link path: %v", err)
	}
	if _, err := env.driver.Stat(ctx, linkPath); !isPathNotFound(err) {
		t.Fatalf("expected link path %s to be removed by Unlink, got err: %v", linkPath, err)
	}

	descriptors, err = refSvc.Referrers(ctx, subject, artifactType)
	if err != nil {
		t.Fatalf("unexpected error enumerating referrers after unlink: %v", err)
	}
	if len(descriptors) != 0 {
		t.Fatalf("expected no referrers after unlink, got %d", len(descriptors))
	}
}

func TestUnlinkMissingLinkIsNoop(t *testing.T) {
	_, refSvc := newTestReferenceService(t)
	subject := digest.FromBytes([]byte("subject-unlink-missing"))
	referrer := digest.FromBytes([]byte("referrer-unlink-missing"))

	if err := refSvc.Unlink(context.Background(), "application/vnd.dsse.envelope.v1+json", referrer, subject); err != nil {
		t.Fatalf("expected missing link unlink to be a no-op, got error: %v", err)
	}
}

func TestUnlinkReturnsPathBuildError(t *testing.T) {
	_, refSvc := newTestReferenceService(t)
	handler := refSvc.(*referenceHandler)

	pathErr := errors.New("path build failed")
	handler.pathFn = func(name, mediaType string, reference, subject digest.Digest) (string, error) {
		return "", pathErr
	}

	err := handler.Unlink(
		context.Background(),
		"application/vnd.dsse.envelope.v1+json",
		digest.FromBytes([]byte("referrer-unlink-path-error")),
		digest.FromBytes([]byte("subject-unlink-path-error")),
	)
	if !errors.Is(err, pathErr) {
		t.Fatalf("expected path build error, got: %v", err)
	}
}
