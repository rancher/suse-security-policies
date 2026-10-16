package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1" //nolint:gosec // UUID version 5 is defined with SHA-1.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// The SPDX types keep their fields sorted by JSON key. encoding/json writes
// the fields in this order, and testdata/sbom.golden.json has sorted keys.
type spdxDocument struct {
	SPDXID               string                    `json:"SPDXID"`
	CreationInfo         spdxCreationInfo          `json:"creationInfo"`
	DataLicense          string                    `json:"dataLicense"`
	DocumentNamespace    string                    `json:"documentNamespace"`
	ExternalDocumentRefs []spdxExternalDocumentRef `json:"externalDocumentRefs"`
	Name                 string                    `json:"name"`
	Packages             []spdxPackage             `json:"packages"`
	Relationships        []spdxRelationship        `json:"relationships"`
	SPDXVersion          string                    `json:"spdxVersion"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxExternalDocumentRef struct {
	Checksum           spdxChecksum `json:"checksum"`
	ExternalDocumentID string       `json:"externalDocumentId"`
	SPDXDocument       string       `json:"spdxDocument"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxPackage struct {
	SPDXID                string            `json:"SPDXID"`
	Checksums             []spdxChecksum    `json:"checksums"`
	CopyrightText         string            `json:"copyrightText"`
	DownloadLocation      string            `json:"downloadLocation"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs"`
	FilesAnalyzed         bool              `json:"filesAnalyzed"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	Name                  string            `json:"name"`
	Originator            string            `json:"originator"`
	PackageFileName       string            `json:"packageFileName"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose"`
	SourceInfo            string            `json:"sourceInfo"`
	Supplier              string            `json:"supplier"`
	VersionInfo           string            `json:"versionInfo"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceLocator  string `json:"referenceLocator"`
	ReferenceType     string `json:"referenceType"`
}

type spdxRelationship struct {
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
	SPDXElementID      string `json:"spdxElementId"`
}

var placeholderDigest = "sha256:" + strings.Repeat("0", 64)

// checkSUSESBOM runs before the push, also in a dry run. The upstream
// license, copyright and SPDXID data can fail the validation on every run of
// a release, and a failure after the push leaves an artifact that no run can
// sign. The draft is not a release asset.
func checkSUSESBOM(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleCheckSUSESBOM)
	defer logf("::endgroup::")
	_, err := writeSUSESBOM(ctx, d, d.cfg.Destination.Registry+"/"+d.id+"@"+placeholderDigest, d.path(draftSUSESBOMName))
	return err
}

func suseSBOM(ctx context.Context, d *repackageData) error {
	logf("::group::%s", titleSUSESBOM)
	defer logf("::endgroup::")
	if d.immutableRef == "" {
		return nil
	}
	var err error
	d.suseNamespace, err = writeSUSESBOM(ctx, d, d.immutableRef, d.path(suseSBOMName))
	return err
}

// writeSUSESBOM returns the namespace of the document.
func writeSUSESBOM(ctx context.Context, d *repackageData, immutableRef, path string) (string, error) {
	doc := suseSBOMDocument(d, immutableRef)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The purl holds "&", which must stay as it is.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return "", err
	}
	if out, err := sbomUtility(ctx, "validate", "--input-file", path); err != nil {
		return "", fmt.Errorf("the SUSE SBOM is not valid SPDX 2.3: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return doc.DocumentNamespace, nil
}

// The document does not name the commit of the run, so a second run gives
// the same document for the same artifact and can keep its attestation.
func suseSBOMDocument(d *repackageData, immutableRef string) spdxDocument {
	wasmSum, _ := fileSHA256(d.path(suseWasmName))
	upstreamSum, _ := fileSHA256(d.path(upstreamSBOMName))
	cfg, root, pkg := d.cfg, d.upstreamRoot, "SPDXRef-Package-"+d.id
	repository, digest, _ := strings.Cut(immutableRef, "@")
	return spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: d.id + "-" + d.version,
		DocumentNamespace: cfg.SBOM.NamespaceBase + "/" + d.id + "/" + d.version + "-" + nameUUID(immutableRef),
		CreationInfo: spdxCreationInfo{
			Created:  d.upstreamPublished.UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Organization: SUSE", "Tool: " + cfg.SBOM.ToolName},
		},
		ExternalDocumentRefs: []spdxExternalDocumentRef{{
			ExternalDocumentID: "DocumentRef-upstream", SPDXDocument: d.upstreamNamespace,
			Checksum: spdxChecksum{Algorithm: "SHA256", ChecksumValue: upstreamSum},
		}},
		Packages: []spdxPackage{{
			SPDXID: pkg, Name: d.id, VersionInfo: d.version, PackageFileName: suseWasmName,
			Checksums:     []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: wasmSum}},
			FilesAnalyzed: false, PrimaryPackagePurpose: "APPLICATION",
			Supplier: cfg.SBOM.Supplier, Originator: cfg.SBOM.Originator,
			DownloadLocation: "https://github.com/" + d.repo + "/releases/download/" + d.tag + "/" + suseWasmName,
			ExternalRefs: []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl",
				ReferenceLocator: "pkg:oci/" + d.id + "@" + strings.Replace(digest, ":", "%3A", 1) + "?repository_url=" + repository + "&tag=v" + d.version,
			}},
			SourceInfo: "Repackaged by SUSE from https://github.com/" + cfg.Upstream.Repository + " release " + d.tag +
				" (upstream OCI digest " + d.upstreamDigest + ", upstream source commit " + cmp.Or(str(root, "versionInfo"), "unknown") +
				"). kwctl annotate set the SUSE annotations (io.kubewarden.policy.ociUrl, io.kubewarden.policy.author, io.kubewarden.policy.url, org.opencontainers.image.source and com.suse.policy.upstream.*) in the io.kubewarden.metadata custom section and wrote the module out again. The program made sure that no other metadata changed, except the io.kubewarden.kwctl annotation. The program did not compare the other bytes of the module with upstream.",
			// SUSE did not determine the licenses.
			LicenseConcluded: orNoAssertion(root, "licenseConcluded"), LicenseDeclared: orNoAssertion(root, "licenseDeclared"),
			CopyrightText: orNoAssertion(root, "copyrightText"),
		}},
		Relationships: []spdxRelationship{
			{SPDXElementID: "SPDXRef-DOCUMENT", RelatedSPDXElement: pkg, RelationshipType: "DESCRIBES"},
			{SPDXElementID: pkg, RelatedSPDXElement: "DocumentRef-upstream:" + str(root, "SPDXID"), RelationshipType: "GENERATED_FROM"},
		},
	}
}

func orNoAssertion(v any, key string) string { return cmp.Or(str(v, key), "NOASSERTION") }

// upstreamRoot does not guess, because GENERATED_FROM would then claim a
// provenance that nobody checked. The form of DESCRIBES depends on the tool.
func upstreamRoot(doc any) (any, error) {
	var ids []string
	for _, r := range list(doc, "relationships") {
		if str(r, "relationshipType") == "DESCRIBES" && str(r, "spdxElementId") == "SPDXRef-DOCUMENT" {
			ids = append(ids, str(r, "relatedSpdxElement"))
		}
	}
	for _, id := range list(doc, "documentDescribes") {
		ids = append(ids, str(id))
	}
	slices.Sort(ids)
	if ids = slices.Compact(ids); len(ids) != 1 {
		return nil, fmt.Errorf("the upstream SBOM describes %d packages (%s), but it must describe exactly 1", len(ids), strings.Join(ids, " "))
	}
	for _, p := range list(doc, "packages") {
		if str(p, "SPDXID") == ids[0] {
			return p, nil
		}
	}
	return nil, fmt.Errorf("the upstream SBOM describes %q, but it has no package with that SPDXID", ids[0])
}

// nameUUID returns a version 5 UUID in the URL namespace of RFC 4122.
func nameUUID(name string) string {
	h := sha1.New() //nolint:gosec // UUID version 5 is defined with SHA-1.
	h.Write([]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8})
	h.Write([]byte(name))
	u := h.Sum(nil)[:16]
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	b := hex.EncodeToString(u)
	return b[0:8] + "-" + b[8:12] + "-" + b[12:16] + "-" + b[16:20] + "-" + b[20:32]
}
