import unittest
import tempfile
from pathlib import Path

from fd_sightings.cpe import CPERegistry
from fd_sightings.http import HTTPError
from fd_sightings.models import Extraction
from fd_sightings.models import Message
from fd_sightings.store import Store


class CPERegistryTests(unittest.TestCase):
    def test_exact_product_match_adds_canonical_product_and_vendor(self):
        class Client:
            def get_json(self, url, params=None):
                self.request = (url, params)
                return {"items": [{
                    "uuid": "product-uuid",
                    "vendor_uuid": "vendor-uuid",
                    "name": "widget_server",
                    "title": "Widget Server",
                    "vendor_name": "example_corp",
                    "vendor_title": "Example Corp",
                }]}

        client = Client()
        extraction = CPERegistry(client, "https://cpe.example").enrich(
            Extraction(product_hint="widget-server", relevant=True)
        )

        self.assertEqual(extraction.product_hint, "Widget Server")
        self.assertEqual(extraction.vendor_hint, "Example Corp")
        self.assertEqual(extraction.cpe_product_uuid, "product-uuid")
        self.assertEqual(extraction.cpe_vendor_uuid, "vendor-uuid")
        self.assertEqual(client.request, (
            "https://cpe.example/api/products/suggest",
            {"q": "widget-server", "limit": "20"},
        ))

    def test_prefix_only_or_ambiguous_matches_do_not_guess(self):
        class Client:
            def get_json(self, url, params=None):
                return {"items": [
                    {"uuid": "one", "vendor_uuid": "v1", "name": "widget_server",
                     "vendor_name": "first"},
                    {"uuid": "two", "vendor_uuid": "v2", "name": "widget",
                     "vendor_name": "second"},
                ]}

        extraction = Extraction(product_hint="Widget")
        CPERegistry(Client()).enrich(extraction)
        self.assertEqual(extraction.vendor_hint, "second")

        extraction = Extraction(product_hint="Widget Server")
        duplicate = Client()
        duplicate.get_json = lambda url, params=None: {"items": [
            {"uuid": "one", "vendor_uuid": "v1", "name": "widget_server", "vendor_name": "first"},
            {"uuid": "two", "vendor_uuid": "v2", "title": "Widget Server", "vendor_name": "second"},
        ]}
        CPERegistry(duplicate).enrich(extraction)
        self.assertEqual(extraction.vendor_hint, "")

    def test_existing_vendor_and_service_errors_leave_extraction_unchanged(self):
        class Client:
            def get_json(self, url, params=None):
                raise HTTPError(503, "Unavailable")

        known = Extraction(product_hint="Widget", vendor_hint="Known Vendor")
        self.assertIs(CPERegistry(Client()).enrich(known), known)
        missing = Extraction(product_hint="Widget")
        self.assertIs(CPERegistry(Client()).enrich(missing), missing)
        self.assertEqual(missing.vendor_hint, "")

    def test_identifier_is_never_looked_up_as_a_product(self):
        class Client:
            def get_json(self, url, params=None):
                raise AssertionError("identifier must not be sent to CPE suggestions")

        extraction = Extraction(product_hint="CVE-2026-52307")
        CPERegistry(Client()).enrich(extraction)
        self.assertEqual(extraction.vendor_hint, "")

    def test_product_helper_degrades_when_suggestion_service_fails(self):
        class Client:
            def get_json(self, url, params=None):
                raise HTTPError(503, "Unavailable")

        self.assertIsNone(CPERegistry(Client())._product("Widget"))

    def test_vendor_prefix_helper_has_no_external_local_state(self):
        class Client:
            def get_json(self, url, params=None):
                return {"items": [{"uuid": "apple", "name": "apple", "title": "Apple"}]}

        match = CPERegistry(Client())._vendor_prefix("Apple macOS")
        self.assertEqual(match["title"], "Apple")

    def test_vendor_prefix_is_used_when_combined_product_name_has_no_product_match(self):
        class Client:
            def get_json(self, url, params=None):
                if url.endswith("/api/products/suggest"):
                    if params["q"] == "macos":
                        return {"items": [{
                            "uuid": "macos-uuid", "vendor_uuid": "apple-uuid",
                            "name": "macos", "title": "macOS", "vendor_name": "apple",
                            "vendor_title": "Apple",
                        }]}
                    return {"items": []}
                self.vendor_request = (url, params)
                return {"items": [{
                    "uuid": "apple-uuid", "name": "apple", "title": "Apple",
                }]}

        client = Client()
        extraction = CPERegistry(client).enrich(Extraction(product_hint="Apple macOS"))

        self.assertEqual(extraction.vendor_hint, "Apple")
        self.assertEqual(extraction.product_hint, "macOS")
        self.assertEqual(extraction.cpe_vendor_uuid, "apple-uuid")
        self.assertEqual(extraction.cpe_product_uuid, "macos-uuid")
        self.assertEqual(client.vendor_request, (
            "https://cpe.gcve.eu/api/vendors/suggest", {"q": "apple", "limit": "20"},
        ))

    def test_mass_enrichment_validates_existing_vendors_too(self):
        class Client:
            def get_json(self, url, params=None):
                product = params["q"]
                return {"items": [{
                    "uuid": f"{product}-uuid", "vendor_uuid": "vendor-uuid",
                    "name": product, "vendor_name": "canonical_vendor",
                }]}

        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "cpe.sqlite")
            try:
                store.save(Message("missing", "Missing"), Extraction(product_hint="widget"), [])
                store.save(
                    Message("known", "Known"),
                    Extraction(product_hint="gadget", vendor_hint="Existing Vendor"), [],
                )
                result = CPERegistry(Client()).enrich_store(store)

                self.assertEqual(result, {
                    "candidates": 2, "enriched": 2, "unchanged": 0,
                    "publications_updated": 0,
                })
                self.assertEqual(store.get("missing")["extraction"]["vendor_hint"], "canonical_vendor")
                self.assertEqual(store.get("known")["extraction"]["vendor_hint"], "canonical_vendor")
            finally:
                store.close()

    def test_mass_enrichment_corrects_an_already_published_unknown_vendor(self):
        class Client:
            def get_json(self, url, params=None):
                if url.endswith("/api/products/suggest"):
                    if params["q"] == "macos":
                        return {"items": [{
                            "uuid": "macos-uuid", "vendor_uuid": "apple-uuid",
                            "name": "macos", "title": "macOS", "vendor_name": "apple",
                            "vendor_title": "Apple",
                        }]}
                    return {"items": []}
                return {"items": [{"uuid": "apple-uuid", "name": "apple", "title": "Apple"}]}

        record = {
            "cveMetadata": {"vulnId": "GCVE-1988-2026-0291", "dateUpdated": "2026-01-01T00:00:00Z"},
            "containers": {"cna": {
                "providerMetadata": {"dateUpdated": "2026-01-01T00:00:00Z"},
                "affected": [
                    {"vendor": "unknown", "product": "Apple macOS"},
                    {"vendor": "Other", "product": "Unrelated"},
                ],
            }},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "published.sqlite")
            try:
                store.save(Message("apple", "Apple"), Extraction(product_hint="Apple macOS"), [])
                store.save_publication(
                    "apple", "gcve:advisory", "gcve", gcve_id="GCVE-1988-2026-0291",
                    status="published", payload=record,
                )

                result = CPERegistry(Client()).enrich_store(store)

                self.assertEqual(result["publications_updated"], 1)
                published = store.gcve_record("GCVE-1988-2026-0291")
                affected = published["containers"]["cna"]["affected"]
                self.assertEqual(affected[0]["vendor"], "Apple")
                self.assertEqual(affected[0]["product"], "macOS")
                self.assertEqual(affected[1], {"vendor": "Other", "product": "Unrelated"})
                self.assertNotEqual(
                    published["cveMetadata"]["dateUpdated"], "2026-01-01T00:00:00Z",
                )
            finally:
                store.close()

    def test_refresh_correction_replaces_identifier_affected_values(self):
        record = {
            "cveMetadata": {"vulnId": "GCVE-1988-2026-0314"},
            "containers": {"cna": {
                "providerMetadata": {},
                "affected": [{"vendor": "CVE", "product": "CVE-2026-52307"}],
            }},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "correction.sqlite")
            try:
                store.save(Message("source", "CVE title"), Extraction(), [])
                store.save_publication(
                    "source", "gcve:advisory", "gcve", gcve_id="GCVE-1988-2026-0314",
                    status="published", payload=record,
                )
                updated = store.update_published_affected(
                    "source", vendor="Acme", product="Mail Gateway",
                )
                self.assertEqual(updated, 1)
                affected = store.gcve_record("GCVE-1988-2026-0314")["containers"]["cna"]["affected"]
                self.assertEqual(affected, [{"vendor": "Acme", "product": "Mail Gateway"}])
            finally:
                store.close()

    def test_refresh_correction_replaces_advisory_id_product_prefix(self):
        record = {
            "cveMetadata": {"vulnId": "GCVE-1988-2026-0315"},
            "containers": {"cna": {
                "providerMetadata": {},
                "affected": [{
                    "vendor": "Apple", "product": "APPLE-SA-08-18-2026-1 Safari",
                }],
            }},
        }
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "advisory-prefix.sqlite")
            try:
                store.save(Message("source", "Apple advisory"), Extraction(), [])
                store.save_publication(
                    "source", "gcve:advisory", "gcve", gcve_id="GCVE-1988-2026-0315",
                    status="published", payload=record,
                )
                updated = store.update_published_affected(
                    "source", vendor="Apple", product="Safari",
                )
                self.assertEqual(updated, 1)
                affected = store.gcve_record("GCVE-1988-2026-0315")["containers"]["cna"]["affected"]
                self.assertEqual(affected, [{"vendor": "Apple", "product": "Safari"}])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
