from __future__ import annotations

import re
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING

from .http import Client, HTTPError
from .models import Extraction

if TYPE_CHECKING:
    from .store import Store


PLACEHOLDERS = {"", "unknown", "n/a"}


def _identity(value: object) -> str:
    """Normalize display and CPE tokens for conservative identity comparison."""
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _words(value: object) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+", str(value or "").casefold()))


def _identifier_namespace(value: object) -> bool:
    return bool(re.fullmatch(r"(?:cve|gcve|ghsa)(?:[-_ ].*)?", str(value or ""), re.IGNORECASE))


@dataclass(slots=True)
class CPERegistry:
    """Validate extracted product/vendor names against the GCVE CPE registry."""

    client: Client
    base_url: str = "https://cpe.gcve.eu"

    def _suggest(self, kind: str, query: str) -> list[dict[str, object]]:
        """Return suggestion dictionaries, degrading registry errors to no match.

        Keeping all endpoint access in this method also makes the helper-based
        product/vendor resolver safe: `_product` must never depend on a method
        that is only conditionally defined by a previous refactor.
        """
        try:
            payload = self.client.get_json(
                f"{self.base_url.rstrip('/')}/api/{kind}/suggest",
                {"q": query, "limit": "20"},
            )
        except (HTTPError, OSError, RuntimeError, ValueError):
            return []
        items = payload.get("items", []) if isinstance(payload, dict) else []
        return [item for item in items if isinstance(item, dict)]

    @staticmethod
    def _exact(items: list[dict[str, object]], value: str) -> list[dict[str, object]]:
        wanted = _identity(value)
        return [
            item for item in items
            if wanted and wanted in {_identity(item.get("name")), _identity(item.get("title"))}
        ]

    def _product(self, name: str, vendor: str = "") -> dict[str, object] | None:
        """Resolve one exact and unambiguous product suggestion."""
        matches = [item for item in self._exact(self._suggest("products", name), name)
                   if item.get("vendor_name")]
        if vendor:
            wanted_vendor = _identity(vendor)
            matches = [
                item for item in matches
                if wanted_vendor in {
                    _identity(item.get("vendor_name")), _identity(item.get("vendor_title")),
                }
            ]
        identities = {
            (str(item.get("uuid") or ""), str(item.get("vendor_uuid") or ""))
            for item in matches
        }
        return matches[0] if matches and len(identities) == 1 else None

    def enrich(self, extraction: Extraction) -> Extraction:
        """Fill a missing vendor only when one unambiguous product is found.

        The suggestion endpoint uses prefix matching, so accepting its first
        result could silently assign a related product.  Require an exact
        normalized name/title match and a unique product/vendor identity.
        Registry availability must never prevent preservation of a message.
        """
        if (extraction.vendor_hint or not extraction.product_hint or not self.base_url
                or _identifier_namespace(extraction.product_hint)):
            return extraction
        if match := self._product(extraction.product_hint):
            vendor = str(match.get("vendor_title") or match["vendor_name"])
            if _identifier_namespace(vendor):
                return extraction
            extraction.product_hint = str(match.get("title") or match.get("name"))
            extraction.vendor_hint = vendor
            extraction.cpe_product_uuid = str(match.get("uuid") or "")
            extraction.cpe_vendor_uuid = str(match.get("vendor_uuid") or "")
            return extraction

    @staticmethod
    def _unique(items: list[dict[str, object]], *keys: str) -> dict[str, object] | None:
        identities = {tuple(str(item.get(key) or "") for key in keys) for item in items}
        return items[0] if items and len(identities) == 1 else None

    def _product(self, name: str, vendor: str = "") -> dict[str, object] | None:
        matches = self._exact(self._suggest("products", name), name)
        if vendor and vendor.casefold() not in PLACEHOLDERS:
            compatible = [
                item for item in matches
                if _identity(vendor) in {
                    _identity(item.get("vendor_name")), _identity(item.get("vendor_title")),
                }
            ]
            if compatible:
                matches = compatible
        matches = [item for item in matches if item.get("vendor_name")]
        return self._unique(matches, "uuid", "vendor_uuid")

    def _vendor(self, name: str) -> dict[str, object] | None:
        return self._unique(self._exact(self._suggest("vendors", name), name), "uuid")

    @staticmethod
    def _apply_product(extraction: Extraction, match: dict[str, object]) -> None:
        vendor = str(match.get("vendor_title") or match.get("vendor_name") or "")
        if not vendor or _identifier_namespace(vendor):
            return
        extraction.product_hint = str(match.get("title") or match.get("name") or extraction.product_hint)
        extraction.vendor_hint = vendor
        extraction.cpe_product_uuid = str(match.get("uuid") or "")
        extraction.cpe_vendor_uuid = str(match.get("vendor_uuid") or "")

    def enrich(self, extraction: Extraction) -> Extraction:
        """Canonicalize a product/vendor only when the registry is unambiguous.

        Existing values are checked too: this lets a product match correct an
        advisory author mistakenly extracted as its vendor. Registry failures
        or ambiguous prefix results leave the original evidence untouched.
        """
        product = extraction.product_hint.strip()
        if not product or not self.base_url or _identifier_namespace(product):
            return extraction
        items = self._suggest("vendors", product_words[0])
        prefixes: list[tuple[int, dict[str, object]]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            remainder = " ".join(words[length:])
            candidates = self._exact(self._suggest("products", remainder), remainder)
            candidates = [
                item for item in candidates
                if str(item.get("vendor_uuid") or "") == str(vendor_match.get("uuid") or "")
            ]
            if lengths:
                prefixes.append((max(lengths), item))
        if not prefixes:
            return extraction
        longest = max(length for length, _ in prefixes)
        matches = [item for length, item in prefixes if length == longest]
        identities = {str(item.get("uuid") or "") for item in matches}
        if len(identities) != 1:
            return extraction
        match = matches[0]
        vendor = str(match.get("title") or match.get("name"))
        if _identifier_namespace(vendor):
            return extraction
        extraction.vendor_hint = vendor
        extraction.cpe_vendor_uuid = str(match.get("uuid") or "")
        return extraction

    def enrich_store(self, store: Store, *, limit: int = 0) -> dict[str, int]:
        """Validate eligible stored observations and return run counters."""
        candidates = store.cpe_enrichment_candidates(limit)
        allowed = {item.name for item in fields(Extraction)}
        enriched = 0
        publications_updated = 0
        for row in candidates:
            raw = row.get("extraction")
            values = raw if isinstance(raw, dict) else {}
            extraction = Extraction(**{key: value for key, value in values.items() if key in allowed})
            before = (
                extraction.product_hint, extraction.vendor_hint,
                extraction.cpe_product_uuid, extraction.cpe_vendor_uuid,
            )
            self.enrich(extraction)
            after = (
                extraction.product_hint, extraction.vendor_hint,
                extraction.cpe_product_uuid, extraction.cpe_vendor_uuid,
            )
            if after != before and (extraction.cpe_product_uuid or extraction.cpe_vendor_uuid):
                store.update_extraction(str(row["source_url"]), extraction)
                publications_updated += store.update_published_affected(
                    str(row["source_url"]), extraction.vendor_hint, extraction.product_hint,
                    previous_product=before[0],
                )
                enriched += 1
        return {
            "candidates": len(candidates),
            "enriched": enriched,
            "unchanged": len(candidates) - enriched,
            "publications_updated": publications_updated,
        }
