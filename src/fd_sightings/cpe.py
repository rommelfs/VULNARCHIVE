from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .http import Client, HTTPError
from .models import Extraction


def _identity(value: object) -> str:
    """Normalize display and CPE tokens for conservative identity comparison."""
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


@dataclass(slots=True)
class CPERegistry:
    """Resolve extracted product names against the GCVE CPE OpenAPI service."""

    client: Client
    base_url: str = "https://cpe.gcve.eu"

    def enrich(self, extraction: Extraction) -> Extraction:
        """Fill a missing vendor only when one unambiguous product is found.

        The suggestion endpoint uses prefix matching, so accepting its first
        result could silently assign a related product.  Require an exact
        normalized name/title match and a unique product/vendor identity.
        Registry availability must never prevent preservation of a message.
        """
        if extraction.vendor_hint or not extraction.product_hint or not self.base_url:
            return extraction
        try:
            payload = self.client.get_json(
                f"{self.base_url.rstrip('/')}/api/products/suggest",
                {"q": extraction.product_hint, "limit": "20"},
            )
        except (HTTPError, OSError, RuntimeError, ValueError):
            return extraction
        items = payload.get("items", []) if isinstance(payload, dict) else []
        wanted = _identity(extraction.product_hint)
        matches = [
            item for item in items
            if isinstance(item, dict)
            and wanted
            and wanted in {_identity(item.get("name")), _identity(item.get("title"))}
            and item.get("vendor_name")
        ]
        identities = {
            (str(item.get("uuid") or ""), str(item.get("vendor_uuid") or ""))
            for item in matches
        }
        if len(identities) != 1:
            return extraction
        match = matches[0]
        extraction.product_hint = str(match.get("title") or match.get("name"))
        extraction.vendor_hint = str(match.get("vendor_title") or match["vendor_name"])
        extraction.cpe_product_uuid = str(match.get("uuid") or "")
        extraction.cpe_vendor_uuid = str(match.get("vendor_uuid") or "")
        return extraction
