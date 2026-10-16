"""Official domains per brand. Edit backend/app/rules/data/brands.yaml instead."""

from app.rules.loader import get_brand_domains

BRAND_OFFICIAL_DOMAINS: dict[str, list[str]] = get_brand_domains()
