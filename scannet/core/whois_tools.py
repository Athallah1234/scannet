import whois
from typing import Dict, Any

class WHOISTools:
    @staticmethod
    def domain_whois(domain: str) -> Dict[str, Any]:
        """Retrieves WHOIS records for a domain."""
        try:
            w = whois.whois(domain)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois_server": w.whois_server,
                "referral_url": w.referral_url,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "country": w.country
            }
        except Exception as e:
            return {"error": f"WHOIS query failed: {e}"}
