import os
import csv
import random

# Seed for reproducibility
random.seed(42)

BENIGN_URLS = [
    # Search & Tech
    ("https://www.google.com/search?q=machine+learning+security", 0, "google.com", "search"),
    ("https://github.com/torvalds/linux/commit/80b628b8", 0, "github.com", "developer"),
    ("https://en.wikipedia.org/wiki/Phishing", 0, "wikipedia.org", "reference"),
    ("https://docs.python.org/3/library/urllib.parse.html", 0, "python.org", "documentation"),
    ("https://pypi.org/project/scikit-learn/", 0, "pypi.org", "package_repo"),
    ("https://stackoverflow.com/questions/11887762/how-to-compare-two-arrays-in-python", 0, "stackoverflow.com", "developer"),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers", 0, "mozilla.org", "documentation"),
    ("https://huggingface.co/models?pipeline_tag=text-classification", 0, "huggingface.co", "ai_platform"),
    ("https://arxiv.org/abs/2103.00020", 0, "arxiv.org", "academic"),
    ("https://scholar.google.com/citations?user=sample", 0, "google.com", "academic"),
    
    # Cloud & Enterprise
    ("https://aws.amazon.com/ec2/pricing/on-demand/", 0, "amazon.com", "cloud"),
    ("https://cloud.google.com/kubernetes-engine/docs", 0, "google.com", "cloud"),
    ("https://portal.azure.com/#home", 0, "azure.com", "enterprise"),
    ("https://slack.com/workspace/signin", 0, "slack.com", "collaboration"),
    ("https://zoom.us/j/1234567890", 0, "zoom.us", "collaboration"),
    ("https://drive.google.com/drive/u/0/my-drive", 0, "google.com", "cloud_storage"),
    ("https://dropbox.com/home/shared_documents", 0, "dropbox.com", "cloud_storage"),
    ("https://jira.atlassian.net/jira/software/projects", 0, "atlassian.net", "project_mgmt"),
    ("https://trello.com/b/proj1234/sprint-board", 0, "trello.com", "project_mgmt"),
    ("https://notion.so/workspace/cybersecurity-roadmap", 0, "notion.so", "productivity"),

    # News, Reference & E-commerce
    ("https://www.bbc.com/news/technology-5928374", 0, "bbc.com", "news"),
    ("https://www.nytimes.com/section/technology", 0, "nytimes.com", "news"),
    ("https://reuters.com/business/finance-news-today", 0, "reuters.com", "news"),
    ("https://www.nature.com/articles/s41586-020-2649-2", 0, "nature.com", "academic"),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0, "amazon.com", "ecommerce"),
    ("https://www.apple.com/iphone-16-pro/specs/", 0, "apple.com", "ecommerce"),
    ("https://www.paypal.com/signin", 0, "paypal.com", "banking"),
    ("https://www.netflix.com/browse/genre/83", 0, "netflix.com", "streaming"),
    ("https://www.spotify.com/us/premium/", 0, "spotify.com", "streaming"),
    ("https://www.reddit.com/r/netsec/comments/sample_post", 0, "reddit.com", "social"),
    ("https://medium.com/@infosec/evaluating-zero-day-phishing", 0, "medium.com", "blog"),
    ("https://news.ycombinator.com/item?id=38192019", 0, "ycombinator.com", "community"),
    ("https://www.linkedin.com/in/security-engineer-sample", 0, "linkedin.com", "professional"),
    ("https://chase.com/personal/banking", 0, "chase.com", "banking"),
    ("https://bankofamerica.com/online-banking/overview.go", 0, "bankofamerica.com", "banking")
]

PHISHING_URLS = [
    # Brand Impersonation & Typosquatting
    ("http://paypa1-account-verification-alert.com/login.php?cmd=verify", 1, "paypa1-account-verification-alert.com", "brand_impersonation"),
    ("https://secure-login.paypal.com.account-update-notice.xyz/signin", 1, "account-update-notice.xyz", "subdomain_brand_abuse"),
    ("http://accounts-google-security-notice.top/signin/v2/identifier", 1, "accounts-google-security-notice.top", "brand_impersonation"),
    ("https://appleid-icloud-device-locked.info/account/unlock?token=938210", 1, "appleid-icloud-device-locked.info", "brand_impersonation"),
    ("http://netflix-billing-issue-update.cc/service/update_card", 1, "netflix-billing-issue-update.cc", "credential_harvesting"),
    ("https://chase-security-verify-identity.site/auth/logon?srv=retail", 1, "chase-security-verify-identity.site", "financial_phishing"),
    ("http://bankofamerica-alert-customer.top/bofa/login.htm", 1, "bankofamerica-alert-customer.top", "financial_phishing"),
    ("https://wellsfargo-notice-urgent.com/w/login?session=a7f93b21", 1, "wellsfargo-notice-urgent.com", "financial_phishing"),
    ("http://microsoft-onedrive-file-share.download.link/auth?user=target", 1, "microsoft-onedrive-file-share.download.link", "brand_impersonation"),
    ("https://c0inbase-wallet-security-fix.org/claim/airdrop", 1, "c0inbase-wallet-security-fix.org", "crypto_drainer"),
    ("http://binance-safety-kyc-validation.pw/login", 1, "binance-safety-kyc-validation.pw", "crypto_drainer"),
    ("https://amazon-prime-membership-renew.vip/account?alert=suspended", 1, "amazon-prime-membership-renew.vip", "brand_impersonation"),
    ("http://facebook-security-appeal-form-93821.xyz/support/case", 1, "facebook-security-appeal-form-93821.xyz", "credential_harvesting"),

    # IP-based Hosts
    ("http://192.168.1.100/admin/secure_login.php?dest=dashboard", 1, "192.168.1.100", "ip_address_host"),
    ("http://45.33.32.156/bank/verification/submit.aspx?id=82739", 1, "45.33.32.156", "ip_address_host"),
    ("http://185.220.101.5/wp-content/plugins/login/paypal_auth.php", 1, "185.220.101.5", "ip_address_host"),
    ("http://104.244.72.115/update/credentials.html", 1, "104.244.72.115", "ip_address_host"),

    # Homoglyphs & Confusables (Cyrillic a, e, o etc.)
    ("https://xn--pypal-4ve.com/signin/webapps/mpp/home", 1, "xn--pypal-4ve.com", "punycode_homoglyph"),
    ("https://xn--appl-coa.com/icloud/find-my-iphone", 1, "xn--appl-coa.com", "punycode_homoglyph"),
    ("https://xn--gogle-qqa.com/webhp?auth=expired", 1, "xn--gogle-qqa.com", "punycode_homoglyph"),
    ("http://microsоft-security.com/office365/login", 1, "microsоft-security.com", "unicode_confusable"),

    # High-Entropy, Obfuscated & Nested Redirects
    ("http://auth.secure-portal-gateway.top/q?entropy=8f7b2c9e4d1a0b3f5e6d7c8b9a0e1f2&client=2849", 1, "auth.secure-portal-gateway.top", "high_entropy_obfuscated"),
    ("http://portal.client.auth.session.verify.support.urgent-action.cloud/verify?auth=token", 1, "portal.client.auth.session.verify.support.urgent-action.cloud", "deep_subdomain_abuse"),
    ("http://login-help.xyz/redirect?url=http%3A%2F%2Fmalicious-payload.test%2Fharvest.exe", 1, "login-help.xyz", "open_redirect_vector"),
    ("http://bit.ly/3xPh1shU?target=https%3A%2F%2Ffake-bank.ru%2Flogin", 1, "bit.ly", "shortener_redirect_evasion"),
    ("http://tinyurl.com/account-suspended-action-required-now", 1, "tinyurl.com", "shortener_social_engineering"),
    ("http://update-secure-auth.club/%2e%2e/%2e%2e/etc/passwd?payload=%3Cscript%3E", 1, "update-secure-auth.club", "url_encoding_obfuscation"),
    ("http://secure.account.bank.verification.alert.portal.xyz/cgi-bin/login.cgi", 1, "secure.account.bank.verification.alert.portal.xyz", "deep_subdomain_abuse"),
    ("http://dhl-package-tracking-fee-unpaid.top/track/parcel?id=DHL99831", 1, "dhl-package-tracking-fee-unpaid.top", "smishing_lure"),
    ("http://usps-redelivery-scheduled-pay.info/reschedule/step1", 1, "usps-redelivery-scheduled-pay.info", "smishing_lure")
]

# Generate additional diverse test cases across benign and malicious domains
ADDITIONAL_BENIGN_DOMAINS = [
    "cornell.edu", "mit.edu", "stanford.edu", "berkeley.edu", "ox.ac.uk",
    "cdc.gov", "nasa.gov", "weather.gov", "nist.gov", "who.int",
    "gitlab.com", "bitbucket.org", "codepen.io", "jsfiddle.net", "npm.js",
    "theguardian.com", "washingtonpost.com", "forbes.com", "bloomberg.com", "wired.com",
    "steampowered.com", "epicgames.com", "twitch.tv", "vimeo.com", "soundcloud.com",
    "shopify.com", "etsy.com", "target.com", "walmart.com", "bestbuy.com"
]

BENIGN_PATHS = [
    "/about-us", "/privacy-policy", "/terms-of-service", "/docs/getting-started",
    "/api/v1/health", "/blog/2026/cybersecurity-overview", "/products/category/all",
    "/research/publications/paper-2026", "/download/installer.tar.gz", "/help/faq"
]

ADDITIONAL_MALICIOUS_TEMPLATES = [
    ("http://{brand}-security-update-{num}.{tld}/login?user=verify", "brand_impersonation"),
    ("https://{brand}-account-unlock-{num}.{tld}/auth/step2", "credential_harvesting"),
    ("http://confirm-identity-{brand}.{tld}/session/urgent-alert", "urgency_lure"),
    ("http://{sub1}.{sub2}.{sub3}.verify-{num}.{tld}/account/login.php", "deep_subdomain_abuse"),
    ("http://194.87.{ip3}.{ip4}/secure/update_{brand}.html", "ip_address_host"),
    ("http://free-gift-card-claim-{brand}-{num}.{tld}/redeem?card=win", "prize_lure"),
    ("https://xn--{puny}-{num}.{tld}/signin", "punycode_homoglyph"),
]

TLDS = ["xyz", "top", "club", "info", "cc", "pw", "work", "loan", "site", "online"]
BRANDS = ["paypal", "google", "apple", "netflix", "microsoft", "amazon", "chase", "bofa", "coinbase"]

def generate_benchmark_dataset():
    records = []
    
    # 1. Base curated samples
    for url, label, domain, category in BENIGN_URLS:
        records.append({
            "url": url,
            "label": label,
            "domain": domain,
            "category": category,
            "is_synthetic": 0
        })
        
    for url, label, domain, category in PHISHING_URLS:
        records.append({
            "url": url,
            "label": label,
            "domain": domain,
            "category": category,
            "is_synthetic": 0
        })

    # 2. Add realistic variations to ensure statistical robustness (balanced 200+ samples for audit & baselines)
    for i in range(120):
        dom = random.choice(ADDITIONAL_BENIGN_DOMAINS)
        path = random.choice(BENIGN_PATHS)
        query = f"?ref=nav&page={i}&lang=en" if i % 2 == 0 else ""
        url = f"https://www.{dom}{path}{query}"
        records.append({
            "url": url,
            "label": 0,
            "domain": dom,
            "category": "benign_legitimate",
            "is_synthetic": 1
        })

    for i in range(125):
        template, cat = random.choice(ADDITIONAL_MALICIOUS_TEMPLATES)
        brand = random.choice(BRANDS)
        tld = random.choice(TLDS)
        num = random.randint(100, 9999)
        ip3 = random.randint(10, 250)
        ip4 = random.randint(2, 254)
        sub1 = random.choice(["auth", "login", "verify", "secure", "client"])
        sub2 = random.choice(["portal", "service", "gateway", "alert"])
        sub3 = random.choice(["session", "account", "update"])
        puny = random.choice(["googl", "paypl", "app1e", "microsft"])

        url = template.format(
            brand=brand, tld=tld, num=num, ip3=ip3, ip4=ip4,
            sub1=sub1, sub2=sub2, sub3=sub3, puny=puny
        )
        # Extract registered domain
        dom_part = url.split("://")[1].split("/")[0].split(":")[0]
        records.append({
            "url": url,
            "label": 1,
            "domain": dom_part,
            "category": cat,
            "is_synthetic": 1
        })

    # Shuffle records
    random.shuffle(records)

    # Ensure output directories exist
    os.makedirs("data/raw", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)
    os.makedirs("data/synthetic_test", exist_ok=True)

    # Save to data/raw/dataset.csv and data/processed/benchmark_urls.csv
    raw_path = "data/raw/dataset.csv"
    processed_path = "data/processed/benchmark_urls.csv"
    
    fieldnames = ["url", "label", "domain", "category", "is_synthetic"]
    for path in [raw_path, processed_path]:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(records)

    print(f"Generated {len(records)} records saved to {raw_path} and {processed_path}")
    benign_count = sum(1 for r in records if r['label'] == 0)
    malicious_count = sum(1 for r in records if r['label'] == 1)
    print(f"Class distribution: Benign={benign_count}, Malicious={malicious_count}")

if __name__ == "__main__":
    generate_benchmark_dataset()
