"""
Inbox Email Generator & DNS MX Resolver
Generates realistic inbound email streams with authentic multi-hop routing,
DNS MX resolution for the recipient's domain, and detailed forensic source headers.
"""

import socket
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


def resolve_recipient_mx(domain: str) -> Tuple[str, str]:
    """
    Resolve primary MX hostname and IP address for a recipient's domain.
    Falls back gracefully if DNS resolution is unreachable.
    """
    clean_domain = domain.strip().lower()
    if not clean_domain or '.' not in clean_domain:
        return "mx.inbound.local", "198.51.100.25"

    try:
        import dns.resolver
        answers = dns.resolver.resolve(clean_domain, 'MX', lifetime=2.0)
        best = sorted(answers, key=lambda r: r.preference)[0]
        mx_host = best.exchange.to_text().rstrip('.')
        try:
            mx_ip = socket.gethostbyname(mx_host)
        except Exception:
            mx_ip = "192.178.211.27"
        return mx_host, mx_ip
    except Exception as e:
        logger.debug(f"DNS MX resolution fallback for {clean_domain}: {e}")
        # Realistic fallback mapping for common domains
        if 'gmail.com' in clean_domain:
            return "gmail-smtp-in.l.google.com", "192.178.211.27"
        elif 'outlook.com' in clean_domain or 'hotmail.com' in clean_domain:
            return "outlook-com.olc.protection.outlook.com", "52.101.50.1"
        elif 'yahoo.com' in clean_domain:
            return "mta.am0.yahoodns.net", "67.195.204.79"
        elif 'proton' in clean_domain:
            return "mail.protonmail.ch", "185.70.42.128"
        return f"mx.{clean_domain}", "198.51.100.25"


def generate_inbox_emails_for_address(target_email: str, limit: int = 5) -> List[Dict]:
    """
    Generate 5 realistic inbound emails delivered to target_email,
    including authentic multi-hop routing, origin servers, and source headers.
    """
    clean_target = (target_email or "user@gmail.com").strip().lower()
    if '@' in clean_target:
        username, domain = clean_target.split('@', 1)
    else:
        username = clean_target or "user"
        domain = "gmail.com"
        clean_target = f"{username}@{domain}"

    mx_host, mx_ip = resolve_recipient_mx(domain)
    now = datetime.now(timezone.utc)

    def rfc_date(minutes_ago: int) -> str:
        t = now - timedelta(minutes=minutes_ago)
        return t.strftime("%a, %d %b %Y %H:%M:%S +0000")

    scenarios = [
        # 1. Legitimate Bank Statement
        {
            "id": f"inbox_{username}_001_bank_statement",
            "body": f"""Your Monthly Account Statement is Ready

Dear {username.capitalize()},

Your monthly account statement for your Bank of America checking account is now available to download.

Account Ending: ****4892
Statement Period: Recent 30 Days
Statement Available At: Official Mobile App & Online Banking

To review your statement, please log in directly via the official Bank of America mobile application or visit https://www.bankofamerica.com.

For your protection, never share your security passcode, debit card PIN, or online banking password with anyone. Bank of America representatives will never contact you requesting your credentials.

Sincerely,
Bank of America Online Customer Service
https://www.bankofamerica.com""",
            "headers": {
                "From": "Bank of America <statements@bankofamerica.com>",
                "To": clean_target,
                "Subject": f"Monthly Account Statement Available for {clean_target}",
                "Date": rfc_date(12),
                "Message-ID": f"<boa-stmt-{int(now.timestamp())}-001@bankofamerica.com>",
                "Return-Path": "<bounce-statements@bankofamerica.com>",
                "Authentication-Results": f"{mx_host}; spf=pass (sender IP is 171.161.160.100) smtp.mailfrom=statements@bankofamerica.com; dkim=pass header.d=bankofamerica.com; dmarc=pass action=none header.from=bankofamerica.com",
                "Received": f"from mail-out.bankofamerica.com (mail-out.bankofamerica.com [171.161.160.100]) by {mx_host} ([{mx_ip}]) with ESMTPS id boa8921 for <{clean_target}>; {rfc_date(12)}\nfrom internal-core.bankofamerica.com ([10.40.12.5]) by mail-out.bankofamerica.com ([171.161.160.100]); {rfc_date(13)}",
                "X-Originating-IP": "171.161.160.100",
                "X-Mailer": "BankOfAmerica-Core-MTA v4.2"
            }
        },

        # 2. Executive BEC Wire Fraud (Zero-link conversational deception)
        {
            "id": f"inbox_{username}_002_stealth_bec",
            "body": f"""Urgent & Confidential - Wire Settlement Update

Hi {username.capitalize()},

Are you at your desk right now? I am currently tied up in an offsite strategic board meeting with our external acquisition team and cannot take phone calls.

We have an urgent payment of $68,450.00 due today to settle the contractual retainer with our counsel. I need you to initiate a priority wire transfer immediately so we don't breach our agreement.

Wire instructions:
Beneficiary: Apex Strategic Advisory Partners LLC
Bank: Wells Fargo Bank, N.A.
Routing: 12100024
Account: 8847291054
Amount: $68,450.00 USD
Reference: Acquisition-Settlement-Confidential

Please process this immediately from our main operating reserve and email me the wire confirmation receipt as soon as it's completed. Keep this strictly between us until the announcement next week.

Thanks,
David Vance
Chief Executive Officer
Sent from my iPad""",
            "headers": {
                "From": "David Vance, Executive Office <ceo@corp-executive-hq.com>",
                "Reply-To": "david.vance.corp.desk@gmail.com",
                "To": clean_target,
                "Subject": f"[CONFIDENTIAL] Urgent Wire Settlement Required - {clean_target}",
                "Date": rfc_date(35),
                "Message-ID": f"<exec-wire-{int(now.timestamp())}-002@corp-executive-hq.com>",
                "Return-Path": "<bounce@corp-executive-hq.com>",
                "Authentication-Results": f"{mx_host}; spf=softfail (sender IP 103.25.48.12 is neither permitted nor denied) smtp.mailfrom=ceo@corp-executive-hq.com; dkim=none; dmarc=fail action=none header.from=corp-executive-hq.com",
                "Received": f"from relay14.hk-outbound.com (relay14.hk-outbound.com [103.25.48.12]) by {mx_host} ([{mx_ip}]) with ESMTPS id hk7821 for <{clean_target}>; {rfc_date(35)}\nfrom dynamic-pool-103-25-48-12.hk.broadband.net ([103.25.48.12]) by relay14.hk-outbound.com ([103.25.48.12]); {rfc_date(36)}",
                "X-Originating-IP": "103.25.48.12",
                "X-Mailer": "Apple Mail (2.3654.120.0.1)"
            }
        },

        # 3. Tor Exit Node Origin / Anonymizer Credential Harvesting
        {
            "id": f"inbox_{username}_003_tor_relay_phish",
            "body": f"""[SECURITY WARNING] Unauthorized Login from Moscow, Russia

Dear {clean_target},

We observed an unauthorized sign-in attempt to your master account credentials:

Device: Windows 11 Enterprise (Firefox 128)
IP Location: 91.219.236.88 (Moscow, Russian Federation)
Timestamp: Today at 03:42:15 UTC
Status: Blocked Pending Identity Confirmation

Because this connection originated from an unrecognized geographic location, your account privileges have been temporarily frozen to prevent credential harvesting.

You must authenticate your identity within 24 hours to avoid permanent suspension of your mailbox:
http://185.220.101.5/auth-verify/confirm?account={username}

If you do not recognize this activity, verify your session immediately at the URL above.

Security Operations Team
Global Identity Services""",
            "headers": {
                "From": "Account Security Team <security-alert@global-id-protection.com>",
                "To": clean_target,
                "Subject": f"🚨 Security Alert: Unauthorized access attempt for {clean_target}",
                "Date": rfc_date(58),
                "Message-ID": f"<sec-tor-{int(now.timestamp())}-003@global-id-protection.com>",
                "Return-Path": "<bounce@tor-exit-node.net>",
                "Authentication-Results": f"{mx_host}; spf=fail (sender IP 185.220.101.5 not authorized) smtp.mailfrom=security-alert@global-id-protection.com; dkim=fail header.d=global-id-protection.com; dmarc=fail action=reject header.from=global-id-protection.com",
                "Received": f"from mail-relay-nl.fast-bulletproof.com (mail-relay-nl.fast-bulletproof.com [185.220.101.34]) by {mx_host} ([{mx_ip}]) with ESMTPS id tor904 for <{clean_target}>; {rfc_date(58)}\nfrom tor-exit-frankfurt.anonymizer.net ([185.220.101.5]) by mail-relay-nl.fast-bulletproof.com ([185.220.101.34]); {rfc_date(59)}\nfrom hidden-tor-service.onion by tor-exit-frankfurt.anonymizer.net ([185.220.101.5]); {rfc_date(60)}",
                "X-Originating-IP": "185.220.101.5",
                "X-Mailer": "PHPMailer 6.8.0 (Custom Tor Relay)"
            }
        },

        # 4. Brand Impersonation / Typosquat MFA Attack (Microsoft 365)
        {
            "id": f"inbox_{username}_004_brand_typosquat",
            "body": f"""Microsoft 365: Multi-Factor Authentication Reset Required

Notice for User: {clean_target}
Tenant Organization: Enterprise Default
Ticket ID: MS-892147

Your Multi-Factor Authentication (MFA) security certificate for Microsoft 365 is scheduled to expire in 4 hours. Failure to refresh your authentication token will lock you out of Microsoft Teams, Outlook, and OneDrive cloud files.

Please renew your cryptographic authentication token using the official IT self-service gateway:
http://45.77.65.211/m365-verify/login?user={clean_target}

This is a mandatory tenant-wide security policy requirement.

Regards,
Microsoft 365 Security Operations
micros0ft-mfa-support.com""",
            "headers": {
                "From": "Microsoft 365 Security <admin@micros0ft-mfa-support.com>",
                "To": clean_target,
                "Subject": f"Action Required: Microsoft 365 MFA Certificate Expiry for {clean_target}",
                "Date": rfc_date(92),
                "Message-ID": f"<ms-typo-{int(now.timestamp())}-004@micros0ft-mfa-support.com>",
                "Return-Path": "<admin@micros0ft-mfa-support.com>",
                "Authentication-Results": f"{mx_host}; spf=fail (IP 45.77.65.211 is not permitted by microsoft.com) smtp.mailfrom=admin@micros0ft-mfa-support.com; dkim=fail; dmarc=fail action=quarantine header.from=micros0ft-mfa-support.com",
                "Received": f"from smtp-bulletproof-node.jp (smtp-bulletproof-node.jp [45.77.65.211]) by {mx_host} ([{mx_ip}]) with ESMTPS id ms9912 for <{clean_target}>; {rfc_date(92)}\nfrom workstation-tokyo.local ([45.77.65.211]) by smtp-bulletproof-node.jp ([45.77.65.211]); {rfc_date(93)}",
                "X-Originating-IP": "45.77.65.211",
                "X-Mailer": "Exim 4.93 (Linux x86_64)"
            }
        },

        # 5. Legitimate GitHub Notification (Clean Cloud Platform)
        {
            "id": f"inbox_{username}_005_github_notification",
            "body": f"""[GitHub] Security Alert & Repository Notification

Hey {username},

A new commit was successfully deployed to your repository:

Repository: {username}/MailForensic-AI
Commit: 09b29b1
Branch: main
Author: Praveen Tiwari <praveen.tiwari@example.com>
Message: MailForensic-AI Enterprise Update

All CI/CD forensic verification suites and automated tests passed with 100% compliance.

View commit diff: https://github.com/Tiwari-Praveen-Codes/MailForensic-AI/commit/09b29b1

You received this email because you are watching this repository or are a team collaborator.
Manage notification settings: https://github.com/settings/notifications

GitHub, Inc. • 88 Colin P Kelly Jr St • San Francisco, CA 94107""",
            "headers": {
                "From": "GitHub Notifications <notifications@github.com>",
                "To": clean_target,
                "Subject": f"[GitHub] Commit pushed to {username}/MailForensic-AI",
                "Date": rfc_date(120),
                "Message-ID": f"<gh-commit-{int(now.timestamp())}-005@github.com>",
                "Return-Path": "<noreply@github.com>",
                "Authentication-Results": f"{mx_host}; spf=pass (sender IP is 192.30.252.206) smtp.mailfrom=notifications@github.com; dkim=pass header.d=github.com; dmarc=pass action=none header.from=github.com",
                "Received": f"from smtp.github.com (smtp.github.com [192.30.252.206]) by {mx_host} ([{mx_ip}]) with ESMTPS id gh4401 for <{clean_target}>; {rfc_date(120)}\nfrom github-worker-prod.internal ([10.200.15.30]) by smtp.github.com ([192.30.252.206]); {rfc_date(121)}",
                "X-Originating-IP": "192.30.252.206",
                "X-Mailer": "GitHub-Notification-Engine/3.2"
            }
        }
    ]

    selected = scenarios[:limit]
    result = []
    for s in selected:
        headers_dict = s.get("headers", {})
        header_lines = [f"{k}: {v}" for k, v in headers_dict.items()]
        email_obj = {
            "id": s["id"],
            "body": s["body"],
            "raw_body": s["body"],
            "headers": headers_dict,
            "raw_headers": "\n".join(header_lines),
            "target_inbox": clean_target,
            "mx_host": mx_host,
            "mx_ip": mx_ip
        }
        result.append(email_obj)

    return result
