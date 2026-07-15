# Phishing Email IOC Summary

## Analyst Verdict

**Classification: Simulated Phishing Email**

The email contained multiple high-confidence phishing indicators, including a lookalike sender domain, failed email authentication, urgency-based language, and a deceptive hyperlink.

## Indicators of Compromise

| Type | Indicator | Analyst Notes |
|---|---|---|
| Sender address | security-alert@micros0ft-support.example | Uses `0` instead of `o` in Microsoft |
| Sender domain | micros0ft-support.example | Lookalike domain |
| Reply-To address | recovery-team@outlook-security.example | Does not match sender domain |
| Sending IP | 203.0.113.45 | Safe simulated IP used for the lab |
| Actual URL | https://secure-login.example.com/session/verify?id=784392 | Destination does not match visible link |
| Visible URL | https://account.microsoft.com/security | Designed to appear legitimate |
| SPF | Fail | Sending server was not authorized |
| DKIM | None | Message was not digitally signed |
| DMARC | Fail | Sender identity failed alignment |

## Social-Engineering Indicators

- Urgent request to act within 30 minutes
- Warning that account access may be restricted
- Trusted Microsoft branding
- Deceptive link text
- Fear of account suspension

## Recommended Response

1. Do not click the link.
2. Quarantine or delete the email.
3. Block the sender address and related domains.
4. Search for other recipients of the message.
5. Determine whether any user clicked the link.
6. Reset credentials if information was submitted.
7. Review authentication logs for unusual activity.
8. Document and escalate the incident.
