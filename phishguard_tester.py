# test_phishguard.py
import unittest

# Import our domain models and core engine
from models import EmailMessage, Indicator, RiskLevel
from extractor import extract_links, extract_sender
from parser import parse_email
from scoring import calculate_risk
from detectors.keywords import scan_keywords
from detectors.urls import scan_urls
from detectors.sender import scan_sender


class TestPhishGuardExtractor(unittest.TestCase):
    """Tests for link extraction and normalization (extractor.py)."""

    def test_standard_url_extraction(self):
        text = "Check this out: https://secure-login.com/auth and http://unsafe.org"
        links = extract_links(text)
        self.assertEqual(len(links), 2)
        self.assertIn("https://secure-login.com/auth", links)
        self.assertIn("http://unsafe.org", links)

    def test_defanged_url_normalization(self):
        # Test cleaning of common obfuscated malware/phishing formats
        text = "Click here: hxxps[:]//badsite[.]com/login"
        links = extract_links(text)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0], "https://badsite.com/login")


class TestPhishGuardParser(unittest.TestCase):
    """Tests for raw email parsing into EmailMessage objects (parser.py)."""

    def test_parse_simple_email(self):
        raw_email = (
            "From: Security Team <security@bank.com>\n"
            "Subject: Account Action Required\n"
            "Content-Type: text/plain\n\n"
            "Your bank account has been compromised. "
            "Please go to http://bank-secure.com to verify."
        )
        email_obj = parse_email(raw_email)
        
        self.assertEqual(email_obj.sender, "Security Team <security@bank.com>")
        self.assertEqual(email_obj.subject, "Account Action Required")
        self.assertIn("compromised", email_obj.body)
        self.assertEqual(email_obj.links, ["http://bank-secure.com"])


class TestPhishGuardDetectors(unittest.TestCase):
    """Tests for keyword, URL, and sender detectors (detectors/*)."""

    def test_keyword_detector(self):
        email = EmailMessage(
            sender="test@test.com",
            subject="Urgent action required!",
            body="Click here immediately to verify your account locked status.",
            links=[],
            headers={}
        )
        indicators = scan_keywords(email)
        indicator_names = [ind.name for ind in indicators]
        
        # Verify specific keywords were detected
        self.assertIn("KEYWORD_URGENT", indicator_names)
        self.assertIn("KEYWORD_CLICK_HERE", indicator_names)
        self.assertIn("KEYWORD_VERIFY", indicator_names)

    def test_url_detector(self):
        email = EmailMessage(
            sender="test@test.com",
            subject="Test",
            body="Checking http://192.168.0.1/verify",
            links=["http://192.168.0.1/verify"],
            headers={}
        )
        indicators = scan_urls(email)
        indicator_names = [ind.name for ind in indicators]
        
        # Should flag both HTTP and IP host usage
        self.assertIn("HTTP_URL", indicator_names)
        self.assertIn("IP_URL", indicator_names)

    def test_sender_detector(self):
        email = EmailMessage(
            sender="Attacker <bad_guy@phish-site.xyz>",
            subject="Hello",
            body="Nothing here",
            links=[],
            headers={}
        )
        indicators = scan_sender(email)
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0].name, "SUSPICIOUS_TLD")


class TestPhishGuardScoring(unittest.TestCase):
    """Tests for risk level categorization based on score points (scoring.py)."""

    def test_scoring_thresholds(self):
        # 1. Low Risk (< 20 pts)
        low_risk_indicators = [Indicator("KEYWORD_URGENT", 5, "Urgent keyword")]
        result_low = calculate_risk(low_risk_indicators)
        self.assertEqual(result_low.level, RiskLevel.LOW)
        self.assertEqual(result_low.score, 5)

        # 2. Medium Risk (20 - 49 pts)
        med_risk_indicators = [
            Indicator("HTTP_URL", 10, "Non-HTTPS link"),
            Indicator("SUSPICIOUS_TLD", 10, "Suspicious TLD")
        ]
        result_med = calculate_risk(med_risk_indicators)
        self.assertEqual(result_med.level, RiskLevel.MEDIUM)
        self.assertEqual(result_med.score, 20)

        # 3. High Risk (>= 50 pts)
        high_risk_indicators = [
            Indicator("IP_URL", 15, "IP Address link"),
            Indicator("HTTP_URL", 10, "Non-HTTPS link"),
            Indicator("SUSPICIOUS_TLD", 10, "Suspicious TLD"),
            Indicator("KEYWORD_URGENT", 5, "Urgent keyword"),
            Indicator("KEYWORD_CLICK_HERE", 5, "Click here keyword"),
            Indicator("KEYWORD_ACCOUNT_LOCKED", 5, "Account locked keyword"),
            Indicator("KEYWORD_VERIFY", 5, "Verify keyword"),
        ]
        result_high = calculate_risk(high_risk_indicators)
        self.assertEqual(result_high.level, RiskLevel.HIGH)
        self.assertEqual(result_high.score, 55)


if __name__ == "__main__":
    unittest.main()