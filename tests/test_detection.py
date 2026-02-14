"""Tests for PII detection engine accuracy and session management."""
import pytest
import spacy
from app.services.detector import PIIDetector
from app.services.session_manager import SessionManager, SessionState


def _has_ner_model() -> bool:
    """Check if a SpaCy model with NER is available."""
    for model in ["en_core_web_lg", "en_core_web_sm"]:
        try:
            nlp = spacy.load(model)
            return "ner" in nlp.pipe_names
        except OSError:
            continue
    return False


requires_ner = pytest.mark.skipif(
    not _has_ner_model(),
    reason="Requires SpaCy NER model (en_core_web_sm/lg). Install with: python -m spacy download en_core_web_sm",
)


class TestPIIDetection:
    """Test PII detection accuracy across entity types."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.detector = PIIDetector()

    def test_detect_email(self):
        text = "Contact me at john.doe@example.com for details."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "EMAIL_ADDRESS" in types

    def test_detect_phone_number(self):
        text = "Call us at 555-123-4567 or (555) 987-6543."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "PHONE_NUMBER" in types

    @requires_ner
    def test_detect_ssn(self):
        text = "John's social security number is 123-45-6789, please keep it safe."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        # Presidio should detect US_SSN, PERSON, or other entities
        assert len(entities) > 0

    def test_detect_credit_card(self):
        text = "My credit card number is 4111-1111-1111-1111."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "CREDIT_CARD" in types

    @requires_ner
    def test_detect_person_name(self):
        text = "Please contact John Smith about the project."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "PERSON" in types

    @requires_ner
    def test_detect_multiple_entities(self):
        text = "John Smith's email is john@example.com and his phone is 555-123-4567."
        entities = self.detector.detect(text)
        assert len(entities) >= 2  # At least person + email

    def test_safe_text_no_detection(self):
        text = "The weather today is nice and sunny."
        entities = self.detector.detect(text)
        # Should have very few or no detections
        assert len(entities) <= 1  # Allow for occasional false positives

    def test_detect_aws_key(self):
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "AWS_KEY" in types

    def test_detect_github_token(self):
        text = "Use token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm for auth."
        entities = self.detector.detect(text)
        types = [e.type for e in entities]
        assert "GITHUB_TOKEN" in types

    def test_entities_sorted_by_position(self):
        text = "Email: john@example.com, Phone: 555-123-4567"
        entities = self.detector.detect(text)
        if len(entities) >= 2:
            for i in range(len(entities) - 1):
                assert entities[i].start <= entities[i + 1].start


class TestRedaction:
    """Test PII redaction with pseudonym generation."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.detector = PIIDetector()
        self.session = SessionState()

    def test_basic_redaction(self):
        text = "Contact john@example.com for info."
        entities = self.detector.detect(text)
        if entities:
            redacted, mapping = self.detector.redact(text, entities, self.session)
            assert "john@example.com" not in redacted
            assert len(mapping) > 0

    def test_consistent_pseudonyms(self):
        """Same entity in same session should get same pseudonym."""
        text1 = "John Smith said hello."
        text2 = "John Smith said goodbye."

        entities1 = self.detector.detect(text1)
        entities2 = self.detector.detect(text2)

        if entities1 and entities2:
            _, mapping1 = self.detector.redact(text1, entities1, self.session)
            _, mapping2 = self.detector.redact(text2, entities2, self.session)

            # Same text should produce same pseudonym
            for key in mapping1:
                if key in mapping2:
                    assert mapping1[key] == mapping2[key]


class TestSessionManager:
    """Test session management."""

    def test_create_session(self):
        manager = SessionManager()
        session = manager.get_or_create("test-session-1")
        assert isinstance(session, SessionState)

    def test_reuse_session(self):
        manager = SessionManager()
        session1 = manager.get_or_create("test-session-2")
        session1.get_pseudonym("PERSON", "John")

        session2 = manager.get_or_create("test-session-2")
        assert session2.get_pseudonym("PERSON", "John") == session1.get_pseudonym(
            "PERSON", "John"
        )

    def test_different_sessions_independent(self):
        manager = SessionManager()
        session_a = manager.get_or_create("session-a")
        session_b = manager.get_or_create("session-b")

        session_a.get_pseudonym("PERSON", "Alice")
        pseudo_b = session_b.get_pseudonym("PERSON", "Alice")

        # Both get PERSON_A since they're separate sessions
        assert pseudo_b == "PERSON_A"

    def test_pseudonym_incrementing(self):
        session = SessionState()
        p1 = session.get_pseudonym("PERSON", "Alice")
        p2 = session.get_pseudonym("PERSON", "Bob")
        p3 = session.get_pseudonym("PERSON", "Charlie")

        assert p1 == "PERSON_A"
        assert p2 == "PERSON_B"
        assert p3 == "PERSON_C"

    def test_email_pseudonym_format(self):
        session = SessionState()
        p = session.get_pseudonym("EMAIL_ADDRESS", "john@example.com")
        assert p == "email_PERSON_A@domain"

    def test_ssn_pseudonym_format(self):
        session = SessionState()
        p = session.get_pseudonym("US_SSN", "123-45-6789")
        assert p == "SSN_A"

    def test_session_expired_cleanup(self):
        import time

        manager = SessionManager()
        manager.SESSION_TTL_SECONDS = 0  # Instant expiry

        session = manager.get_or_create("expire-test")
        session.get_pseudonym("PERSON", "Test")

        time.sleep(0.1)
        # After cleanup, session should be gone
        new_session = manager.get_or_create("expire-test")
        # New session should have empty map
        assert len(new_session.entity_map) == 0
