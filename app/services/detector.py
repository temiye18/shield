import re
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

from presidio_analyzer import AnalyzerEngine, RecognizerResult, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from app.services.session_manager import SessionState

logger = logging.getLogger(__name__)


@dataclass
class DetectedEntity:
    """A single detected PII entity."""
    type: str
    text: str
    start: int
    end: int
    confidence: float


def _create_analyzer() -> AnalyzerEngine:
    """Create Presidio AnalyzerEngine with graceful SpaCy model fallback.

    Tries: en_core_web_lg → en_core_web_sm → blank spacy model.
    """
    import spacy

    for model_name in ["en_core_web_lg", "en_core_web_sm"]:
        try:
            spacy.load(model_name)
            logger.info(f"Using SpaCy model: {model_name}")
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model_name}],
            })
            return AnalyzerEngine(nlp_engine=provider.create_engine())
        except OSError:
            logger.warning(f"SpaCy model '{model_name}' not found, trying next...")

    # Last resort: blank model (regex-only detection, no NER for person names)
    logger.warning(
        "No SpaCy NER model installed. Using blank model — "
        "person name detection will be limited. "
        "Install a model with: python -m spacy download en_core_web_sm"
    )
    nlp = spacy.blank("en")
    nlp.add_pipe("sentencizer")

    from presidio_analyzer.nlp_engine import SpacyNlpEngine
    nlp_engine = SpacyNlpEngine()
    nlp_engine.nlp = {"en": nlp}
    return AnalyzerEngine(nlp_engine=nlp_engine)


class PIIDetector:
    """PII detection engine wrapping Microsoft Presidio with custom regex patterns.

    Detects 15+ entity types including emails, SSNs, credit cards,
    phone numbers, person names, API keys, AWS keys, and GitHub tokens.
    """

    def __init__(self):
        self._analyzer = _create_analyzer()
        self._register_custom_recognizers()

    def _register_custom_recognizers(self):
        """Register custom regex-based recognizers for API keys, AWS keys, etc."""

        # API Key patterns (generic long hex/base64 strings)
        api_key_pattern = Pattern(
            name="api_key_pattern",
            regex=r"(?:api[_-]?key|apikey|api[_-]?secret)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})[\"']?",
            score=0.85,
        )
        api_key_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            patterns=[api_key_pattern],
            supported_language="en",
        )
        self._analyzer.registry.add_recognizer(api_key_recognizer)

        # AWS Access Key pattern
        aws_key_pattern = Pattern(
            name="aws_access_key",
            regex=r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            score=0.95,
        )
        aws_secret_pattern = Pattern(
            name="aws_secret_key",
            regex=r"(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
            score=0.90,
        )
        aws_recognizer = PatternRecognizer(
            supported_entity="AWS_KEY",
            patterns=[aws_key_pattern, aws_secret_pattern],
            supported_language="en",
        )
        self._analyzer.registry.add_recognizer(aws_recognizer)

        # GitHub Token pattern
        github_token_pattern = Pattern(
            name="github_token",
            regex=r"gh[pousr]_[A-Za-z0-9_]{36,}",
            score=0.95,
        )
        github_recognizer = PatternRecognizer(
            supported_entity="GITHUB_TOKEN",
            patterns=[github_token_pattern],
            supported_language="en",
        )
        self._analyzer.registry.add_recognizer(github_recognizer)

        # Generic Bearer / Secret Token pattern
        bearer_pattern = Pattern(
            name="bearer_token",
            regex=r"(?:bearer|token|secret|password)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{20,})[\"']?",
            score=0.70,
        )
        bearer_recognizer = PatternRecognizer(
            supported_entity="API_KEY",
            name="BearerTokenRecognizer",
            patterns=[bearer_pattern],
            supported_language="en",
        )
        self._analyzer.registry.add_recognizer(bearer_recognizer)

    def detect(
        self,
        text: str,
        language: str = "en",
        org_patterns: Optional[List[Dict]] = None,
    ) -> List[DetectedEntity]:
        """Detect PII entities in the given text.

        Args:
            text: The text to scan for PII.
            language: Language code (default: "en").
            org_patterns: Optional list of org-specific patterns from DB.

        Returns:
            List of detected entities sorted by start position.
        """
        # Run Presidio analyzer
        presidio_results = self._analyzer.analyze(
            text=text,
            language=language,
            entities=None,  # Detect all supported entities
        )

        # Run organization-specific patterns if provided
        custom_results = []
        if org_patterns:
            custom_results = self._run_org_patterns(text, org_patterns)

        # Combine results
        all_results = list(presidio_results) + custom_results

        # Deduplicate overlapping entities (keep higher confidence)
        deduped = self._deduplicate(all_results, text)

        # Convert to DetectedEntity objects and sort by start position
        entities = [
            DetectedEntity(
                type=r.entity_type,
                text=text[r.start : r.end],
                start=r.start,
                end=r.end,
                confidence=round(r.score, 2),
            )
            for r in deduped
        ]
        entities.sort(key=lambda e: e.start)
        return entities

    def _run_org_patterns(
        self, text: str, patterns: List[Dict]
    ) -> List[RecognizerResult]:
        """Run organization-specific custom patterns against the text."""
        results = []
        for pattern_config in patterns:
            if pattern_config.get("pattern_type") == "regex":
                try:
                    regex = pattern_config["pattern_value"]
                    entity_type = pattern_config.get("entity_type", "CUSTOM")
                    for match in re.finditer(regex, text):
                        results.append(
                            RecognizerResult(
                                entity_type=entity_type,
                                start=match.start(),
                                end=match.end(),
                                score=0.80,
                            )
                        )
                except re.error:
                    continue
            elif pattern_config.get("pattern_type") == "keyword":
                keywords = [
                    kw.strip()
                    for kw in pattern_config["pattern_value"].split(",")
                ]
                entity_type = pattern_config.get("entity_type", "KEYWORD")
                for keyword in keywords:
                    start = 0
                    lower_text = text.lower()
                    lower_kw = keyword.lower()
                    while True:
                        idx = lower_text.find(lower_kw, start)
                        if idx == -1:
                            break
                        results.append(
                            RecognizerResult(
                                entity_type=entity_type,
                                start=idx,
                                end=idx + len(keyword),
                                score=0.75,
                            )
                        )
                        start = idx + 1
        return results

    def _deduplicate(
        self, results: List[RecognizerResult], text: str
    ) -> List[RecognizerResult]:
        """Remove overlapping entity results, keeping the one with higher confidence."""
        if not results:
            return []

        # Sort by start position, then by score descending
        sorted_results = sorted(results, key=lambda r: (r.start, -r.score))

        deduped = [sorted_results[0]]
        for current in sorted_results[1:]:
            last = deduped[-1]
            # Check for overlap
            if current.start < last.end:
                # Keep the one with higher score
                if current.score > last.score:
                    deduped[-1] = current
            else:
                deduped.append(current)

        return deduped

    def redact(
        self,
        text: str,
        entities: List[DetectedEntity],
        session: SessionState,
    ) -> Tuple[str, Dict[str, str]]:
        """Replace detected entities with pseudonyms using session state.

        Replaces in reverse order to preserve character positions.
        Returns (redacted_text, mapping).
        """
        mapping: Dict[str, str] = {}
        redacted = text

        # Process in reverse order to preserve positions
        for entity in sorted(entities, key=lambda e: e.start, reverse=True):
            pseudonym = session.get_pseudonym(entity.type, entity.text)
            mapping[entity.text] = pseudonym
            redacted = redacted[: entity.start] + pseudonym + redacted[entity.end :]

        return redacted, mapping


# Global singleton
pii_detector = PIIDetector()
