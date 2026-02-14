import time
import string
from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class SessionState:
    """Tracks entity-to-pseudonym mappings within a conversation session."""

    entity_map: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)
    last_accessed: float = field(default_factory=time.time)

    # Alphabet for pseudonym suffixes: A, B, C, ...
    ALPHABET = list(string.ascii_uppercase)

    def _next_label(self, entity_type: str) -> str:
        """Generate the next pseudonym label for a given entity type.

        Returns labels like PERSON_A, PERSON_B, ..., PERSON_Z, PERSON_AA, etc.
        """
        count = self.counters.get(entity_type, 0)
        self.counters[entity_type] = count + 1

        if count < 26:
            suffix = self.ALPHABET[count]
        else:
            # For > 26 entities of same type: AA, AB, etc.
            first = self.ALPHABET[(count // 26) - 1]
            second = self.ALPHABET[count % 26]
            suffix = f"{first}{second}"

        return suffix

    def get_pseudonym(self, entity_type: str, original_text: str) -> str:
        """Get or create a consistent pseudonym for an entity.

        Same original text within a session always gets the same pseudonym.
        """
        self.last_accessed = time.time()

        # Normalize lookup key
        key = f"{entity_type}::{original_text}"

        if key in self.entity_map:
            return self.entity_map[key]

        suffix = self._next_label(entity_type)
        pseudonym = self._format_pseudonym(entity_type, suffix)
        self.entity_map[key] = pseudonym
        return pseudonym

    def _format_pseudonym(self, entity_type: str, suffix: str) -> str:
        """Format pseudonym based on entity type per SPEC rules."""
        pseudonym_formats = {
            "PERSON": f"PERSON_{suffix}",
            "EMAIL_ADDRESS": f"email_PERSON_{suffix}@domain",
            "PHONE_NUMBER": f"PHONE_{suffix}",
            "US_SSN": f"SSN_{suffix}",
            "CREDIT_CARD": f"CARD_{suffix}",
            "API_KEY": f"API_KEY_{suffix}",
            "AWS_KEY": f"AWS_KEY_{suffix}",
            "GITHUB_TOKEN": f"GITHUB_TOKEN_{suffix}",
            "LOCATION": f"LOCATION_{suffix}",
            "DATE_TIME": f"DATE_{suffix}",
            "IBAN_CODE": f"IBAN_{suffix}",
            "IP_ADDRESS": f"IP_{suffix}",
            "US_DRIVER_LICENSE": f"LICENSE_{suffix}",
            "US_PASSPORT": f"PASSPORT_{suffix}",
            "NRP": f"NRP_{suffix}",
        }
        return pseudonym_formats.get(entity_type, f"{entity_type}_{suffix}")


class SessionManager:
    """Manages conversation sessions for consistent entity pseudonymization.

    Sessions expire after 1 hour of inactivity.
    """

    SESSION_TTL_SECONDS = 3600  # 1 hour

    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

    def get_or_create(self, session_id: str) -> SessionState:
        """Get an existing session or create a new one."""
        self._cleanup_expired()

        if session_id in self._sessions:
            session = self._sessions[session_id]
            session.last_accessed = time.time()
            return session

        session = SessionState()
        self._sessions[session_id] = session
        return session

    def _cleanup_expired(self):
        """Remove sessions that haven't been accessed in TTL seconds."""
        now = time.time()
        expired = [
            sid
            for sid, state in self._sessions.items()
            if now - state.last_accessed > self.SESSION_TTL_SECONDS
        ]
        for sid in expired:
            del self._sessions[sid]

    def get_mapping(self, session_id: str) -> Dict[str, str]:
        """Get the current entity mapping for a session."""
        if session_id in self._sessions:
            return dict(self._sessions[session_id].entity_map)
        return {}


# Global singleton
session_manager = SessionManager()
