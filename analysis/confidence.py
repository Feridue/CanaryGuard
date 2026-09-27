"""
Confidence Engine — Phase 6
Maps Correlator raw scores to Low/Medium/High confidence levels.
"""

from typing import List, Dict, Any
from evidence.logger import EvidenceLogger


class ConfidenceEngine:
    def __init__(self, logger: EvidenceLogger):
        self.logger = logger
        self.thresholds = self.logger.confidence_thresholds

    def evaluate(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Takes a list of candidates from the Correlator and maps their
        raw scores into confidence buckets and explanation strings.
        Modifies the list in-place and returns it.
        """
        for candidate in candidates:
            score = candidate.get("score", 0.0)
            
            # Map score to Low/Medium/High
            if score >= self.thresholds.get("high", 80):
                confidence = "High"
            elif score >= self.thresholds.get("medium", 50):
                confidence = "Medium"
            else:
                # Even if it's below 'low', if it's in the candidates list,
                # the correlator gave it *some* score, so it's at least 'Low'.
                confidence = "Low"
                
            candidate["confidence"] = confidence
            
            # Join evidence into human readable explanation
            evidence_list = candidate.get("evidence", [])
            if evidence_list:
                explanation = "Candidate flagged due to: " + ", ".join(evidence_list)
            else:
                explanation = "Candidate flagged due to unknown anomalies."
                
            candidate["explanation"] = explanation
            
        return candidates
