from app.detectors.rule_detector import RuleDetector
from app.detectors.anomaly_detector import AnomalyDetector
from typing import Dict, List

class DetectorManager:
    def __init__(self):
        self.detectors = [
            RuleDetector(),
            AnomalyDetector()
        ]
    
    def detect(self, data: Dict) -> List[Dict]:
        """Run all detectors on the data"""
        all_detections = []
        
        for detector in self.detectors:
            detections = detector.detect(data)
            all_detections.extend(detections)
        
        return all_detections
    
    def add_detector(self, detector):
        """Add a custom detector"""
        self.detectors.append(detector)
    
    def remove_detector(self, detector):
        """Remove a detector"""
        if detector in self.detectors:
            self.detectors.remove(detector)
