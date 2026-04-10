import threading
from app.collectors.network_collector import NetworkCollector
from app.collectors.log_collector import LogCollector

class CollectorManager:
    def __init__(self):
        self.collectors = []
        self.running = False
        self.callback = None
    
    def start(self, callback=None):
        self.running = True
        self.callback = callback
        
        # Initialize and start collectors
        network_collector = NetworkCollector()
        log_collector = LogCollector(log_type='generic')  # Using generic for demonstration
        
        self.collectors.extend([network_collector, log_collector])
        
        for collector in self.collectors:
            collector.start(callback=self._collector_callback)
        
        print("Collector manager started")
    
    def stop(self):
        self.running = False
        for collector in self.collectors:
            collector.stop()
        print("Collector manager stopped")
    
    def _collector_callback(self, data):
        """Callback function for collectors to send data"""
        if self.callback and self.running:
            self.callback(data)
    
    def add_collector(self, collector):
        """Add a custom collector to the manager"""
        self.collectors.append(collector)
        if self.running:
            collector.start(callback=self._collector_callback)
    
    def remove_collector(self, collector):
        """Remove a collector from the manager"""
        if collector in self.collectors:
            collector.stop()
            self.collectors.remove(collector)
