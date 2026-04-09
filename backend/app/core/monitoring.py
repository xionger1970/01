import os
import psutil
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MonitoringManager:
    def __init__(self):
        self.metrics_history = {}
        self.health_checks = []
        self.alert_thresholds = {
            'cpu_usage': 80,  # percentage
            'memory_usage': 85,  # percentage
            'disk_usage': 90,  # percentage
            'response_time': 2.0,  # seconds
        }
    
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu': {
                'usage': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
                'freq': psutil.cpu_freq().current if psutil.cpu_freq() else 0
            },
            'memory': {
                'total': psutil.virtual_memory().total,
                'used': psutil.virtual_memory().used,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            },
            'network': {
                'sent': psutil.net_io_counters().bytes_sent,
                'received': psutil.net_io_counters().bytes_recv
            },
            'processes': {
                'count': len(psutil.pids()),
                'cpu_percent': psutil.Process().cpu_percent()
            }
        }
        
        # Store metrics in history
        self._store_metrics(metrics)
        
        # Check for alerts
        self._check_alert_thresholds(metrics)
        
        return metrics
    
    def _store_metrics(self, metrics: Dict[str, Any]) -> None:
        """Store metrics in history"""
        timestamp = metrics['timestamp']
        if 'system' not in self.metrics_history:
            self.metrics_history['system'] = []
        
        self.metrics_history['system'].append(metrics)
        
        # Keep only last 1000 metrics
        if len(self.metrics_history['system']) > 1000:
            self.metrics_history['system'] = self.metrics_history['system'][-1000:]
    
    def _check_alert_thresholds(self, metrics: Dict[str, Any]) -> None:
        """Check if metrics exceed alert thresholds"""
        alerts = []
        
        # Check CPU usage
        if metrics['cpu']['usage'] > self.alert_thresholds['cpu_usage']:
            alerts.append({
                'type': 'cpu_usage',
                'message': f'CPU usage {metrics["cpu"]["usage"]}% exceeds threshold {self.alert_thresholds["cpu_usage"]}%',
                'severity': 'warning'
            })
        
        # Check memory usage
        if metrics['memory']['percent'] > self.alert_thresholds['memory_usage']:
            alerts.append({
                'type': 'memory_usage',
                'message': f'Memory usage {metrics["memory"]["percent"]}% exceeds threshold {self.alert_thresholds["memory_usage"]}%',
                'severity': 'warning'
            })
        
        # Check disk usage
        if metrics['disk']['percent'] > self.alert_thresholds['disk_usage']:
            alerts.append({
                'type': 'disk_usage',
                'message': f'Disk usage {metrics["disk"]["percent"]}% exceeds threshold {self.alert_thresholds["disk_usage"]}%',
                'severity': 'critical'
            })
        
        # Log alerts
        for alert in alerts:
            logger.warning(f"ALERT: {alert['message']}")
    
    def check_system_health(self) -> Dict[str, Any]:
        """Check system health"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy',
            'checks': []
        }
        
        # Check CPU
        cpu_check = {
            'name': 'CPU',
            'status': 'healthy',
            'details': {
                'usage': psutil.cpu_percent(interval=0.1),
                'count': psutil.cpu_count()
            }
        }
        if cpu_check['details']['usage'] > 90:
            cpu_check['status'] = 'critical'
        elif cpu_check['details']['usage'] > 70:
            cpu_check['status'] = 'warning'
        health_status['checks'].append(cpu_check)
        
        # Check memory
        memory_check = {
            'name': 'Memory',
            'status': 'healthy',
            'details': {
                'percent': psutil.virtual_memory().percent,
                'available': psutil.virtual_memory().available
            }
        }
        if memory_check['details']['percent'] > 90:
            memory_check['status'] = 'critical'
        elif memory_check['details']['percent'] > 75:
            memory_check['status'] = 'warning'
        health_status['checks'].append(memory_check)
        
        # Check disk
        disk_check = {
            'name': 'Disk',
            'status': 'healthy',
            'details': {
                'percent': psutil.disk_usage('/').percent,
                'free': psutil.disk_usage('/').free
            }
        }
        if disk_check['details']['percent'] > 95:
            disk_check['status'] = 'critical'
        elif disk_check['details']['percent'] > 85:
            disk_check['status'] = 'warning'
        health_status['checks'].append(disk_check)
        
        # Check processes
        process_check = {
            'name': 'Processes',
            'status': 'healthy',
            'details': {
                'count': len(psutil.pids())
            }
        }
        health_status['checks'].append(process_check)
        
        # Determine overall status
        for check in health_status['checks']:
            if check['status'] == 'critical':
                health_status['status'] = 'critical'
                break
            elif check['status'] == 'warning' and health_status['status'] != 'critical':
                health_status['status'] = 'warning'
        
        return health_status
    
    def get_metrics_history(self, metric_type: str = 'system', limit: int = 100) -> List[Dict[str, Any]]:
        """Get metrics history"""
        if metric_type not in self.metrics_history:
            return []
        
        return self.metrics_history[metric_type][-limit:]
    
    def log_system_event(self, event_type: str, message: str, severity: str = 'info') -> None:
        """Log system event"""
        log_message = f"[{event_type}] {message}"
        
        if severity == 'error':
            logger.error(log_message)
        elif severity == 'warning':
            logger.warning(log_message)
        elif severity == 'info':
            logger.info(log_message)
        elif severity == 'debug':
            logger.debug(log_message)
    
    def get_logs(self, limit: int = 100) -> List[str]:
        """Get recent logs"""
        logs = []
        try:
            with open('app.log', 'r') as f:
                lines = f.readlines()
                logs = lines[-limit:]
        except FileNotFoundError:
            pass
        
        return logs

# Create singleton instance
monitoring_manager = MonitoringManager()

# Type hint for Any
from typing import Any