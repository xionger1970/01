from fastapi import APIRouter, Query
from typing import Optional
from app.core.performance_monitor import performance_monitor

router = APIRouter()

@router.get("/metrics")
def get_metrics(
    metric_type: Optional[str] = Query(None, description="指标类型: cpu, memory, disk, network, response_times, request_counts"),
    limit: int = Query(100, description="返回数据的数量限制")
):
    """获取性能指标"""
    metrics = performance_monitor.get_metrics(metric_type, limit)
    return metrics

@router.get("/summary")
def get_performance_summary():
    """获取性能摘要"""
    summary = performance_monitor.get_summary()
    return summary

@router.post("/start-monitoring")
def start_monitoring(interval: int = Query(5, description="监控间隔（秒）")):
    """开始性能监控"""
    performance_monitor.start_monitoring(interval)
    return {"message": "性能监控已启动"}

@router.post("/stop-monitoring")
def stop_monitoring():
    """停止性能监控"""
    performance_monitor.stop_monitoring()
    return {"message": "性能监控已停止"}
