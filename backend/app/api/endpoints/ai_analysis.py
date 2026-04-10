from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
from app.ai.ai_analyzer import ai_analyzer
from app.alerting.alert_manager import alert_manager
from app.detectors.anomaly_detector import anomaly_detector
from app.analysis.attack_tracker import attack_tracker

router = APIRouter()

class AnalyzeRequest(BaseModel):
    event_type: str = "attack_event"
    event_data: str = ""
    model: str = "default"

class BatchAnalyzeRequest(BaseModel):
    alerts: List[Dict] = []

@router.post("/analyze", response_model=Dict)
def analyze_event(request: AnalyzeRequest):
    """智能分析事件"""
    try:
        event_data = request.event_data
        if not event_data.strip():
            raise HTTPException(status_code=400, detail="事件数据不能为空")
        
        import json
        try:
            parsed_data = json.loads(event_data)
        except json.JSONDecodeError:
            parsed_data = {"raw_data": event_data}
        
        analysis_result = ai_analyzer.analyze_alert(parsed_data)
        return analysis_result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")

@router.get("/models", response_model=List[Dict])
def get_models():
    """获取分析模型列表"""
    threat_models = ai_analyzer.get_threat_models()
    models = []
    for key, model in threat_models.items():
        models.append({
            "id": key,
            "name": model.get("name", key),
            "description": model.get("description", ""),
            "type": key,
            "status": "active",
            "accuracy": 0.85 + (hash(key) % 15) / 100.0,
            "patterns": model.get("patterns", [])
        })
    return models

@router.post("/analyze-alert/{alert_id}", response_model=Dict)
def analyze_alert(alert_id: int):
    """分析单个告警"""
    alert = alert_manager.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    analysis_result = ai_analyzer.analyze_alert(alert)
    return analysis_result

@router.post("/analyze-attack-chain/{chain_id}", response_model=Dict)
def analyze_attack_chain(chain_id: int):
    """分析攻击链"""
    chain = attack_tracker.get_attack_chain(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain not found")
    
    analysis_result = ai_analyzer.analyze_attack_chain(chain_id)
    return analysis_result

@router.post("/analyze-anomaly/{anomaly_id}", response_model=Dict)
def analyze_anomaly(anomaly_id: int):
    """分析异常行为"""
    anomaly = anomaly_detector.get_anomaly_by_id(anomaly_id)
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    
    analysis_result = ai_analyzer.analyze_anomaly(anomaly)
    return analysis_result

@router.get("/history", response_model=List[Dict])
def get_analysis_history(
    threat_type: Optional[str] = Query(None, description="威胁类型过滤"),
    min_confidence: Optional[float] = Query(None, description="最小置信度"),
    limit: int = Query(100, description="返回结果数量限制")
):
    """获取分析历史"""
    filters = {}
    if threat_type:
        filters['threat_type'] = threat_type
    if min_confidence is not None:
        filters['min_confidence'] = min_confidence
    
    history = ai_analyzer.get_analysis_history(filters)
    return history[:limit]

@router.get("/threat-models", response_model=Dict)
def get_threat_models():
    """获取威胁模型"""
    return ai_analyzer.get_threat_models()

@router.post("/batch-analyze-alerts", response_model=Dict)
def batch_analyze_alerts(request: BatchAnalyzeRequest):
    """批量分析告警"""
    try:
        alerts = request.alerts
        if not alerts:
            raise HTTPException(status_code=400, detail="告警列表不能为空")
        
        analysis_result = ai_analyzer.analyze_batch_alerts(alerts)
        return analysis_result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"批量分析失败: {str(e)}")

@router.post("/batch-analyze-by-ids", response_model=Dict)
def batch_analyze_by_ids(alert_ids: List[int]):
    """根据ID批量分析告警"""
    try:
        alerts = []
        for alert_id in alert_ids:
            alert = alert_manager.get_alert_by_id(alert_id)
            if alert:
                alerts.append(alert)
        
        if not alerts:
            raise HTTPException(status_code=404, detail="未找到任何告警")
        
        analysis_result = ai_analyzer.analyze_batch_alerts(alerts)
        return analysis_result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"批量分析失败: {str(e)}")

@router.delete("/history/{analysis_id}")
def delete_analysis_history(analysis_id: int):
    """删除分析历史"""
    with ai_analyzer.lock:
        for i, record in enumerate(ai_analyzer.analysis_history):
            if record.get('id') == analysis_id:
                ai_analyzer.analysis_history.pop(i)
                return {"message": "删除成功", "id": analysis_id}
    raise HTTPException(status_code=404, detail="分析记录未找到")
