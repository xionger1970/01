from fastapi import APIRouter, HTTPException, Query
from typing import Dict, List, Optional
from app.reporting.report_generator import report_generator

router = APIRouter()

@router.post("/generate-report", response_model=Dict)
def generate_report(
    report_type: str = Query(..., description="报告类型: daily, weekly, monthly, incident"),
    parameters: Optional[Dict] = None
):
    """生成报告"""
    if report_type not in report_generator.get_report_templates():
        raise HTTPException(status_code=400, detail="无效的报告类型")
    
    report = report_generator.generate_report(report_type, parameters)
    return report

@router.get("/reports", response_model=List[Dict])
def get_reports(
    report_type: Optional[str] = Query(None, description="报告类型"),
    status: Optional[str] = Query(None, description="报告状态")
):
    """获取报告列表"""
    filters = {}
    if report_type:
        filters["type"] = report_type
    if status:
        filters["status"] = status
    
    return report_generator.get_reports(filters)

@router.get("/reports/{report_id}", response_model=Dict)
def get_report(report_id: int):
    """获取单个报告"""
    report = report_generator.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    return report

@router.get("/reports/{report_id}/status", response_model=Dict)
def get_report_status(report_id: int):
    """获取报告状态"""
    status = report_generator.get_report_status(report_id)
    if status is None:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"status": status}

@router.get("/report-templates", response_model=Dict)
def get_report_templates():
    """获取报告模板"""
    return report_generator.get_report_templates()

@router.delete("/reports/{report_id}", response_model=Dict)
def delete_report(report_id: int):
    """删除报告"""
    success = report_generator.delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"success": True}
