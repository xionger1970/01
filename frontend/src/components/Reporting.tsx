import React, { useState, useEffect } from 'react';
import { reportingService } from '../services/api';

interface ReportParameters {
  [key: string]: any;
}

interface ReportContent {
  title: string;
  generated_at: string;
  time_range?: {
    start: string;
    end: string;
  };
  sections: {
    [key: string]: any;
  };
}

interface Report {
  id: number;
  type: string;
  name: string;
  status: string;
  created_at: string;
  updated_at: string;
  parameters?: ReportParameters;
  content?: ReportContent;
}

interface ReportTemplate {
  name: string;
  description: string;
  sections: string[];
}

interface ReportTemplates {
  [key: string]: ReportTemplate;
}

const Reporting: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [templates, setTemplates] = useState<ReportTemplates>({});
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [reportType, setReportType] = useState<string>('daily');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);

  useEffect(() => {
    loadReportTemplates();
    loadReports();

    // 每30秒刷新一次报告列表
    const interval = setInterval(() => {
      loadReports();
    }, 30000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const loadReportTemplates = async () => {
    try {
      const data = await reportingService.getReportTemplates();
      setTemplates(data);
    } catch (error) {
      console.error('加载报告模板失败:', error);
    }
  };

  const loadReports = async () => {
    try {
      const data = await reportingService.getReports();
      setReports(data);
    } catch (error) {
      console.error('加载报告失败:', error);
    }
  };

  const generateReport = async () => {
    setIsGenerating(true);
    try {
      await reportingService.generateReport(reportType);
      // 生成后刷新报告列表
      setTimeout(loadReports, 1000);
    } catch (error) {
      console.error('生成报告失败:', error);
    } finally {
      setIsGenerating(false);
    }
  };

  const viewReport = async (report: Report) => {
    try {
      const data = await reportingService.getReport(report.id);
      setSelectedReport(data);
    } catch (error) {
      console.error('获取报告详情失败:', error);
    }
  };

  const deleteReport = async (reportId: number) => {
    try {
      await reportingService.deleteReport(reportId);
      loadReports();
      if (selectedReport && selectedReport.id === reportId) {
        setSelectedReport(null);
      }
    } catch (error) {
      console.error('删除报告失败:', error);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-3xl font-bold mb-6 text-gray-900">安全报告管理</h1>

        {/* 报告生成部分 */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">生成报告</h2>
          <div className="flex items-center space-x-4">
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {Object.entries(templates).map(([key, template]) => (
                <option key={key} value={key}>
                  {template.name}
                </option>
              ))}
            </select>
            <button
              onClick={generateReport}
              disabled={isGenerating}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {isGenerating ? '生成中...' : '生成报告'}
            </button>
          </div>
          {templates[reportType] && (
            <div className="mt-4 text-sm text-gray-600">
              <p>{templates[reportType].description}</p>
              <p className="mt-1">
                包含章节: {templates[reportType].sections.join(', ')}
              </p>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* 报告列表 */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-800">报告列表</h2>
              <div className="space-y-4">
                {reports.length === 0 ? (
                  <p className="text-gray-500">暂无报告</p>
                ) : (
                  reports.map((report) => (
                    <div
                      key={report.id}
                      className={`border rounded-lg p-4 cursor-pointer transition-colors ${selectedReport?.id === report.id ? 'bg-blue-50 border-blue-300' : 'border-gray-200 hover:bg-gray-50'}`}
                      onClick={() => viewReport(report)}
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <h3 className="font-medium text-gray-900">{report.name}</h3>
                          <p className="text-sm text-gray-500">生成时间: {formatDate(report.created_at)}</p>
                        </div>
                        <span
                          className={`text-xs font-medium px-2 py-1 rounded-full ${report.status === 'completed' ? 'bg-green-100 text-green-800' : report.status === 'generating' ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'}`}
                        >
                          {report.status === 'completed' ? '已完成' : report.status === 'generating' ? '生成中' : '失败'}
                        </span>
                      </div>
                      <div className="mt-2 flex justify-end">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteReport(report.id);
                          }}
                          className="text-red-600 hover:text-red-800 text-sm"
                        >
                          删除
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 报告详情 */}
          <div className="lg:col-span-2">
            <div className="bg-white rounded-lg shadow-md p-6">
              <h2 className="text-xl font-semibold mb-4 text-gray-800">报告详情</h2>
              {selectedReport ? (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-lg font-medium text-gray-900">{selectedReport.name}</h3>
                    <p className="text-sm text-gray-500">生成时间: {formatDate(selectedReport.created_at)}</p>
                    <p className="text-sm text-gray-500">更新时间: {formatDate(selectedReport.updated_at)}</p>
                  </div>
                  
                  {selectedReport.status === 'completed' && selectedReport.content ? (
                    <div className="space-y-4">
                      {Object.entries(selectedReport.content.sections).map(([sectionKey, sectionContent]) => (
                        <div key={sectionKey} className="border-t pt-4">
                          <h4 className="text-md font-medium text-gray-800 mb-2">
                            {sectionKey === 'summary' && '摘要'}
                            {sectionKey === 'attack_stats' && '攻击统计'}
                            {sectionKey === 'anomalies' && '异常检测'}
                            {sectionKey === 'threat_intel' && '威胁情报'}
                            {sectionKey === 'cloud_security' && '云安全'}
                            {sectionKey === 'container_security' && '容器安全'}
                            {sectionKey === 'recommendations' && '安全建议'}
                            {sectionKey === 'incident_summary' && '事件摘要'}
                            {sectionKey === 'timeline' && '时间线'}
                            {sectionKey === 'impact' && '影响'}
                            {sectionKey === 'response_actions' && '响应动作'}
                            {sectionKey === 'lessons_learned' && '经验教训'}
                          </h4>
                          <div className="text-sm text-gray-600">
                            {typeof sectionContent === 'object' && sectionContent !== null ? (
                              <pre className="whitespace-pre-wrap bg-gray-50 p-3 rounded-md overflow-x-auto">
                                {JSON.stringify(sectionContent, null, 2)}
                              </pre>
                            ) : (
                              <p>{sectionContent}</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : selectedReport.status === 'generating' ? (
                    <div className="flex items-center justify-center py-12">
                      <div className="text-center">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                        <p className="mt-4 text-gray-600">报告生成中，请稍候...</p>
                      </div>
                    </div>
                  ) : selectedReport.status === 'failed' ? (
                    <div className="bg-red-50 border border-red-200 rounded-md p-4">
                      <p className="text-red-600">报告生成失败: {selectedReport.error}</p>
                    </div>
                  ) : (
                    <p className="text-gray-500">选择一个报告查看详情</p>
                  )}
                </div>
              ) : (
                <div className="flex items-center justify-center h-64 border border-dashed border-gray-300 rounded-md">
                  <p className="text-gray-500">选择一个报告查看详情</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Reporting;