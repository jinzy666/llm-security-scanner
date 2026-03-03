from typing import List, Dict, Any
import json

class ResultAnalyzer:
    def __init__(self):
        self.vulnerability_severity = {
            "prompt_injection": "high",
            "function_call_escalation": "high",
            "data_leakage": "high",
            "overfitting": "medium",
            "privilege_escalation": "high",
            "insecure_output": "medium",
            "model_poisoning": "high",
            "denial_of_service": "medium",
            "information_disclosure": "high",
            "unauthorized_access": "high"
        }
    
    def analyze(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """分析扫描结果"""
        # 统计漏洞
        vulnerability_stats = self._count_vulnerabilities(scan_results)
        
        # 计算风险等级
        risk_level = self._calculate_risk_level(vulnerability_stats)
        
        # 生成修复建议
        recommendations = self._generate_recommendations(vulnerability_stats)
        
        # 生成报告摘要
        summary = self._generate_summary(scan_results, vulnerability_stats, risk_level)
        
        return {
            "vulnerability_stats": vulnerability_stats,
            "risk_level": risk_level,
            "recommendations": recommendations,
            "summary": summary,
            "total_tests": len(scan_results),
            "vulnerable_tests": sum(1 for r in scan_results if r["is_vulnerable"]),
            "detection_rate": round(sum(1 for r in scan_results if r["is_vulnerable"]) / len(scan_results) * 100, 2) if scan_results else 0
        }
    
    def _count_vulnerabilities(self, scan_results: List[Dict[str, Any]]) -> Dict[str, int]:
        """统计漏洞类型和数量"""
        stats = {}
        for result in scan_results:
            if result["is_vulnerable"]:
                vuln_type = result["vulnerability_type"]
                stats[vuln_type] = stats.get(vuln_type, 0) + 1
        return stats
    
    def _calculate_risk_level(self, vulnerability_stats: Dict[str, int]) -> str:
        """计算整体风险等级"""
        high_severity_count = 0
        medium_severity_count = 0
        
        for vuln_type, count in vulnerability_stats.items():
            severity = self.vulnerability_severity.get(vuln_type, "medium")
            if severity == "high":
                high_severity_count += count
            elif severity == "medium":
                medium_severity_count += count
        
        if high_severity_count >= 3:
            return "高风险"
        elif high_severity_count >= 1 or medium_severity_count >= 3:
            return "中风险"
        else:
            return "低风险"
    
    def _generate_recommendations(self, vulnerability_stats: Dict[str, int]) -> List[Dict[str, Any]]:
        """生成修复建议"""
        recommendations = []
        
        if "prompt_injection" in vulnerability_stats:
            recommendations.append({
                "vulnerability": "提示词注入",
                "severity": "高",
                "recommendation": "实施输入验证和过滤，使用结构化提示词，限制模型权限范围"
            })
        
        if "function_call_escalation" in vulnerability_stats:
            recommendations.append({
                "vulnerability": "函数调用越权",
                "severity": "高",
                "recommendation": "实施严格的权限校验，限制函数调用参数，使用白名单机制"
            })
        
        if "data_leakage" in vulnerability_stats:
            recommendations.append({
                "vulnerability": "数据泄露",
                "severity": "高",
                "recommendation": "实施数据脱敏，限制敏感信息访问，使用安全的数据存储"
            })
        
        if "overfitting" in vulnerability_stats:
            recommendations.append({
                "vulnerability": "过度拟合",
                "severity": "中",
                "recommendation": "使用更多样化的训练数据，实施正则化技术，定期模型评估"
            })
        
        if "privilege_escalation" in vulnerability_stats:
            recommendations.append({
                "vulnerability": "权限提升",
                "severity": "高",
                "recommendation": "实施最小权限原则，定期权限审计，使用多因素认证"
            })
        
        return recommendations
    
    def _generate_summary(self, scan_results: List[Dict[str, Any]], vulnerability_stats: Dict[str, int], risk_level: str) -> str:
        """生成报告摘要"""
        total_tests = len(scan_results)
        vulnerable_tests = sum(1 for r in scan_results if r["is_vulnerable"])
        
        summary = f"扫描完成，共执行 {total_tests} 个测试用例，发现 {vulnerable_tests} 个漏洞。"
        summary += f"整体风险等级：{risk_level}。"
        
        if vulnerability_stats:
            summary += "发现的漏洞类型包括："
            for vuln_type, count in vulnerability_stats.items():
                summary += f"{vuln_type} ({count}个)，"
            summary = summary.rstrip("，") + "。"
        else:
            summary += "未发现明显漏洞。"
        
        return summary
