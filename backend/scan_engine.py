import requests
import time
import json
from typing import List, Dict, Any

class ScanEngine:
    def __init__(self):
        self.model_configs = {
            "chatglm": {
                "default_url": "https://open.bigmodel.cn/api/messages",
                "headers": {"Content-Type": "application/json"}
            },
            "qwen": {
                "default_url": "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
                "headers": {"Content-Type": "application/json"}
            },
            "wenxin": {
                "default_url": "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions",
                "headers": {"Content-Type": "application/json"}
            }
        }
    
    def scan(self, model_type: str, api_key: str, model_url: str = None, test_cases: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """执行漏洞扫描"""
        results = []
        
        if not model_url:
            model_url = self.model_configs.get(model_type, {}).get("default_url")
        
        headers = self.model_configs.get(model_type, {}).get("headers", {})
        headers["Authorization"] = f"Bearer {api_key}"
        
        for test_case in test_cases:
            try:
                # 构建请求
                payload = self._build_payload(model_type, test_case["prompt"])
                
                # 发送请求
                start_time = time.time()
                response = requests.post(
                    model_url,
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                end_time = time.time()
                
                # 处理响应
                if response.status_code == 200:
                    response_data = response.json()
                    model_response = self._extract_response(model_type, response_data)
                    
                    # 评估结果
                    is_vulnerable = self._evaluate_response(test_case, model_response)
                    
                    results.append({
                        "test_case_id": test_case["id"],
                        "vulnerability_type": test_case["type"],
                        "prompt": test_case["prompt"],
                        "model_response": model_response,
                        "is_vulnerable": is_vulnerable,
                        "response_time": round(end_time - start_time, 2),
                        "status": "success"
                    })
                else:
                    results.append({
                        "test_case_id": test_case["id"],
                        "vulnerability_type": test_case["type"],
                        "prompt": test_case["prompt"],
                        "model_response": f"API错误: {response.status_code}",
                        "is_vulnerable": False,
                        "response_time": round(end_time - start_time, 2),
                        "status": "error"
                    })
            except Exception as e:
                results.append({
                    "test_case_id": test_case["id"],
                    "vulnerability_type": test_case["type"],
                    "prompt": test_case["prompt"],
                    "model_response": f"执行错误: {str(e)}",
                    "is_vulnerable": False,
                    "response_time": 0,
                    "status": "error"
                })
            
            # 避免请求过快
            time.sleep(1)
        
        return results
    
    def _build_payload(self, model_type: str, prompt: str) -> Dict[str, Any]:
        """构建请求 payload"""
        if model_type == "chatglm":
            return {
                "model": "chatglm4",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
        elif model_type == "qwen":
            return {
                "model": "qwen-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
        elif model_type == "wenxin":
            return {
                "model": "ernie-3.5",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
        else:
            return {
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.7
            }
    
    def _extract_response(self, model_type: str, response_data: Dict[str, Any]) -> str:
        """从响应中提取模型回复"""
        if model_type == "chatglm":
            return response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
        elif model_type == "qwen":
            return response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
        elif model_type == "wenxin":
            return response_data.get("result", "")
        else:
            return str(response_data)
    
    def _evaluate_response(self, test_case: Dict[str, Any], model_response: str) -> bool:
        """评估模型响应是否存在漏洞"""
        # 简单的评估逻辑，实际项目中需要更复杂的判断
        if test_case.get("expected_contains"):
            for keyword in test_case["expected_contains"]:
                if keyword in model_response:
                    return True
        
        if test_case.get("expected_not_contains"):
            for keyword in test_case["expected_not_contains"]:
                if keyword not in model_response:
                    return True
        
        return False
