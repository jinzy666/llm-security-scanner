from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import os
from scan_engine import ScanEngine
from result_analyzer import ResultAnalyzer
from test_cases import load_test_cases

app = FastAPI(title="大模型安全漏洞扫描平台", version="1.0.0")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 初始化扫描引擎和分析器
scan_engine = ScanEngine()
result_analyzer = ResultAnalyzer()

@app.post("/api/scan")
async def scan_model(
    model_type: str = Form(...),
    api_key: str = Form(...),
    model_url: str = Form(None),
    test_cases: str = Form("all")
):
    """提交扫描任务"""
    try:
        # 加载测试用例
        test_cases_list = load_test_cases(test_cases)
        
        # 执行扫描
        scan_results = scan_engine.scan(
            model_type=model_type,
            api_key=api_key,
            model_url=model_url,
            test_cases=test_cases_list
        )
        
        # 分析结果
        analysis_results = result_analyzer.analyze(scan_results)
        
        return {
            "success": True,
            "data": {
                "scan_results": scan_results,
                "analysis": analysis_results
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/api/test_cases")
async def get_test_cases():
    """获取测试用例列表"""
    try:
        test_cases = load_test_cases("all")
        return {
            "success": True,
            "data": test_cases
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
