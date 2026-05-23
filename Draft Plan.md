# Project Sentinel: Agentic Security Proxy

## 1. Project Overview
Project Sentinel is a low-latency, AI-powered reverse proxy designed to secure autonomous computer-using agents (e.g., OpenClaw). It acts as an execution guardrail. Before an agent executes a system command, the command and context are intercepted by Sentinel. A locally-hosted PyTorch binary classifier evaluates the command for malicious or destructive intent. 
*   If `score >= 0.8` (Dangerous): The command is blocked, returning a `403 Forbidden`.
*   If `score < 0.8` (Safe): The command is executed within a sandboxed Docker container, returning `stdout`/`stderr`.
*   Every interception is asynchronously logged to AWS DynamoDB for auditing.

## 2. Tech Stack
*   **ML Engine:** PyTorch (Fine-tuning Hugging Face `DistilBERT`), exported to ONNX for fast inference.
*   **Proxy Server:** Python (FastAPI), Uvicorn, `asyncio`.
*   **Containerization:** Docker (Multi-stage builds, non-root execution).
*   **Cloud Infrastructure:** AWS (API Gateway, ECS/Fargate, DynamoDB, `boto3`).

## 3. Data Schema
The PyTorch model requires a `jsonl` training dataset with the following strict schema:
```json
{
  "context": "User prompt or agent objective string.",
  "command": "The raw bash, Python, or AWS CLI command the agent intends to run.",
  "label": 0 // 0 for Safe, 1 for Dangerous
}

4. Required Scripts & Architecture Specs
A. Data Engineering (data_pipeline.py)
Input: Raw trace logs from 2026 agent safety benchmarks (e.g., CUAHarm, OS-Harm).

Execution: Extract system_prompt and tool_execution strings. Map tasks flagged as safety violations to label: 1, and benign operations to label: 0.

Synthetic Augmentation: Include an async function using the openai SDK to generate edge-case bash commands (obfuscated payloads vs. complex benign commands) using a strict system prompt.

B. Model Training (train_guardrail.py)
Execution: Load the jsonl dataset via PyTorch DataLoader. Fine-tune a pre-trained DistilBERT sequence classifier for binary classification.

Optimization: Focus loss calculations on penalizing False Negatives.

Output: Export the trained weights to an .onnx file for optimized production inference.

C. Proxy API (main.py)
Framework: FastAPI.

Inference: Load the .onnx model into memory on startup.

Endpoint: POST /execute accepting {"context": str, "command": str}.

Routing Logic:

Score the command.

If blocked, trigger background DynamoDB logging task and return 403.

If allowed, execute the command using Python's subprocess.run with a strict timeout and captured streams. Trigger background DynamoDB logging task and return 200 with stdout.

D. AWS Infrastructure (infra.py or CDK script)
DynamoDB Table: sentinel_audit_logs.

Partition Key: request_id (String - UUID)

Sort Key: timestamp (Number)

Attributes: command (String), inference_score (Number), verdict (String).

Compute: Specifications for an ECS Fargate task definition utilizing the Dockerfile.

E. Dockerfile
Requirements: Must install PyTorch inference dependencies and FastAPI. Must create a dedicated sentinel non-root user. Must use a WORKDIR with restricted write permissions to ensure the shell execution layer is heavily sandboxed.