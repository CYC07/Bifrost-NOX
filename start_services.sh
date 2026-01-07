#!/bin/bash
export PYTHONPATH=$PYTHONPATH:$(pwd)

# Kill existing if any (simple cleanup)
pkill -f "uvicorn" || true

source /home/cyc0logy/FYP/ai_firewall/venv/bin/activate

echo "Starting Image Service on 8001..."
nohup uvicorn image_service.main:app --host 0.0.0.0 --port 8001 > image.log 2>&1 &

echo "Starting Document Service on 8002..."
nohup uvicorn document_service.main:app --host 0.0.0.0 --port 8002 > document.log 2>&1 &

echo "Starting Text Service on 8003..."
nohup uvicorn text_service.main:app --host 0.0.0.0 --port 8003 > text.log 2>&1 &

echo "Starting Master AI on 8000..."
nohup uvicorn master_ai.orchestrator:app --host 0.0.0.0 --port 8000 > master.log 2>&1 &

echo "All services started."
