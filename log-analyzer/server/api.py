from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
import json
import uvicorn
import random

# Adjust import paths for local package execution
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import init_db, get_db, Device, RawLog, ParsedLog, Alert, Template, CryptoEvent
from decryptor import Decryptor
from classifier import LogSourceClassifier
from parser_engine import ParserEngine
from anomaly_detector import AnomalyDetector
from alert_service import AlertService

app = FastAPI(title="Secure Log Analysis API")

SERVER_PRIVATE_KEY_PATH = "keys/server_private.pem"
CLIENT_KEY_MAP = {
    "client_v1": "keys/client_public.pem"
}

# Initialize modules
init_db()
app.state.decryptor = Decryptor(SERVER_PRIVATE_KEY_PATH, CLIENT_KEY_MAP["client_v1"])
app.state.classifier = LogSourceClassifier()
app.state.parser = ParserEngine()
app.state.detector = AnomalyDetector()
app.state.alert_service = AlertService()

class SecurePayload(BaseModel):
    device_id: str
    timestamp: str
    kid: str | None = None
    sequence_number: int | None = None
    encrypted_logs: str
    encrypted_aes_key: str
    iv: str
    signature: str

@app.get("/health")
def health_check():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

def process_log_batch(payload_dict: dict, db: Session):
    device_id = payload_dict.get('device_id', 'unknown')
    
    # Register/Update Device
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        device = Device(id=device_id)
        db.add(device)
        db.commit()
    else:
        device.last_seen = datetime.utcnow()
        db.commit()

    logs = payload_dict.get('logs', [])
    if not logs:
        return

    raw_messages = [log['raw_logs'] for log in logs]
    predictions = app.state.classifier.predict(raw_messages)

    for i, log_data in enumerate(logs):
        raw_msg = log_data['raw_logs']
        pred_source = predictions[i]['source_type']
        confidence = predictions[i]['confidence_score']

        new_log = RawLog(
            device_id=device_id,
            raw_content=raw_msg,
            predicted_source=pred_source,
            source_confidence=confidence
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log)

        # Parse and Extract Template
        parsed_dict = app.state.parser.parse_log(pred_source, raw_msg)
        template_text, template_id = app.state.parser.extract_template(parsed_dict.get('message', raw_msg))

        db_template = db.query(Template).filter(Template.id == template_id).first()
        if not db_template:
            db_template = Template(id=template_id, template_text=template_text)
            db.add(db_template)
        else:
            db_template.frequency += 1
        
        parsed_log = ParsedLog(
            raw_log_id=new_log.id,
            template_id=template_id,
            parsed_json=json.dumps(parsed_dict)
        )
        db.add(parsed_log)

        # Tabular Transformer Anomaly Detection
        # Simulate features that would normally be extracted via parsing or aggregated
        df_dict = {
            'Response_Time_ms': random.randint(100, 10000),
            'CPU_Usage_Percent': random.uniform(10.0, 99.0),
            'Memory_Usage_MB': random.randint(500, 64000),
            'Disk_Usage_Percent': random.uniform(10.0, 99.0),
            'Network_In_KB': random.randint(1000, 1000000),
            'Network_Out_KB': random.randint(1000, 1000000),
            'Login_Attempts': random.randint(0, 50),
            'Failed_Transactions': random.randint(0, 20),
            'Alert_Count': random.randint(0, 50),
            'Retry_Count': random.randint(0, 10),
            'Source': pred_source,
            'User_Role': random.choice(['Admin', 'User', 'Operator', 'Service Account']),
            'Service_Type': random.choice(['API', 'Web', 'DB', 'Cache', 'Storage']),
            'Location': random.choice(['US', 'EU', 'APAC', 'LATAM'])
        }
        
        anomaly_score, pred_severity = app.state.detector.compute_transformer_anomaly(df_dict)

        alert_obj = app.state.alert_service.evaluate(new_log.id, anomaly_score, parsed_dict)
        if alert_obj:
            if pred_severity != "UNKNOWN":
                alert_obj.severity = pred_severity.upper()
            db.add(alert_obj)

    db.commit()

@app.post("/receive_logs")
def receive_logs(payload: SecurePayload, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    kid = payload.kid or "client_v1"
    if kid not in CLIENT_KEY_MAP:
        raise HTTPException(status_code=400, detail="Unknown key id.")

    app.state.decryptor.load_keys(SERVER_PRIVATE_KEY_PATH, CLIENT_KEY_MAP[kid])

    decrypted_dict, events = app.state.decryptor.decrypt_and_verify(payload.dict())
    
    # Log all cryptographic events
    for event in events:
        db.add(CryptoEvent(
            device_id=payload.device_id,
            event_type=event['event_type'],
            status=event['status'],
            details=event.get('details', '')
        ))
    db.commit()

    if decrypted_dict is None:
        # The last event in the list will contain the reason for failure
        failure_reason = events[-1]['details'] if events else "Unknown validation error"
        raise HTTPException(status_code=400, detail=failure_reason)

    seq = decrypted_dict.get('sequence_number')
    device_id = decrypted_dict.get('device_id', payload.device_id)

    if seq is not None and device_id:
        device = db.query(Device).filter(Device.id == device_id).first()
        now = datetime.utcnow()
        if not device:
            device = Device(id=device_id, first_seen=now, last_seen=now, last_sequence=seq)
            db.add(device)
            db.add(CryptoEvent(
                device_id=device_id,
                event_type="Replay Protection",
                status="Success",
                details=f"Initial sequence_number accepted: {seq}"
            ))
            db.commit()
        else:
            if device.last_sequence is not None and seq <= device.last_sequence:
                db.add(CryptoEvent(
                    device_id=device_id,
                    event_type="Replay Protection",
                    status="Failure",
                    details=f"Rejected sequence_number {seq} (last seen {device.last_sequence})"
                ))
                db.commit()
                raise HTTPException(status_code=400, detail="Replay or out-of-order payload detected.")
            device.last_sequence = seq
            device.last_seen = now
            db.add(CryptoEvent(
                device_id=device_id,
                event_type="Replay Protection",
                status="Success",
                details=f"Accepted sequence_number {seq}"
            ))
            db.commit()

    background_tasks.add_task(process_log_batch, decrypted_dict, db)
    return {"status": "accepted", "message": "Payload verified and accepted for processing"}

@app.get("/alerts")
def get_alerts(limit: int = 50, db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
    return alerts

@app.post("/train_models")
def trigger_training(background_tasks: BackgroundTasks):
    from subprocess import Popen
    background_tasks.add_task(lambda: Popen(["python", "ml/train_classifier.py"]))
    return {"status": "training_triggered"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
