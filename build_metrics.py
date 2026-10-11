#!/usr/bin/env python3
"""Calculate transparent metrics over explicitly synthetic SOC training CSVs."""
from __future__ import annotations
import argparse,csv,json,sqlite3
from collections import Counter
from datetime import datetime,timezone
from pathlib import Path

SCHEMA='''
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,alert_type TEXT NOT NULL,severity TEXT NOT NULL,disposition TEXT NOT NULL,source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY,alert_id TEXT,occurred_at TEXT,detected_at TEXT,first_response_at TEXT,resolved_at TEXT,category TEXT NOT NULL,outcome TEXT NOT NULL);
'''

def parse_time(value: str):
    if not value.strip(): return None
    dt=datetime.fromisoformat(value.replace('Z','+00:00'))
    if dt.tzinfo is None: raise ValueError(f'Timestamp must include a timezone: {value}')
    return dt.astimezone(timezone.utc)

def minutes(start,end):
    a,b=parse_time(start or ''),parse_time(end or '')
    if a is None or b is None:return None,'missing'
    delta=(b-a).total_seconds()/60
    if delta<0:return None,'invalid'
    return round(delta,2),'valid'

def read_rows(path: Path, required: set[str]) -> list[dict[str,str]]:
    with path.open(newline='',encoding='utf-8-sig') as f:
        reader=csv.DictReader(f)
        missing=required-set(reader.fieldnames or [])
        if missing: raise ValueError(f'{path} missing required CSV columns: {", ".join(sorted(missing))}')
        rows=list(reader)
    for row_number,row in enumerate(rows,2):
        if any(row.get(column) is None for column in required):
            raise ValueError(f'{path}:{row_number} has a malformed row')
    return rows

def load_csv(conn,alerts_path:Path,incidents_path:Path):
    alert_rows=read_rows(alerts_path,{'alert_id','created_at','alert_type','severity','disposition','source'})
    incident_rows=read_rows(incidents_path,{'incident_id','alert_id','occurred_at','detected_at','first_response_at','resolved_at','category','outcome'})
    for row in alert_rows:
        if not row['alert_id'] or not row['created_at'] or not row['alert_type']:
            raise ValueError(f'{alerts_path}: alert ID, created timestamp, and type are required')
        parse_time(row['created_at'])
    for row in incident_rows:
        if not row['incident_id'] or not row['category']:
            raise ValueError(f'{incidents_path}: incident ID and category are required')
        for column in ('occurred_at','detected_at','first_response_at','resolved_at'):
            if row[column]: parse_time(row[column])
    try:
        conn.execute('BEGIN')
        conn.execute('DELETE FROM alerts')
        conn.execute('DELETE FROM incidents')
        conn.executemany('INSERT INTO alerts VALUES(:alert_id,:created_at,:alert_type,:severity,:disposition,:source)',alert_rows)
        conn.executemany('INSERT INTO incidents VALUES(:incident_id,:alert_id,:occurred_at,:detected_at,:first_response_at,:resolved_at,:category,:outcome)',incident_rows)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

def build(conn):
    alert_rows=conn.execute('SELECT alert_type,severity,disposition FROM alerts').fetchall()
    volume=Counter((r[0],r[1],r[2]) for r in alert_rows)
    by_type=[{'alert_type':a,'severity':s,'disposition':d,'count':n} for (a,s,d),n in sorted(volume.items())]
    incidents=conn.execute('SELECT incident_id,occurred_at,detected_at,first_response_at FROM incidents ORDER BY incident_id').fetchall()
    ttd=[];ttr=[];missing={'ttd':0,'ttr':0};invalid={'ttd':0,'ttr':0}
    for _,occurred,detected,response in incidents:
        value,state=minutes(occurred,detected)
        if state=='valid':ttd.append(value)
        else:(missing if state=='missing' else invalid)['ttd']+=1
        value,state=minutes(detected,response)
        if state=='valid':ttr.append(value)
        else:(missing if state=='missing' else invalid)['ttr']+=1
    def summary(values):
        return {'count':len(values),'mean_minutes':round(sum(values)/len(values),2) if values else None,'median_minutes':median(values) if values else None}
    return {'label':'SYNTHETIC TRAINING DATA — NOT OPERATIONAL SOC PERFORMANCE','alert_record_count':len(alert_rows),'alert_volume_by_type_severity_disposition':by_type,'incident_count':len(incidents),'time_to_detect':summary(ttd),'time_to_first_response':summary(ttr),'missing_interval_count':missing,'invalid_negative_interval_count':invalid,'definitions':{'ttd':'detected_at - occurred_at','ttr':'first_response_at - detected_at (first response, not containment)'},'limitations':['Synthetic sample only; not Sentinel or live SIEM data.','Small sample; no SLA attainment or comparative performance claim.','No de-duplication beyond unique alert_id; validate event semantics and time sources for production.']}

def median(values):
    values=sorted(values);n=len(values);mid=n//2
    return round(values[mid],2) if n%2 else round((values[mid-1]+values[mid])/2,2)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--alerts',type=Path,default=Path('data/alerts.csv'));p.add_argument('--incidents',type=Path,default=Path('data/incidents.csv'));p.add_argument('--db',type=Path,default=Path('data/soc-metrics.sqlite'));p.add_argument('--out',type=Path,default=Path('reports'));a=p.parse_args()
    for path in (a.alerts,a.incidents):
        if not path.is_file():p.error(f'input not found: {path}')
    a.db.parent.mkdir(parents=True,exist_ok=True);a.out.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(a.db)
    try:
        conn.executescript(SCHEMA);load_csv(conn,a.alerts,a.incidents);result=build(conn)
    except (ValueError,sqlite3.Error) as exc:
        p.error(str(exc))
    finally:conn.close()
    (a.out/'metrics.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    with (a.out/'metrics-summary.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f);w.writerow(['metric','count','mean_minutes','median_minutes']);w.writerow(['TTD',result['time_to_detect']['count'],result['time_to_detect']['mean_minutes'],result['time_to_detect']['median_minutes']]);w.writerow(['TTR',result['time_to_first_response']['count'],result['time_to_first_response']['mean_minutes'],result['time_to_first_response']['median_minutes']])
    print(f"Built metrics for {result['alert_record_count']} synthetic alert records and {result['incident_count']} incidents. Outputs: {a.out}; not live SOC data.")
    return 0
if __name__=='__main__':raise SystemExit(main())
