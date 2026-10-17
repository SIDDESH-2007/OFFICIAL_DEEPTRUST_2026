"""Offline regressions: no app startup, live DB writes or real user credentials."""
import ast
import copy
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Optional, Dict, Any
from bson import ObjectId
from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'server/ai_service'))
import session_monitor as monitor

def match(doc,query):
    for key,value in query.items():
        if key=='$or':
            if not any(match(doc,q) for q in value):return False
        elif isinstance(value,dict) and '$in' in value:
            if doc.get(key) not in value['$in']:return False
        elif doc.get(key)!=value:return False
    return True
class Cursor(list):
    def sort(self,key,direction):return Cursor(sorted(self,key=lambda d:d.get(key,0),reverse=direction<0))
    def limit(self,n):return Cursor(self[:n])
class Collection:
    def __init__(self,docs=()):self.docs=copy.deepcopy(list(docs))
    def find_one(self,query):return next((copy.deepcopy(d) for d in self.docs if match(d,query)),None)
    def find(self,query):return Cursor(copy.deepcopy([d for d in self.docs if match(d,query)]))
    def update_one(self,query,update,**kwargs):
        for d in self.docs:
            if match(d,query):d.update(update.get('$set',{}));return
    def insert_one(self,doc):self.docs.append(copy.deepcopy(doc))
    def count_documents(self,query):return len(self.find(query))

class LifecycleTests(unittest.TestCase):
    def test_active_clock_and_expiry_cap(self):
        s={'login_at':100,'last_activity_at':120,'expires_at':200}
        self.assertEqual(monitor.lifecycle(s,150)['duration_seconds'],50)
        self.assertEqual(monitor.lifecycle(s,500)['duration_seconds'],100)
        self.assertEqual(monitor.lifecycle(s,500)['status'],'EXPIRED')
    def test_logout_and_revocation_freeze_clock(self):
        for state in ['LOGGED_OUT','REVOKED']:
            s={'login_at':100,'logout_at':140,'revoked_at':140,'revoked':True,'status':state}
            result=monitor.lifecycle(s,800)
            self.assertEqual(result['status'],state);self.assertEqual(result['duration_seconds'],40)
    def test_idle_session_elapsed_duration_still_runs(self):
        self.assertEqual(monitor.lifecycle({'login_at':100,'expires_at':8000},2000)['status'],'IDLE')
    def test_all_ip_families_masked(self):
        for ip in ['127.0.0.1','192.168.10.3','8.8.8.8','2001:db8::1234','::1']:
            self.assertNotEqual(monitor.masked_ip(ip),ip);self.assertIn('*',monitor.masked_ip(ip))
        self.assertEqual(monitor.masked_ip(None),'Unavailable')
    def test_missing_device_and_behavior_do_not_claim_normal(self):
        view=monitor.session_projection({'_id':'a','login_at':100,'behavior_summary':{'status':'NORMAL','average_velocity':45}},150)
        self.assertEqual(view['behavior_summary']['status'],'INSUFFICIENT_DATA')
        self.assertEqual(view['browser'],'Unknown')
    def test_missing_factor_data_not_verified(self):
        self.assertEqual(set(monitor.assurance_projection(None).values()),{'NOT_RECORDED'})

class RouteTests(unittest.TestCase):
    def setUp(self):
        self.user={'_id':'alice','session_id':'a','email':'a@example.test','role':'HOSPITAL_ADMIN','organization_id':'org-a'}
        common={'user_id':'alice','identity_id':'alice','email':'a@example.test','organization_id':'org-a','login_at':100,
            'created_at':100,'expires_at':500,'status':'ACTIVE','ip_address':'192.168.10.4','verification_session_id':'v',
            'last_activity_at':110,'device_context':{'browser':'Firefox','os':'Linux'}}
        self.db=SimpleNamespace(auth_sessions=Collection([dict(common,_id='a',session_id='a'),dict(common,_id='b',session_id='b',user_id='bob',identity_id='bob',organization_id='org-b')]),
            verification_sessions=Collection([{'session_id':'v','credential_status':'VERIFIED','face_status':'VERIFIED','mfa_status':'VERIFIED'}]),
            audit_logs=Collection(),trusted_devices=Collection(),users=Collection([{'_id':'alice','email':'a@example.test','organization_id':'org-a'}]))
        self.db.security_policies=Collection()
        self.now=150
        self.env={k:getattr(monitor,k) for k in ['PLATFORM_ROLES','MONITOR_ROLES','masked_ip','iso_time','lifecycle','session_projection','assurance_projection','behavior_signal']}
        self.env.update(db=self.db,time=SimpleNamespace(time=lambda:self.now),ObjectId=ObjectId,HTTPException=HTTPException,
            BaseModel=BaseModel,Field=Field,Optional=Optional,Dict=Dict,Any=Any,Request=Any,
            Header=lambda *_:None,Depends=lambda *_:None,get_authenticated_user_from_header=lambda _:self.user)
        def audit(event,uid,email,org,action,**kwargs):
            self.db.audit_logs.insert_one({'event_type':event,'identity_id':uid,'session_id':kwargs.get('session_id'),
                'created_at':self.now,'action':action,'details':kwargs.get('details') or {}})
        from security_controls import session_deadline
        self.env['session_deadline']=session_deadline
        self.env['log_audit_event']=audit
        tree=ast.parse((ROOT/'server/ai_service/face_service.py').read_text(encoding='utf-8'))
        selected={'SessionActivityHeartbeat','BehaviorSummaryRequest','require_monitor_scope','owned_monitor_session','record_session_activity',
            'record_behavior_summary','get_session_control_data','get_session_security_context','get_session_audit_timeline'}
        nodes=[]
        for n in tree.body:
            if isinstance(n,(ast.ClassDef,ast.FunctionDef)) and n.name in selected:n.decorator_list=[];nodes.append(n)
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual monitor routes>','exec'),self.env)
    def call(self,name,*args):return self.env[name](*args)
    def activity(self,**kwargs):return self.call('record_session_activity',self.env['SessionActivityHeartbeat'](**kwargs))
    def behavior(self,**kwargs):return self.call('record_behavior_summary',self.env['BehaviorSummaryRequest'](**kwargs))
    def test_monitor_roles_and_organization_isolation(self):
        self.assertEqual(self.call('get_session_control_data',self.user)['count'],1)
        self.user['role']='DOCTOR'
        with self.assertRaises(HTTPException) as err:self.call('get_session_control_data',self.user)
        self.assertEqual(err.exception.status_code,403)
    def test_details_reject_another_organization(self):
        with self.assertRaises(HTTPException) as err:self.call('get_session_security_context','b',self.user)
        self.assertEqual(err.exception.status_code,403)
    def test_missing_organization_never_exposes_unscoped_sessions(self):
        self.user.pop('organization_id')
        with self.assertRaises(HTTPException):self.call('get_session_control_data',self.user)
        self.user['organization_id']='org-a'
        self.db.auth_sessions.docs[0].pop('organization_id')
        with self.assertRaises(HTTPException):self.call('get_session_security_context','a',self.user)
    def test_heartbeat_cannot_target_another_session(self):
        with self.assertRaises(HTTPException):self.activity(session_id='b',has_activity=True)
        self.assertEqual(self.db.auth_sessions.docs[1]['last_activity_at'],110)
    def test_heartbeat_does_not_fake_user_activity(self):
        self.activity()
        self.assertEqual(self.db.auth_sessions.docs[0]['last_activity_at'],110)
        self.assertEqual(self.db.auth_sessions.docs[0]['last_heartbeat_at'],150)
    def test_navigation_is_recorded_only_for_own_session(self):
        self.activity(action_type='VIEW_SECTION',has_activity=True,details={'resource':'admin-session-control','password':'ignored'})
        event=self.db.audit_logs.docs[0]
        self.assertEqual(event['session_id'],'a');self.assertEqual(event['details'],{'resource':'admin-session-control'})
    def test_normal_variance_is_not_automatically_bot(self):
        result=self.behavior(sample_count=10,average_velocity=400,velocity_variance=100000,trusted_events=20)
        self.assertEqual(result['behavior_signal'],'NORMAL')
        self.assertEqual(result['summary']['identity_claim'],'UNDETERMINED')
        self.assertNotIn('behavior_summary',self.db.auth_sessions.docs[1])
    def test_automation_signal_is_correlated_and_does_not_grant_access(self):
        result=self.behavior(webdriver=True,synthetic_events=4)
        self.assertEqual(result['behavior_signal'],'DEVIATION')
        self.assertEqual(self.db.audit_logs.docs[0]['session_id'],'a')
        self.assertEqual(self.db.auth_sessions.docs[0]['status'],'ACTIVE')
    def test_old_interaction_data_is_marked_stale_without_mutating_storage(self):
        source={'_id':'x','login_at':100,'behavior_summary':{'status':'NORMAL','updated_at':100,'reason_codes':[]}}
        view=monitor.session_projection(source,150)
        self.assertEqual(view['behavior_summary']['status'],'STALE_DATA')
        self.assertEqual(view['behavior_summary']['last_measured_status'],'NORMAL')
        self.assertEqual(source['behavior_summary']['status'],'NORMAL')
    def test_logged_out_interaction_data_is_historical(self):
        source={'_id':'x','login_at':100,'status':'LOGGED_OUT','logout_at':140,'behavior_summary':{'status':'NORMAL','updated_at':110}}
        view=monitor.session_projection(source,200)
        self.assertEqual(view['behavior_summary']['freshness'],'HISTORICAL')
        self.assertEqual(view['behavior_summary']['status'],'NORMAL')
    def test_high_polling_mouse_is_not_automatically_suspicious(self):
        result=self.behavior(sample_count=100,movement_rate=1000,average_velocity=500,velocity_variance=40000,trusted_events=100)
        self.assertEqual(result['behavior_signal'],'NORMAL')
    def test_uniform_repeated_paths_are_review_indicators(self):
        result=self.behavior(sample_count=100,average_velocity=500,velocity_variance=0,path_straightness=1,path_segments=8,pointer_interval_cv=0)
        self.assertIn('REPETITIVE_POINTER_PATTERN',result['summary']['reason_codes'])
        self.assertEqual(result['summary']['identity_claim'],'UNDETERMINED')
    def test_touch_swipes_not_evaluated_as_mouse_paths(self):
        result=self.behavior(sample_count=100,average_velocity=500,velocity_variance=0,path_straightness=1,path_segments=8,pointer_interval_cv=0,is_touch_device=True,swipe_count=3)
        self.assertEqual(result['behavior_signal'],'NORMAL')
        self.assertEqual(result['summary']['swipe_count'],3)
    def test_scroll_only_activity_is_measured(self):
        result=self.behavior(scroll_events=5,window_seconds=15)
        self.assertEqual(result['behavior_signal'],'NORMAL')
    def test_extreme_scroll_rate_flagged(self):
        result=self.behavior(wheel_events=2000,window_seconds=15)
        self.assertIn('UNUSUAL_SCROLL_SWIPE_RATE',result['summary']['reason_codes'])
    def test_no_samples_are_insufficient(self):self.assertEqual(self.behavior()['behavior_signal'],'INSUFFICIENT_DATA')
    def test_invalid_numeric_values_rejected(self):
        for kwargs in [{'average_velocity':float('nan')},{'click_rate':-1},{'idle_ratio':2},{'sample_count':-1}]:
            with self.assertRaises(ValidationError):self.env['BehaviorSummaryRequest'](**kwargs)
    def test_logged_out_session_stays_in_history_but_not_active_count(self):
        self.db.auth_sessions.docs[0].update(status='LOGGED_OUT',logout_at=140,revoked=True)
        result=self.call('get_session_control_data',self.user)
        self.assertEqual(result['count'],1);self.assertEqual(result['summary']['active_sessions'],0)
        self.assertEqual(result['sessions'][0]['duration_seconds'],40)
    def test_timeline_uses_only_correlated_events_and_no_fake_times(self):
        self.db.audit_logs.docs=[{'identity_id':'alice','session_id':'v','event_type':'FACE_VERIFIED','created_at':110,'action':'Face matched'},
            {'identity_id':'bob','session_id':'b','event_type':'DASHBOARD_VIEWED','created_at':120,'action':'Other user'}]
        result=self.call('get_session_audit_timeline','alice','a',self.user)
        self.assertEqual(result['activity_timeline'],[])
        rows=result['authentication_timeline']
        self.assertEqual(rows[0]['timestamp'],monitor.iso_time(110))
        self.assertTrue(all(row['timestamp'] is None for row in rows[1:]))
        self.assertNotIn('192.168.10.4',str(result))
    def test_timeline_identity_swap_rejected(self):
        with self.assertRaises(HTTPException):self.call('get_session_audit_timeline','bob','a',self.user)

if __name__=='__main__':unittest.main()
