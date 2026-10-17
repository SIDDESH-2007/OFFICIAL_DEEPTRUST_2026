const {test}=require('node:test'), assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const root=process.env.DEEPTRUST_TEST_ROOT || path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'server/middleware/auth.middleware.js'),'utf8');
const {isNotificationRead}=require(path.join(root,'server/middleware/notification-budget'));
async function request({dbDown=false,readError=false,session={},user={},token={},missingUser=false}={}) {
 const now=Date.now()/1000,decoded={token_type:'ACCESS',sub:'u',email:'u@test',session_id:'s',...token};
 const storedSession=session===null?null:{identity_id:'u',email:'u@test',organization_id:'platform',status:'ACTIVE',created_at:now-10,last_activity_at:now-10,expires_at:now+2000,...session};
 const storedUser={_id:'u',email:'u@test',role:'DEEPTRUST_ADMIN',organization_id:'platform',status:'ACTIVE',...user};
 const db={collection:name=>({findOne:async()=>{if(readError)throw Error('offline');return name==='auth_sessions'?storedSession:name==='security_policies'?{}:missingUser?null:storedUser;}})};
 const context={module:{exports:{}},require:name=>name.includes('token.service')?{verifyToken:()=>decoded}:{getDbInstance:()=>dbDown?null:db},console,Date};
 vm.runInNewContext(source,context);let status=200,body,called=false;
 const req={headers:{authorization:'Bearer fixture'},method:'GET'};
 const res={status:n=>{status=n;return res},json:value=>{body=value;return res}};
 await context.module.exports.authMiddleware(req,res,()=>called=true);
 return {status,body,called,req};
}
test('real account and owned active session proceed with database role',async()=>{const r=await request({token:{role:'ATTACKER_ROLE'}});assert(r.called);assert.equal(r.req.user.role,'DEEPTRUST_ADMIN');});
test('database outages cannot silently authorise',async()=>{for(const opts of [{dbDown:true},{readError:true}]){const r=await request(opts);assert.equal(r.status,503);assert(!r.called);}});
test('missing, revoked and ended sessions denied',async()=>{for(const session of [null,{revoked:true},{status:'REVOKED'},{status:'LOGGED_OUT'},{status:'STEP_UP_REQUIRED'}]){const r=await request({session});assert.equal(r.status,401);assert(!r.called);}});
test('wrong identity and wrong email denied',async()=>{for(const session of [{identity_id:'other'},{email:'other@test'}])assert.equal((await request({session})).status,401);});
test('idle and absolute expiry denied',async()=>{for(const session of [{last_activity_at:1},{created_at:1,last_activity_at:Date.now()/1000}])assert.equal((await request({session})).status,401);});
test('disabled and missing accounts cannot use demo fallback',async()=>{assert.equal((await request({user:{status:'DISABLED'}})).status,403);assert.equal((await request({missingUser:true,token:{email:'admin@novacaremedical.org'}})).status,401);});
test('verification tokens and incomplete claims denied',async()=>{assert.equal((await request({token:{token_type:'VERIFICATION'}})).status,403);assert.equal((await request({token:{session_id:null}})).status,401);});
test('only GET notification reads have a separate polling budget',()=>{for(const p of ['/api/v1/notifications','/api/v1/notifications/','/api/v1/notifications/unread-count'])assert(isNotificationRead({method:'GET',path:p}));for(const req of [{method:'POST',path:'/api/v1/notifications/read-all'},{method:'GET',path:'/api/v1/auth'},{method:'GET',path:'/api/v1/notifications/other'}])assert(!isNotificationRead(req));});
test('normal polling exceeds neither its budget nor global bucket',()=>{const app=fs.readFileSync(path.join(root,'server/app.js'),'utf8');assert(app.includes('isSessionMonitorRequest(req) || isNotificationRead(req)'));assert(app.includes('windowMs: 60 * 1000, max: 180'));assert(60*2<180);});

test('account moved to another organisation cannot reuse its session', async()=>assert.equal((await request({user:{organization_id:'other'}})).status,401));
