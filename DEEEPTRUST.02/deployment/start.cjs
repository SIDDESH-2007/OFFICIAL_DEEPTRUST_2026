// One AI process preserves in-memory challenges and the single-writer audit chain.
const {spawn} = require('node:child_process');
const {validateProductionConfig} = require('../server/config/production.config');
validateProductionConfig();
const children=[];
let ending=false;
function finish(code){if(ending)return;ending=true;for(const child of children)child.kill('SIGTERM');setTimeout(()=>process.exit(code),3000).unref();}
for(const [exe,args] of [['python',['-m','uvicorn','server.ai_service.face_service:app','--host','127.0.0.1','--port','8000','--workers','1']],['node',['server/server.js']]]){
 const child=spawn(exe,args,{stdio:'inherit',env:process.env});children.push(child);
 child.on('error',()=>finish(1));child.on('exit',code=>finish(code||1));
}
process.on('SIGTERM',()=>finish(0));process.on('SIGINT',()=>finish(0));
