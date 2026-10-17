/** Deployment readiness is distinct from the descriptive dashboard health view. */
const express = require('express');
const {getDBStatus} = require('../config/db.config');
const router = express.Router();
router.get('/', async (req,res) => {
  let ready=false;
  try {
    const database=await getDBStatus();
    const response=await fetch(`${process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000'}/api/v1/face/health`, {signal:AbortSignal.timeout(2000)});
    const face=response.ok ? await response.json() : null;
    ready=database.connected===true && face?.status==='ONLINE' && face.mongodb_connected===true;
  } catch (_) {}
  res.setHeader('Cache-Control','no-store');
  return res.status(ready?200:503).json({ready});
});
module.exports=router;
