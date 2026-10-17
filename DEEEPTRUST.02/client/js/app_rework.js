/**
 * app_rework.js — DeepTrust Application & Security Orchestrator
 * ============================================================
 * Complete 5-Stage Zero-Trust Authentication Lifecycle:
 *   Stage 1: Credentials (Email + Password -> Pre-Auth Verification Token)
 *   Stage 2: Real Face Biometrics & Active Liveness (OpenCV YuNet + SFace DNN)
 *   Stage 3: Voice Biometrics & Phrase Verification (Web Audio Waveform + Backend Match)
 *   Stage 4: Two-Step Authenticator (RFC 6238 TOTP)
 *   Stage 5: Zero-Trust Risk Evaluation & Final Access Token Generation (/auth/finalize -> Dashboard)
 */

let activeMediaStream = null;
let detectionInterval = null;
let isProcessingFrame = false;
let isMatching = false;
let isEnrolling = false;
let isLivenessChecking = false;
let currentLivenessChallenge = null;
let faceStableCounter = 0;
let faceMissingCounter = 0;

let lastVerifiedFrame = null;
let lastFaceBoundingBox = null;

function playFaceSuccessAnimation() {
  const container = document.querySelector('.camera-container');
  if (!container) {
    setTimeout(() => {
      stopCameraFeed();
      switchAuthView('voice');
    }, 1000);
    return;
  }
  
  let overlay = document.getElementById('face-success-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'face-success-overlay';
    overlay.className = 'face-success-overlay';
    overlay.innerHTML = `
      <div class="face-success-frame">
        <img class="face-success-image" id="face-success-image" src="" alt="Face">
        <div class="face-success-ring"></div>
        <div class="face-success-check">✓</div>
      </div>
      <div class="face-success-status" id="face-success-status">MATCH CONFIRMED</div>
    `;
    container.appendChild(overlay);
  }
  
  const img = document.getElementById('face-success-image');
  const status = document.getElementById('face-success-status');
  
  if (lastVerifiedFrame) {
    img.src = lastVerifiedFrame;
  }
  
  if (lastFaceBoundingBox) {
    img.style.objectPosition = '50% 50%';
  }
  
  overlay.classList.remove('animate-scan', 'verified');
  
  requestAnimationFrame(() => {
    overlay.classList.add('active');
    
    setTimeout(() => {
      overlay.classList.add('animate-scan');
    }, 50);
    
    setTimeout(() => {
      status.textContent = 'IDENTITY VERIFIED';
      overlay.classList.add('verified');
      
      setTimeout(() => {
        const verifyView = document.getElementById('view-verify');
        if (verifyView && verifyView.classList.contains('active')) {
          stopCameraFeed();
          switchAuthView('voice');
        }
      }, 700);
    }, 1100);
  });
}

let isIdentityMatched = false;
let faceVerificationEpoch = 0;
let isLivenessVerified = false;
let isVoiceVerified = false;
let currentVoiceChallenge = null; // tracks the phrase loaded for this session
let isMfaVerified = false;
let currentSessionId = 'dt_sess_' + Date.now();
let currentVerificationToken = null;
let currentSelectedAccessType = 'HOSPITAL_ADMIN';
let audioContext = null;
let audioAnalyser = null;
let audioStream = null;
let animationFrameId = null;

// A browser Back/Forward cache restore must not revive a completed login form.
window.addEventListener('pageshow', event => {
  if (event.persisted) window.location.reload();
});

document.addEventListener('DOMContentLoaded', () => {
  initOAuthFlowDetection();
  checkExistingSession();
  initStartupIntro();
  initBootExperience();
  initPortalSelection();
  initPasswordUx();
  initAuthNavigation();
  initOtpInputs();
  initAuthForms();
  initFinalAccessButton();
  initVoiceVerification();
  initRegisterUx();
  initRegisterForms();
});

/* ============================================================
   OAUTH2 SSO INTEGRATION (External Healthcare / Portal Gateway)
   ============================================================ */
function initOAuthFlowDetection() {
  const urlParams = new URLSearchParams(window.location.search);
  const clientId = urlParams.get('client_id') || urlParams.get('oauth_client');
  const redirectUri = urlParams.get('redirect_uri');
  const state = urlParams.get('state');
  const codeChallenge = urlParams.get('code_challenge');
  const codeChallengeMethod = urlParams.get('code_challenge_method') || 'S256';
  const requestedRole = urlParams.get('role');
  const requestedEmail = urlParams.get('email');

  if (clientId && redirectUri) {
    const oauthParams = {
      client_id: clientId,
      redirect_uri: redirectUri,
      state: state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      role: requestedRole,
      email: requestedEmail
    };
    sessionStorage.setItem('dt_oauth_params', JSON.stringify(oauthParams));

    const targetEmail = requestedEmail || '';
    currentSelectedAccessType = 'HOSPITAL_ADMIN';

    // Directly focus login view
    setTimeout(() => {
      switchAuthView('login');
      const emailInput = document.getElementById('input-email');
      if (emailInput && targetEmail) {
        emailInput.value = targetEmail;
      }
      const passInput = document.getElementById('input-password');
      if (passInput) {
        passInput.value = '';
      }
      const portalNamePill = document.getElementById('login-portal-name');
      if (portalNamePill) {
        portalNamePill.textContent = `NovaCare Staff SSO: ${(requestedRole || 'STAFF').toUpperCase().replace('_', ' ')}`;
      }
      const loginTitle = document.getElementById('login-title');
      if (loginTitle) {
        loginTitle.textContent = 'NovaCare Staff Biometric SSO';
      }
    }, 100);
  } else {
    sessionStorage.removeItem('dt_oauth_params');
    sessionStorage.removeItem('dt_oauth_completed_access');
  }
}

/* ============================================================
   STARTUP INTRO LOADER (SECTION 23-30)
   0% -> 100% Sequential illumination of 7 security stages
   Neutral wording: Initializing Secure Experience
   Duration: ~2.0 seconds. Does NOT alter authentication state.
   ============================================================ */
function initStartupIntro() {
  const introEl = document.getElementById('dt-startup-intro');
  if (!introEl) return;

  // Session check: only play once per browser session
  if (sessionStorage.getItem('dt_intro_completed') === 'true') {
    introEl.style.display = 'none';
    return;
  }

  const percentEl = document.getElementById('dt-intro-percent');
  const barEl = document.getElementById('dt-intro-bar');
  const stageItems = [
    document.getElementById('intro-stage-1'), // Credentials 0-14%
    document.getElementById('intro-stage-2'), // Face 15-28%
    document.getElementById('intro-stage-3'), // Liveness 29-42%
    document.getElementById('intro-stage-4'), // Voice 43-56%
    document.getElementById('intro-stage-5'), // Authenticator 57-70%
    document.getElementById('intro-stage-6'), // Risk 71-85%
    document.getElementById('intro-stage-7'), // Access 86-100%
  ];

  let currentPercent = 0;
  const totalDurationMs = 2000;
  const intervalMs = 25;
  const step = 100 / (totalDurationMs / intervalMs);

  const timer = setInterval(() => {
    currentPercent += step;
    if (currentPercent >= 100) {
      currentPercent = 100;
      clearInterval(timer);

      stageItems.forEach(item => item && item.classList.add('active'));
      if (percentEl) percentEl.textContent = '100%';
      if (barEl) barEl.style.width = '100%';

      setTimeout(() => {
        introEl.classList.add('fade-out');
        sessionStorage.setItem('dt_intro_completed', 'true');
        setTimeout(() => {
          introEl.style.display = 'none';
        }, 600);
      }, 300);
      return;
    }

    const rounded = Math.floor(currentPercent);
    if (percentEl) percentEl.textContent = `${rounded}%`;
    if (barEl) barEl.style.width = `${rounded}%`;

    if (rounded >= 0 && stageItems[0]) stageItems[0].classList.add('active');
    if (rounded >= 15 && stageItems[1]) stageItems[1].classList.add('active');
    if (rounded >= 29 && stageItems[2]) stageItems[2].classList.add('active');
    if (rounded >= 43 && stageItems[3]) stageItems[3].classList.add('active');
    if (rounded >= 57 && stageItems[4]) stageItems[4].classList.add('active');
    if (rounded >= 71 && stageItems[5]) stageItems[5].classList.add('active');
    if (rounded >= 86 && stageItems[6]) stageItems[6].classList.add('active');
  }, intervalMs);
}

/* ============================================================
   0. SESSION RESUMPTION & PRE-AUTHENTICATION CHECK
   ============================================================ */
let loginEntryInitialized = false;
async function checkExistingSession() {
  // A new login page always requires fresh authentication. Boot also calls
  // this function, so clear only once: never erase an in-progress new login.
  if (!loginEntryInitialized) {
    loginEntryInitialized = true;
    // Hospital SSO must authenticate afresh without signing out a separate
    // DeepTrust monitoring tab that uses the shared persistent access token.
    if (!sessionStorage.getItem('dt_oauth_params')) window.Session?.clear?.();
    sessionStorage.removeItem('dt_verification_token');
    sessionStorage.removeItem('dt_verification_session_id');
    sessionStorage.removeItem('dt_oauth_completed_access');
    currentVerificationToken = null;
  }
  return false;
}

/* ============================================================
   1. BOOT EXPERIENCE & REAL BACKEND HEALTH CHECKS
   ============================================================ */
async function initBootExperience() {
  const bootScreen = document.getElementById('boot-screen');
  const progressFill = document.getElementById('boot-progress-fill');
  const statusText = document.getElementById('boot-status-text');
  const terminal = document.getElementById('boot-log-terminal');

  const dotApi = document.getElementById('dot-api');
  const textApi = document.getElementById('text-api');
  const dotDb = document.getElementById('dot-db');
  const textDb = document.getElementById('text-db');
  const statusGroup = document.getElementById('system-status-indicators');

  if (!bootScreen) return;

  const logStep = (text) => {
    if (!terminal) return;
    const line = document.createElement('div');
    line.className = 'boot-log-line';
    line.innerHTML = `<span>[OK]</span> ${text}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
  };

  try {
    // Stage 1: Checking API
    if (progressFill) progressFill.style.width = '25%';
    if (statusText) statusText.textContent = 'Checking API...';
    await new Promise(r => setTimeout(r, 180));

    const res = await fetch('/api/v1/health');
    const health = res.ok ? await res.json() : null;

    if (res.ok) {
      if (dotApi) dotApi.className = 'status-dot';
      if (textApi) textApi.textContent = 'API Online';
      logStep('API Gateway connected and operational');
    } else {
      if (dotApi) dotApi.className = 'status-dot unavailable';
      if (textApi) textApi.textContent = 'API Unavailable';
    }

    // Stage 2: Connecting database
    if (progressFill) progressFill.style.width = '55%';
    if (statusText) statusText.textContent = 'Connecting database...';
    await new Promise(r => setTimeout(r, 180));

    let isDbOnline = false;
    if (health && health.services) {
      const dbSvc = health.services.find(s => s.id === 'database') || health.services.find(s => s.name?.includes('Database'));
      if (dbSvc && dbSvc.status === 'ONLINE') {
        isDbOnline = true;
        if (dotDb) dotDb.className = 'status-dot';
        if (textDb) textDb.textContent = 'Database Online';
        logStep('MongoDB connection established');
      } else {
        if (dotDb) dotDb.className = 'status-dot unavailable';
        if (textDb) textDb.textContent = 'Database Offline';
      }
    } else {
      if (dotDb) dotDb.className = 'status-dot unavailable';
      if (textDb) textDb.textContent = 'Database Offline';
    }

    // Stage 3: Loading authentication services
    if (progressFill) progressFill.style.width = '80%';
    if (statusText) statusText.textContent = 'Loading authentication services...';
    await new Promise(r => setTimeout(r, 180));
    logStep('Biometric DNN & MFA cryptographic services loaded');

    // Stage 4: Preparing fresh authentication
    if (progressFill) progressFill.style.width = '95%';
    if (statusText) statusText.textContent = 'Preparing secure sign-in...';
    await new Promise(r => setTimeout(r, 180));

    const hasActiveSession = await checkExistingSession();
    if (hasActiveSession) return; // If redirected, keep boot screen visible

    // Environment ready
    if (progressFill) progressFill.style.width = '100%';
    if (statusText) statusText.textContent = 'DeepTrust Environment Ready';
    await new Promise(r => setTimeout(r, 250));

    bootScreen.classList.add('hidden');
  } catch (err) {
    console.warn('[DeepTrust] Boot health check notice:', err);
    if (statusGroup) {
      statusGroup.innerHTML = `
        <span class="status-badge">
          <span class="status-dot unavailable"></span>
          <span>System status unavailable</span>
        </span>
      `;
    }
    if (progressFill) progressFill.style.width = '100%';
    if (statusText) statusText.textContent = 'System status unavailable';
    setTimeout(() => bootScreen.classList.add('hidden'), 400);
  }
}

/* ============================================================
   2. PORTAL SELECTION (Healthcare Organization vs DeepTrust Admin)
   ============================================================ */
function initPortalSelection() {
  const hospitalCard = document.getElementById('portal-card-hospital');
  const adminCard = document.getElementById('portal-card-admin');
  const portalNamePill = document.getElementById('login-portal-name');
  const emailHint = document.getElementById('email-hint');
  const emailInput = document.getElementById('input-email');
  const changePortalBtn = document.getElementById('btn-change-portal');

  const actionTextHospital = document.getElementById('action-text-hospital');
  const actionTextAdmin = document.getElementById('action-text-admin');

  const resetPortalCards = () => {
    if (hospitalCard) hospitalCard.classList.remove('loading');
    if (adminCard) adminCard.classList.remove('loading');
    if (actionTextHospital) {
      actionTextHospital.innerHTML = `
        <span>Continue</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
      `;
    }
    if (actionTextAdmin) {
      actionTextAdmin.innerHTML = `
        <span>Continue</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
      `;
    }
  };

  const registerOption = document.getElementById('deeptrust-register-option');

  // Healthcare option removed per generic requirement
  if (adminCard) {
    adminCard.addEventListener('click', () => {
      adminCard.classList.add('loading');
      if (actionTextAdmin) {
        actionTextAdmin.innerHTML = `<span>Preparing DeepTrust secure session...</span>`;
      }
      currentSelectedAccessType = 'DEEPTRUST_OWNER';
      if (portalNamePill) portalNamePill.textContent = 'DeepTrust Security Console';
      if (emailHint) emailHint.textContent = 'Enter official admin email';
      if (emailInput) {
        emailInput.placeholder = 'admin@deeptrust.com';
        emailInput.value = '';
      }
      if (registerOption) registerOption.style.display = 'block';

      setTimeout(() => {
        switchAuthView('login');
      }, 300);
    });
  }

  if (changePortalBtn) {
    changePortalBtn.addEventListener('click', () => {
      resetPortalCards();
      switchAuthView('portal-select');
    });
  }
}

/* ============================================================
   3. PASSWORD UX (Show/Hide Toggle with SVG Vectors)
   ============================================================ */
function initPasswordUx() {
  const toggleBtn = document.getElementById('btn-toggle-password');
  const passInput = document.getElementById('input-password');

  if (toggleBtn && passInput) {
    toggleBtn.addEventListener('click', () => {
      if (passInput.type === 'password') {
        passInput.type = 'text';
        toggleBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/>
          </svg>
        `;
      } else {
        passInput.type = 'password';
        toggleBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        `;
      }
    });
  }
}

/* ============================================================
   4. AUTH VIEW NAVIGATION
   ============================================================ */
function initAuthNavigation() {
  document.querySelectorAll('[data-switch-view]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = btn.getAttribute('data-switch-view');
      switchAuthView(target);
    });
  });
}

function switchAuthView(viewId) {
  document.querySelectorAll('.auth-view').forEach(v => {
    v.classList.remove('active', 'motion-enter');
  });

  const target = document.getElementById(`view-${viewId}`);
  if (target) {
    target.classList.add('active');
    target.classList.add('motion-enter');
    window.DeepTrustMotion?.enter(target);
  }

  if (typeof syncPipelineStep === 'function') {
    if (viewId === 'login' || viewId === 'portal-select' || viewId === 'admin-register' || viewId === 'email-verify') {
      syncPipelineStep(1);
    } else if (viewId === 'verify') {
      syncPipelineStep(2);
    } else if (viewId === 'voice' || viewId === 'voice-recovery') {
      syncPipelineStep(4);
    } else if (viewId === 'mfa') {
      syncPipelineStep(5);
    } else if (viewId === 'complete') {
      syncPipelineStep(7);
    }
  }

  updateSessionIdentityHeader();

  if (viewId === 'verify') {
    startVerificationPipeline();
  } else {
    stopCameraFeed();
  }

  if (viewId === 'voice') {
    loadVoiceChallenge();
  } else {
    stopAudioRecording();
  }
}

function updateSessionIdentityHeader() {
  const user = getActiveUser();
  document.querySelectorAll('.session-user-name').forEach(el => {
    el.textContent = user.full_name || 'Administrator';
  });
  document.querySelectorAll('.session-user-role').forEach(el => {
    el.textContent = user.email || '';
  });
  document.querySelectorAll('.session-org-badge').forEach(el => {
    el.textContent = user.organization_name || (user.role === 'DEEPTRUST_ADMIN' ? 'DeepTrust' : 'Unknown Organization');
  });
  const mfaEmailEl = document.getElementById('mfa-email-display');
  if (mfaEmailEl && user.email) {
    mfaEmailEl.textContent = `Enter the 6-digit verification code shown in Google Authenticator for: ${user.email}`;
  }
}

function getActiveUser() {
  if (window.Session && typeof window.Session.getUser === 'function') {
    const u = window.Session.getUser();
    if (u) return u;
  }
  return {
    full_name: 'Security Admin',
    email: 'admin@local.demo',
    role: 'DEEPTRUST_ADMIN',
    organization_name: 'Unknown Organization'
  };
}

/* ============================================================
   5. OTP INPUTS HANDLING FOR MFA
   ============================================================ */
function initOtpInputs() {
  const otpContainer = document.getElementById('otp-container');
  if (!otpContainer) return;

  const boxes = otpContainer.querySelectorAll('.otp-box');

  boxes.forEach((box, index) => {
    box.addEventListener('input', () => {
      const val = box.value.trim();
      if (val.length >= 1) {
        box.value = val[0];
        if (index < boxes.length - 1) boxes[index + 1].focus();
      }
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && index > 0) {
        boxes[index - 1].focus();
      }
    });

    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
      if (/^\d{6}$/.test(pasteData)) {
        pasteData.split('').forEach((char, i) => {
          if (boxes[i]) boxes[i].value = char;
        });
        boxes[boxes.length - 1].focus();
      }
    });
  });
}

/* ============================================================
   6. STAGE 1: FORM SUBMISSIONS & CREDENTIALS
   ============================================================ */
function initAuthForms() {
  const loginForm = document.getElementById('form-login');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleLoginSubmit();
    });
  }

  const mfaForm = document.getElementById('form-mfa');
  if (mfaForm) {
    mfaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleMfaSubmit();
    });
  }
}

async function handleLoginSubmit() {
  const submitBtn = document.getElementById('btn-submit-login');
  const btnText = document.getElementById('login-btn-text');
  const emailInput = document.getElementById('input-email');
  const passInput = document.getElementById('input-password');

  if (!emailInput || !passInput) return;

  const email = emailInput.value.trim();
  const password = passInput.value.trim();

  if (!email || !password) {
    alert('Please enter your email and password.');
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.classList.add('auth-pending');
    if (btnText) btnText.textContent = 'AUTHENTICATING...';
  }

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email,
        password: password,
        selected_access_type: sessionStorage.getItem('dt_oauth_params') ? 'HOSPITAL_ADMIN' : currentSelectedAccessType
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      if (submitBtn) {
        submitBtn.classList.remove('auth-pending');
        submitBtn.classList.add('auth-success');
      }
      if (btnText) btnText.textContent = '✓ CREDENTIALS VERIFIED';
      if (data.session_id) currentSessionId = data.session_id;
      currentVerificationToken = data.verification_token || data.token;

      if (window.Session && typeof window.Session.setVerification === 'function') {
        window.Session.setVerification(data.session_id, currentVerificationToken, data.user);
      }

      setTimeout(() => {
        switchAuthView('verify');
      }, 600);
    } else {
      alert(data.detail || data.message || 'Incorrect email or password.');
    }
  } catch (err) {
    alert('Authentication server unavailable. Ensure FastAPI is running on port 8000.');
  } finally {
    if (submitBtn && (!btnText || btnText.textContent.indexOf('VERIFIED') === -1)) {
      submitBtn.disabled = false;
      submitBtn.classList.remove('auth-pending', 'auth-success');
      if (btnText) btnText.textContent = 'Authenticate Credentials';
    }
  }
}

let faceMeshInstance = null;
let isFaceMeshRunning = false;
let faceMeshAnimationFrame = null;
let faceMeshGeneration = 0;
let faceMeshResultGeneration = null;
let faceMeshSendPending = false;
let faceCanvasCtx = null;
let currentFaceMeshResults = null;
let targetFaceMeshIndices = null;

function initFaceMesh() {
  if (faceMeshInstance) return;
  const instance = new window.FaceMesh({locateFile: (file) => {
    return `https://cdn.jsdelivr.net/npm/@mediapipe/face_mesh/${file}`;
  }});
  instance.setOptions({
    maxNumFaces: 1,
    refineLandmarks: true,
    minDetectionConfidence: 0.5,
    minTrackingConfidence: 0.5
  });
  instance.onResults((results) => {
    if (!isFaceMeshRunning || faceMeshResultGeneration !== faceMeshGeneration) return;
    currentFaceMeshResults = results;
    drawFaceLandmarks();
  });
  faceMeshInstance = instance;
}

function buildTargetFaceIndices() {
  if (targetFaceMeshIndices) return targetFaceMeshIndices;
  const indices = new Set();
  const addPairs = (arr) => {
    if (arr) arr.forEach(pair => { indices.add(pair[0]); indices.add(pair[1]); });
  };
  addPairs(window.FACEMESH_FACE_OVAL);
  addPairs(window.FACEMESH_LEFT_EYE);
  addPairs(window.FACEMESH_RIGHT_EYE);
  addPairs(window.FACEMESH_LEFT_EYEBROW);
  addPairs(window.FACEMESH_RIGHT_EYEBROW);
  addPairs(window.FACEMESH_LIPS);
  [1, 2, 4, 5, 6, 168, 195, 197, 278, 344, 440, 275, 45, 115, 220].forEach(i => indices.add(i));
  targetFaceMeshIndices = Array.from(indices);
  return targetFaceMeshIndices;
}

let dtOffscreenCanvas = null;
let dtOffscreenCtx = null;

function startFaceLandmarkOverlay() {
  if (isFaceMeshRunning) return;
  isFaceMeshRunning = true;
  currentFaceMeshResults = null;
  const generation = ++faceMeshGeneration;
  faceMeshAnimationFrame = requestAnimationFrame(() => faceMeshLoop(generation));
}

async function faceMeshLoop(generation = faceMeshGeneration) {
  if (!isFaceMeshRunning || generation !== faceMeshGeneration) return;
  const video = document.getElementById('webcam-feed');
  if (video && video.readyState >= 2 && !video.paused && video.videoWidth > 0 && video.videoHeight > 0) {
    const canvas = document.getElementById('faceCanvas');
    if (canvas) {
      if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
      }
      // A matching canvas size does not imply a drawing context exists.
      if (!faceCanvasCtx || faceCanvasCtx.canvas !== canvas) faceCanvasCtx = canvas.getContext('2d');
    }
    if (!faceMeshInstance) {
      try { initFaceMesh(); } catch (e) {}
    }
    if (faceMeshInstance && !faceMeshSendPending) {
      faceMeshSendPending = true;
      faceMeshResultGeneration = generation;
      try {
        if (!dtOffscreenCanvas) {
          dtOffscreenCanvas = document.createElement('canvas');
          dtOffscreenCtx = dtOffscreenCanvas.getContext('2d');
        }
        if (dtOffscreenCanvas.width !== video.videoWidth || dtOffscreenCanvas.height !== video.videoHeight) {
          dtOffscreenCanvas.width = video.videoWidth;
          dtOffscreenCanvas.height = video.videoHeight;
        }
        dtOffscreenCtx.drawImage(video, 0, 0, video.videoWidth, video.videoHeight);
        await faceMeshInstance.send({image: dtOffscreenCanvas});
      } catch (e) {
        console.warn('FaceMesh send error:', e);
      } finally {
        faceMeshSendPending = false;
      }
    }
  }
  if (isFaceMeshRunning && generation === faceMeshGeneration) {
    faceMeshAnimationFrame = requestAnimationFrame(() => faceMeshLoop(generation));
  }
}

function drawFaceLandmarks() {
  if (!faceCanvasCtx) return;
  const canvas = document.getElementById('faceCanvas');
  faceCanvasCtx.clearRect(0, 0, canvas.width, canvas.height);

  if (!currentFaceMeshResults || !currentFaceMeshResults.multiFaceLandmarks || currentFaceMeshResults.multiFaceLandmarks.length === 0) {
    return; // No face
  }

  const landmarks = currentFaceMeshResults.multiFaceLandmarks[0];
  let minX = 1, minY = 1, maxX = 0, maxY = 0;
  landmarks.forEach(lm => {
    if (lm.x < minX) minX = lm.x;
    if (lm.x > maxX) maxX = lm.x;
    if (lm.y < minY) minY = lm.y;
    if (lm.y > maxY) maxY = lm.y;
  });

  const w = canvas.width;
  const h = canvas.height;
  const boxX = minX * w;
  const boxY = minY * h;
  const boxW = (maxX - minX) * w;
  const boxH = (maxY - minY) * h;
  const padding = 20;

  const isActiveMatch = (typeof isIdentityMatched !== 'undefined' && isIdentityMatched);
  const colorHex = isActiveMatch ? '#10b981' : '#60A5FA';
  const colorRgba = isActiveMatch ? 'rgba(16, 185, 129, 0.8)' : 'rgba(96, 165, 250, 0.8)';

  // Draw bounding box
  faceCanvasCtx.strokeStyle = colorHex;
  faceCanvasCtx.lineWidth = 2;
  faceCanvasCtx.beginPath();
  faceCanvasCtx.rect(boxX - padding, boxY - padding, boxW + padding*2, boxH + padding*2);
  faceCanvasCtx.stroke();

  // Draw dots for the FULL face
  faceCanvasCtx.fillStyle = colorRgba;
  landmarks.forEach(lm => {
    faceCanvasCtx.beginPath();
    faceCanvasCtx.arc(lm.x * w, lm.y * h, 1.5, 0, 2 * Math.PI);
    faceCanvasCtx.fill();
  });
}

/* ============================================================
   7. STAGE 2: REAL OPENCV FACIAL RECOGNITION & LIVENESS
   ============================================================ */
async function startVerificationPipeline() {
  resetFaceState();
  const sessionId = currentSessionId;
  if (await loadBiometricSetup()) return;
  if (sessionId !== currentSessionId || !document.getElementById('view-verify')?.classList.contains('active')) return;
  try {
    initFaceMesh();
  } catch (err) {
    console.warn('[DeepTrust] FaceMesh initialization delayed or failed:', err);
  }
  const enableCamBtn = document.getElementById('btn-enable-camera');
  if (enableCamBtn) {
    enableCamBtn.onclick = requestCameraAccess;
  }
  requestCameraAccess();
}

function setBiometricSetupDisplay(active) {
  const view = document.getElementById('view-verify');
  for (const selector of ['.camera-container', '.verification-checks-grid']) {
    const element = view?.querySelector(selector);
    if (element) element.style.display = active ? 'none' : '';
  }
}

function showBiometricSetupServiceError(message) {
  if ((getActiveUser()?.email || '').toLowerCase() !== 'admin@novacaremedical.org') return false;
  const form = document.getElementById('form-biometric-setup');
  if (!form) return false;
  form.style.display = 'block';
  setBiometricSetupDisplay(true);
  const status = document.getElementById('biometric-setup-message');
  const code = document.getElementById('input-biometric-setup-code');
  const button = document.getElementById('btn-biometric-setup');
  if (status) status.textContent = message;
  if (code) { code.value = ''; code.disabled = true; }
  if (button) { button.disabled = true; button.textContent = 'Setup Service Unavailable'; }
  form.onsubmit = event => event.preventDefault();
  return true;
}

async function loadBiometricSetup() {
  const form = document.getElementById('form-biometric-setup');
  if (!form) return;
  form.style.display = 'none';
  const code = document.getElementById('input-biometric-setup-code');
  const button = document.getElementById('btn-biometric-setup');
  if (code) code.disabled = false;
  if (button) { button.disabled = false; button.textContent = 'Set Up My Face and Voice'; }
  setBiometricSetupDisplay(false);
  const sessionId = currentSessionId;
  try {
    const res = await fetch('/api/v1/face/setup/status', {
      method: 'POST', headers: voiceHeaders(), body: JSON.stringify({session_id: sessionId})
    });
    const data = await res.json();
    if (sessionId !== currentSessionId) return;
    if (!res.ok) {
      const reason = res.status === 404
        ? 'The running DeepTrust service has not loaded one-time setup. Run RESTART_INTEGRATION_FIX.bat from the official DeepTrust folder, then reload this page.'
        : (typeof data.detail === 'string' ? data.detail : data.message) || 'Setup service unavailable. Restart DeepTrust, then sign in again.';
      return showBiometricSetupServiceError(reason);
    }
    if (!data.available || data.authorized) return;
    form.style.display = 'block';
    setBiometricSetupDisplay(true);
    form.onsubmit = authorizeBiometricSetup;
    return true;
  } catch (err) {
    if (sessionId !== currentSessionId) return;
    return showBiometricSetupServiceError('Setup service could not be reached. Check DeepTrust is running, then reload this page.');
  }
}

async function authorizeBiometricSetup(event) {
  event.preventDefault();
  const code = document.getElementById('input-biometric-setup-code');
  const message = document.getElementById('biometric-setup-message');
  const button = document.getElementById('btn-biometric-setup');
  if (!code || !button || button.disabled) return;
  if (!/^[0-9]{6}$/.test(code.value.trim())) {
    if (message) message.textContent = 'Enter your current 6-digit Google Authenticator code.';
    return;
  }
  button.disabled = true;
  const sessionId = currentSessionId;
  stopCameraFeed();
  resetFaceState();
  try {
    const res = await fetch('/api/v1/face/setup/authorize', {
      method: 'POST', headers: voiceHeaders(),
      body: JSON.stringify({session_id: sessionId, code: code.value.trim()})
    });
    const data = await res.json();
    code.value = '';
    if (sessionId !== currentSessionId) return;
    if (!res.ok || !data.success) throw new Error(data.detail || data.message || 'Setup authorization unavailable.');
    document.getElementById('form-biometric-setup').style.display = 'none';
    setBiometricSetupDisplay(false);
    if (message) message.textContent = '';
    await requestCameraAccess();
  } catch (err) {
    if (sessionId === currentSessionId && message) message.textContent = err.message;
  } finally {
    button.disabled = false;
  }
}

function resetFaceState() {
  faceVerificationEpoch++;
  faceStableCounter = 0;
  faceMissingCounter = 0;
  isIdentityMatched = false;
  isLivenessVerified = false;
  isMatching = false;
  isEnrolling = false;
  isLivenessChecking = false;
  currentLivenessChallenge = null;

  updateCheckCard('check-face-presence', 'waiting', 'Waiting');
  updateCheckCard('check-identity-match', 'waiting', 'Waiting');
  updateCheckCard('check-liveness', 'waiting', 'Waiting');

  const bbox = document.getElementById('face-bounding-box');
  if (bbox) bbox.className = 'face-bounding-box';

  const badge = document.getElementById('camera-status-badge');
  if (badge) {
    badge.className = 'camera-status-badge';
    badge.textContent = 'Camera Ready — Waiting for Face';
  }

  const challengeBox = document.getElementById('liveness-challenge-box');
  if (challengeBox) challengeBox.classList.remove('visible');

  const continueBtn = document.getElementById('btn-continue-voice');
  if (continueBtn) continueBtn.style.display = 'none';

  const enrollBtn = document.getElementById('btn-enroll-face');
  if (enrollBtn) enrollBtn.style.display = 'none';
}

async function requestCameraAccess() {
  resetFaceState();
  const permBox = document.getElementById('camera-permission-box');
  const video = document.getElementById('webcam-feed');
  const badge = document.getElementById('camera-status-badge');

  if (badge) {
    badge.className = 'camera-status-badge';
    badge.textContent = 'Requesting camera permission...';
  }

  try {
    const engineHealth = await fetch('/api/v1/face/health', {cache: 'no-store'});
    const engineInfo = await engineHealth.json();
    if (!engineHealth.ok || engineInfo.face_pipeline_version !== '2026-10-06.7') {
      if (badge) { badge.className = 'camera-status-badge failed'; badge.textContent = 'AI backend update pending — run RESTART_FACE_FIX.bat, then reload this page.'; }
      if (permBox) {
        permBox.classList.remove('hidden'); permBox.style.display = 'flex';
        const title = permBox.querySelector('div');
        const desc = permBox.querySelector('p');
        if (title) title.textContent = 'DeepTrust Restart Required';
        if (desc) desc.textContent = 'The previous AI backend is still running. Restart DeepTrust to load the face correction.';
      }
      return;
    }
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: 'user' },
      audio: false
    });

    activeMediaStream = stream;
    if (video) {
      video.srcObject = stream;
      await new Promise(resolve => {
        if (video.readyState >= 1) return resolve();
        video.onloadedmetadata = () => resolve();
      });
      await video.play();
    }

    if (permBox) {
      permBox.classList.add('hidden');
      permBox.style.display = 'none';
    }
    if (badge) {
      badge.className = 'camera-status-badge verified';
      badge.textContent = 'Camera Ready — Positioning Face...';
    }

    if (detectionInterval) clearInterval(detectionInterval);
    detectionInterval = setInterval(processCameraFrame, 250);

    startFaceLandmarkOverlay();

  } catch (err) {
    console.warn('[DeepTrust Camera] Access Notice:', err.name, err.message);
    const isDenied = err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError';

    if (permBox) {
      permBox.classList.remove('hidden');
      permBox.style.display = 'flex';
      
      const titleEl = permBox.querySelector('div[style*="font-weight:700"]');
      const descEl = permBox.querySelector('p');
      const camBtn = document.getElementById('btn-enable-camera');

      if (titleEl) {
        titleEl.textContent = isDenied ? 'Camera Permission Required' : 'Camera Unavailable';
      }
      if (descEl) {
        descEl.textContent = isDenied
          ? 'Camera access is required for face verification. Please allow camera permissions in your browser bar.'
          : 'Could not access optical camera. Hardware may be unplugged, busy, or blocked.';
      }
      if (camBtn) {
        camBtn.textContent = 'Retry Camera';
        camBtn.onclick = requestCameraAccess;
      }
    }

    if (badge) {
      badge.className = 'camera-status-badge failed';
      badge.textContent = isDenied ? 'Permission Denied' : 'Camera Unavailable';
    }
  }
}

function stopCameraFeed() {
  isFaceMeshRunning = false;
  faceMeshGeneration++;
  if (faceMeshAnimationFrame !== null) cancelAnimationFrame(faceMeshAnimationFrame);
  faceMeshAnimationFrame = null;
  currentFaceMeshResults = null;
  if (faceCanvasCtx) {
    const canvas = document.getElementById('faceCanvas');
    if (canvas) faceCanvasCtx.clearRect(0, 0, canvas.width, canvas.height);
  }
  faceCanvasCtx = null;
  if (detectionInterval) {
    clearInterval(detectionInterval);
    detectionInterval = null;
  }
  if (activeMediaStream) {
    try {
      activeMediaStream.getTracks().forEach(track => track.stop());
    } catch (e) {}
    activeMediaStream = null;
  }
  const video = document.getElementById('webcam-feed');
  if (video) {
    video.srcObject = null;
  }
}

function captureVideoFrameAsBase64() {
  const video = document.getElementById('webcam-feed');
  if (!video || video.readyState < 2 || !video.videoWidth || !video.videoHeight) return null;

  const canvas = document.createElement('canvas');
  canvas.width = Math.min(video.videoWidth, 960);
  canvas.height = Math.round(canvas.width * (video.videoHeight / video.videoWidth));
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL('image/jpeg', 0.85);
}

async function processCameraFrame() {
  if (isProcessingFrame || isLivenessVerified) return;

  const frameBase64 = captureVideoFrameAsBase64();
  if (!frameBase64) return;

  isProcessingFrame = true;

  try {
    // Liveness already checks phone presentation, face count and identity.
    // Avoid running another detector before every challenge observation.
    if (isIdentityMatched && currentLivenessChallenge) {
      await performLivenessStep(frameBase64);
      return;
    }
    const res = await fetch('/api/v1/face/detect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ image: frameBase64, session_id: currentSessionId })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.message || 'Face detection service unavailable');
    await handleDetectionResult(data, frameBase64);

  } catch (err) {
    const badge = document.getElementById('camera-status-badge');
    if (badge) { badge.className = 'camera-status-badge warning'; badge.textContent = 'Camera verification service unavailable — retrying connection'; }
  } finally {
    isProcessingFrame = false;
  }
}

async function handleDetectionResult(data, currentFrameBase64) {
  const bbox = document.getElementById('face-bounding-box');
  const badge = document.getElementById('camera-status-badge');

  if (data.status === 'PHONE_DETECTED') {
    faceVerificationEpoch++;
    faceStableCounter = 0;
    isIdentityMatched = false;
    isLivenessVerified = false;
    currentLivenessChallenge = null;
    if (badge) { badge.className = 'camera-status-badge failed'; badge.textContent = data.message; }
    updateCheckCard('check-face-presence', 'failed', 'Phone detected');
    updateCheckCard('check-identity-match', 'failed', 'Photo face blocked');
    updateCheckCard('check-liveness', 'failed', 'Phone presentation blocked');
    const continueBtn = document.getElementById('btn-continue-voice');
    if (continueBtn) continueBtn.style.display = 'none';
    const enrollBtn = document.getElementById('btn-enroll-face');
    if (enrollBtn) enrollBtn.style.display = 'none';
    return;
  }

  if (data.status === 'NO_FACE') {
    faceStableCounter = 0;
    faceMissingCounter++;
    if (badge) {
      badge.className = 'camera-status-badge warning';
      badge.textContent = faceMissingCounter < 4 ? 'Tracking your face — hold steady' : 'Face not visible clearly — look straight at the camera';
    }
    updateCheckCard('check-face-presence', 'waiting', faceMissingCounter < 4 ? 'Tracking...' : 'Face unclear');
    if (isIdentityMatched && currentLivenessChallenge && !isLivenessChecking) await performLivenessStep(currentFrameBase64);
    return;
  }

  if (data.status === 'MULTIPLE_FACES') {
    faceStableCounter = 0;
    if (badge) {
      badge.className = 'camera-status-badge failed';
      badge.textContent = 'Multiple faces detected — Only one allowed';
    }
    updateCheckCard('check-face-presence', 'failed', 'Multiple Faces');
    if (isIdentityMatched && currentLivenessChallenge && !isLivenessChecking) await performLivenessStep(currentFrameBase64);
    return;
  }

  if (data.status === 'ONE_FACE' && data.bounding_box) {
    faceMissingCounter = 0;
    lastFaceBoundingBox = data.bounding_box;
    // Note: Bounding box rendering is handled by the local FaceMesh layer now
    if (badge && !isIdentityMatched) {
      badge.className = 'camera-status-badge detected';
      badge.textContent = 'Face detected — Aligning biometrics';
    }

    faceStableCounter++;

    if (faceStableCounter >= 2) {
      updateCheckCard('check-face-presence', 'verified', 'Verified ✓');

      if (!isIdentityMatched && !isMatching && !isEnrolling) {
        await performIdentityMatch(currentFrameBase64);
      } else if (isIdentityMatched && !isLivenessVerified && !isLivenessChecking) {
        await performLivenessStep(currentFrameBase64);
      }
    }
  }
}

async function performIdentityMatch(frameBase64) {
  if (isMatching || isIdentityMatched) return;
  isMatching = true;
  const verificationEpoch = faceVerificationEpoch;

  const user = getActiveUser();
  updateCheckCard('check-identity-match', 'checking', 'Matching...');

  try {
    const res = await fetch('/api/v1/face/match', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: user.id || user.email || 'admin@local.demo',
        image: frameBase64,
        session_id: currentSessionId
      })
    });

    const data = await res.json();
    const badge = document.getElementById('camera-status-badge');
    if (verificationEpoch !== faceVerificationEpoch) return;

    if (data.status === 'MATCH') {
      isIdentityMatched = true;
      if (badge) {
        badge.className = 'camera-status-badge verified';
        badge.textContent = 'Face matched — verifying live face';
      }
      updateCheckCard('check-identity-match', 'verified', 'Verified ✓');
      await initiateLivenessChallenge();
    } else if (data.status === 'FACE_PROFILE_NOT_ENROLLED' || data.status === 'NOT_ENROLLED') {
      if (badge) {
        badge.className = 'camera-status-badge action-required';
        badge.textContent = 'Face Not Enrolled — Setup Required';
      }
      updateCheckCard('check-identity-match', 'action-required', 'Not Enrolled');
      showEnrollOption('Set Up Face Verification');
    } else if (data.status === 'FACE_MISMATCH' || data.status === 'NO_MATCH') {
      updateCheckCard('check-identity-match', 'failed', 'Mismatch');
      if (badge) {
        badge.className = 'camera-status-badge failed';
        badge.textContent = 'Wrong face detected — does not match your saved face';
      }
      const enrollBtn = document.getElementById('btn-enroll-face');
      if (enrollBtn) enrollBtn.style.display = 'none';
    } else if (data.status === 'NO_FACE') {
      updateCheckCard('check-identity-match', 'waiting', 'No Face');
    } else if (data.status === 'MULTIPLE_FACES') {
      updateCheckCard('check-identity-match', 'failed', 'Multiple Faces');
    } else if (data.status === 'FACE_PROFILE_UNAVAILABLE' || data.status === 'PHONE_DETECTED') {
      updateCheckCard('check-identity-match', 'failed', data.status === 'PHONE_DETECTED' ? 'Phone detected' : 'Saved profile unavailable');
      if (badge) { badge.className = 'camera-status-badge failed'; badge.textContent = data.message; }
      const enrollBtn = document.getElementById('btn-enroll-face');
      if (enrollBtn) enrollBtn.style.display = 'none';
    }
  } catch (err) {
    console.error('Match error:', err);
  } finally {
    isMatching = false;
  }
}

async function enrollFaceWithSamples() {
  if (isEnrolling) return;
  isEnrolling = true;
  const user = getActiveUser();
  const badge = document.getElementById('camera-status-badge');
  const enrollBtn = document.getElementById('btn-enroll-face');

  if (enrollBtn) {
    enrollBtn.disabled = true;
    enrollBtn.textContent = '⏳ Position face inside frame & look at camera...';
  }
  if (badge) {
    badge.className = 'camera-status-badge detected';
    badge.textContent = 'Capturing face samples (0/3)...';
  }
  updateCheckCard('check-identity-match', 'checking', 'Capturing Samples...');

  // Capture 4 samples with 700ms spacing for meaningful angle variation
  const samples = [];
  for (let i = 0; i < 4; i++) {
    const frame = captureVideoFrameAsBase64();
    if (frame) {
      samples.push(frame);
    }
    if (badge) {
      badge.textContent = `Capturing multi-angle face samples (${Math.min(i + 1, 3)}/3)...`;
    }
    await new Promise(r => setTimeout(r, 700));
  }

  if (samples.length < 2) {
    if (badge) {
      badge.className = 'camera-status-badge failed';
      badge.textContent = 'Could not capture sufficient frames from camera';
    }
    updateCheckCard('check-identity-match', 'failed', 'Capture Failed');
    if (enrollBtn) {
      enrollBtn.disabled = false;
      enrollBtn.textContent = 'Set Up Face Verification';
    }
    isEnrolling = false;
    return;
  }

  try {
    if (badge) badge.textContent = 'Creating biometric profile...';
    const res = await fetch('/api/v1/face/enroll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: user.id || user.email || 'admin@local.demo',
        images: samples,
        organization_name: user.organization_name || 'Unknown Organization',
        session_id: currentSessionId
      })
    });

    const d = await res.json();
    if (res.ok && (d.success || d.status === 'ENROLLED')) {
      if (badge) {
        badge.className = 'camera-status-badge detected';
        badge.textContent = 'Enrollment complete — confirming identity match...';
      }
      updateCheckCard('check-identity-match', 'checking', 'Confirming Match...');
      if (enrollBtn) enrollBtn.style.display = 'none';

      // SECURITY: Enrollment alone does NOT pass identity verification.
      // We must run a real backend /face/match call to confirm the live
      // camera face matches the newly enrolled template. This prevents a
      // scenario where someone else enrolls and the original user gets
      // auto-verified, or any enrollment-skip exploit.
      await new Promise(r => setTimeout(r, 300)); // short pause for DB write to settle
      const verifyFrame = captureVideoFrameAsBase64();
      if (!verifyFrame) {
        if (badge) {
          badge.className = 'camera-status-badge failed';
          badge.textContent = 'Could not capture verification frame after enrollment';
        }
        updateCheckCard('check-identity-match', 'failed', 'Verify Failed');
        if (enrollBtn) { enrollBtn.disabled = false; enrollBtn.style.display = 'block'; enrollBtn.textContent = 'Retry Enrollment'; }
        isEnrolling = false;
        return;
      }

      const matchRes = await fetch('/api/v1/face/match', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: user.id || user.email || 'admin@local.demo',
          image: verifyFrame,
          session_id: currentSessionId
        })
      });
      const matchData = await matchRes.json();

      if (matchData.status === 'MATCH' && matchData.matched) {
        // Backend confirmed: live face matches enrolled template
        isIdentityMatched = true;
        if (badge) {
          badge.className = 'camera-status-badge verified';
          badge.textContent = 'Identity Enrolled & Verified ✓';
        }
        updateCheckCard('check-identity-match', 'verified', 'Enrolled & Verified ✓');
        initiateLivenessChallenge();
      } else {
        const matchMsg = (matchData && matchData.message) || 'Identity confirmation failed after enrollment.';
        if (badge) {
          badge.className = 'camera-status-badge failed';
          badge.textContent = matchMsg;
        }
        updateCheckCard('check-identity-match', 'failed', 'Confirm Failed');
        if (enrollBtn) {
          enrollBtn.disabled = false;
          enrollBtn.style.display = 'block';
          enrollBtn.textContent = 'Retry Face Enrollment';
        }
      }
    } else {
      if (badge) {
        badge.className = 'camera-status-badge failed';
        badge.textContent = d.message || 'Face Enrollment Failed';
      }
      updateCheckCard('check-identity-match', 'failed', d.status || 'Enroll Failed');
      if (enrollBtn) {
        enrollBtn.disabled = false;
        enrollBtn.textContent = 'Retry Face Enrollment';
      }
    }
  } catch (e) {
    console.error('Enroll error:', e);
    if (badge) {
      badge.className = 'camera-status-badge failed';
      badge.textContent = 'Network error during enrollment';
    }
    if (enrollBtn) {
      enrollBtn.disabled = false;
      enrollBtn.textContent = 'Retry Face Enrollment';
    }
  } finally {
    isEnrolling = false;
  }
}

function showEnrollOption(label = 'Set Up Face Verification') {
  const enrollBtn = document.getElementById('btn-enroll-face');
  if (!enrollBtn) return;

  enrollBtn.style.display = 'block';
  enrollBtn.textContent = label;
  enrollBtn.onclick = async () => {
    await enrollFaceWithSamples();
  };
}

async function initiateLivenessChallenge() {
  if (currentLivenessChallenge || initiateLivenessChallenge.pendingEpoch === faceVerificationEpoch) return;
  initiateLivenessChallenge.pendingEpoch = faceVerificationEpoch;
  const verificationEpoch = faceVerificationEpoch;
  updateCheckCard('check-liveness', 'action-required', 'Action Required');

  try {
    const res = await fetch('/api/v1/liveness/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentSessionId })
    });

    const data = await res.json();
    if (verificationEpoch !== faceVerificationEpoch) return;
    if (!res.ok || !data.challenge) throw new Error(data.detail || data.message || 'Liveness service unavailable. Retry face verification.');
    currentLivenessChallenge = data.challenge;

    const challengeBox = document.getElementById('liveness-challenge-box');
    const challengeText = document.getElementById('liveness-challenge-text');
    if (challengeBox && challengeText) {
      challengeText.textContent = data.instruction || 'Look straight at the camera';
      challengeBox.classList.add('visible');
    }
  } catch (err) {
    if (verificationEpoch !== faceVerificationEpoch) return;
    currentLivenessChallenge = null;
    isIdentityMatched = false;
    isLivenessVerified = false;
    updateCheckCard('check-liveness', 'failed', 'Retry required');
    updateCheckCard('check-identity-match', 'action-required', 'Recheck required');
    const message = err.message || 'Liveness service unavailable. Retry face verification.';
    stopCameraFeed();
    const badge = document.getElementById('camera-status-badge');
    if (badge) { badge.className = 'camera-status-badge failed'; badge.textContent = message; }
    const continueBtn = document.getElementById('btn-continue-voice');
    if (continueBtn) continueBtn.style.display = 'none';
    const placeholder = document.getElementById('camera-permission-box');
    if (placeholder) {
      placeholder.classList.remove('hidden'); placeholder.style.display = 'flex';
      const title = placeholder.querySelector('div');
      const description = placeholder.querySelector('p');
      if (title) title.textContent = 'Face Verification Needs Retry';
      if (description) description.textContent = message;
    }
    const retry = document.getElementById('btn-enable-camera');
    if (retry) { retry.textContent = 'Retry Live Face Verification'; retry.onclick = requestCameraAccess; }
  } finally {
    if (initiateLivenessChallenge.pendingEpoch === verificationEpoch) {
      initiateLivenessChallenge.pendingEpoch = null;
    }
  }
}

async function performLivenessStep(frameBase64) {
  if (isLivenessChecking || isLivenessVerified || !currentLivenessChallenge) return;
  isLivenessChecking = true;
  const verificationEpoch = faceVerificationEpoch;

  try {
    const res = await fetch('/api/v1/liveness/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentSessionId, image: frameBase64 })
    });

    const data = await res.json();
    const instructionEl = document.getElementById('liveness-challenge-text');
    if (verificationEpoch !== faceVerificationEpoch) return;
    if (instructionEl && (data.instruction || data.message)) {
      const progress = data.step && data.steps ? `Step ${data.step}/${data.steps}: ` : '';
      instructionEl.textContent = progress + (data.instruction || data.message);
    }
    if (data.face_visible === false) updateCheckCard('check-face-presence', 'waiting', 'Keep face visible');
    else if (data.face_visible === true) updateCheckCard('check-face-presence', 'verified', 'Verified ✓');
    if (!res.ok || data.status === 'LIVENESS_FAILED' || data.status === 'LIVENESS_REQUIRED' || data.status === 'PHONE_DETECTED') {
      isIdentityMatched = false;
      isLivenessVerified = false;
      currentLivenessChallenge = null;
      updateCheckCard('check-liveness', 'failed', 'Live verification failed');
      updateCheckCard('check-identity-match', 'action-required', 'Recheck required');
      const badge = document.getElementById('camera-status-badge');
      if (badge) { badge.className = 'camera-status-badge failed'; badge.textContent = data.message || data.detail || 'Restart face verification'; }
      const continueBtn = document.getElementById('btn-continue-voice');
      if (continueBtn) continueBtn.style.display = 'none';
      // Require an explicit camera restart instead of silently retrying a photo.
      stopCameraFeed();
      const placeholder = document.getElementById('camera-permission-box');
      if (placeholder) {
        placeholder.classList.remove('hidden'); placeholder.style.display = 'flex';
        const title = placeholder.querySelector('div');
        const description = placeholder.querySelector('p');
        if (title) title.textContent = 'Face Verification Needs Retry';
        if (description) description.textContent = 'Your camera permission is available. Retry and follow the live face instructions.';
      }
      const retry = document.getElementById('btn-enable-camera');
      if (retry) { retry.textContent = 'Retry Live Face Verification'; retry.onclick = requestCameraAccess; }
      return;
    }
    if (res.ok && data.status === 'LIVENESS_PASSED') {
      isLivenessVerified = true;
      updateCheckCard('check-liveness', 'verified', 'Verified ✓');

      const badge = document.getElementById('camera-status-badge');
      if (badge) {
        badge.className = 'camera-status-badge verified';
        badge.textContent = 'Facial Biometric & Liveness Verified ✓';
      }

      const challengeBox = document.getElementById('liveness-challenge-box');
      if (challengeBox) challengeBox.classList.remove('visible');

      const continueBtn = document.getElementById('btn-continue-voice');
      if (continueBtn) {
        continueBtn.style.display = 'block';
        continueBtn.onclick = () => {
          stopCameraFeed();
          switchAuthView('voice');
        };
      }

      lastVerifiedFrame = frameBase64;
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        setTimeout(() => {
          if (isLivenessVerified) {
            const verifyView = document.getElementById('view-verify');
            if (verifyView && verifyView.classList.contains('active')) {
              stopCameraFeed();
              switchAuthView('voice');
            }
          }
        }, 1000);
      } else {
        playFaceSuccessAnimation();
      }
    }
  } catch (err) {
    console.error('Liveness step error:', err);
  } finally {
    isLivenessChecking = false;
  }
}

function updateCheckCard(id, state, text) {
  const card = document.getElementById(id);
  if (!card) return;
  const statusEl = card.querySelector('.check-card-status');
  if (statusEl) {
    statusEl.className = `check-card-status ${state}`;
    statusEl.textContent = text;
  }
}

/* ============================================================
   8. STAGE 3: VOICE BIOMETRICS & PHRASE VERIFICATION
   ============================================================ */
function initVoiceVerification() {
  const startVoiceBtn = document.getElementById('btn-start-voice');
  const continueMfaBtn = document.getElementById('btn-continue-mfa');

  if (startVoiceBtn) {
    startVoiceBtn.addEventListener('click', startVoiceRecordingSession);
  }

  if (continueMfaBtn) {
    continueMfaBtn.addEventListener('click', () => {
      stopAudioRecording();
      switchAuthView('mfa');
    });
  }

  initVoiceRecovery();
  document.getElementById('btn-open-voice-recovery')?.addEventListener('click', () => {
    if (voiceBusy) return;
    stopAudioRecording();
    switchAuthView('voice-recovery');
    const panel = document.getElementById('voice-recovery-alternate');
    if (panel?.hidden) document.getElementById('btn-voice-recovery-alternate')?.click();
  });
}

let voiceChallengeId = null;
let voiceChallengePurpose = 'VERIFY';
let voiceRepairAvailable = false;
let voiceRepairAuthorized = false;
let voiceBusy = false;
let finishVoiceCapture = null;

function voiceHeaders() {
  return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${currentVerificationToken || ''}` };
}

function voiceEnrollmentPanel() {
  let panel = document.getElementById('voice-enrollment-panel');
  const button = document.getElementById('btn-start-voice');
  if (!panel && button) {
    panel = document.createElement('p');
    panel.id = 'voice-enrollment-panel';
    panel.className = 'voice-setup-note';
    panel.textContent = 'No saved voice profile found. One live recording will set it up after MFA.';
    button.parentNode.insertBefore(panel, button);
  }
  if (panel) {
    panel.hidden = voiceChallengePurpose !== 'ENROLL';
    if (voiceRepairAuthorized) panel.textContent = 'Record one fresh live command. Your previous profile is preserved until final MFA.';
  }
}

async function loadVoiceChallenge() {
  const phraseEl = document.getElementById('voice-phrase-text');
  currentVoiceChallenge = null; voiceChallengeId = null;
  try {
    const user = getActiveUser();
    const res = await fetch('/api/v1/voice/challenge', { method: 'POST', headers: voiceHeaders(),
      body: JSON.stringify({ session_id: currentSessionId, user_id: user.id || user.email }) });
    const data = await res.json();
    if (!res.ok) {
      const detail = data.detail || {};
      if (detail.recovery_required) { switchAuthView('voice-recovery'); return false; }
      throw new Error(typeof detail === 'string' ? detail : detail.message || 'Could not load a new phrase.');
    }
    if (!data.challenge_id || data.mfa_required) throw new Error('Restart DeepTrust to load the simplified voice setup.');
    currentVoiceChallenge = data.challenge_phrase;
    voiceChallengeId = data.challenge_id;
    voiceChallengePurpose = data.purpose;
    voiceRepairAvailable = data.repair_available === true;
    voiceRepairAuthorized = data.repair_authorized === true;
    const recoveryLink = document.getElementById('btn-open-voice-recovery');
    if (recoveryLink) recoveryLink.textContent = voiceRepairAvailable
      ? 'Re-setup voice with Google Authenticator' : 'Voice not working? Use account recovery';
    voiceEnrollmentPanel();
    if (phraseEl) phraseEl.textContent = `"${currentVoiceChallenge}"`;
    const btn = document.getElementById('btn-start-voice');
    if (btn) btn.textContent = voiceChallengePurpose === 'ENROLL'
      ? 'Record Voice Command' : 'Verify Voice';
    return true;
  } catch (error) {
    if (phraseEl) phraseEl.textContent = error.message;
    return false;
  }
}

async function startVoiceRecordingSession() {
  if (voiceBusy) { finishVoiceCapture?.(); return; }
  voiceBusy = true;
  const btn = document.getElementById('btn-start-voice');
  const badge = document.getElementById('voice-status-badge');
  const orb = document.getElementById('voice-mic-orb');
  const container = document.getElementById('voice-visualizer-container');
  let recorder, waveAnimation;
  const status = (text, kind = 'detected') => {
    if (badge) { badge.textContent = text; badge.className = `camera-status-badge ${kind}`; }
  };
  try {
    isVoiceVerified = false;
    const continueBtn = document.getElementById('btn-continue-mfa');
    if (continueBtn) continueBtn.style.display = 'none';
    if (!await loadVoiceChallenge()) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Opening microphone...'; }
    audioStream = await navigator.mediaDevices.getUserMedia({
      audio: { channelCount: { ideal: 1 }, echoCancellation: false, noiseSuppression: false, autoGainControl: false }, video: false
    });
    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    audioAnalyser = audioContext.createAnalyser();
    audioContext.createMediaStreamSource(audioStream).connect(audioAnalyser);
    audioAnalyser.fftSize = 64;
    const canvas = document.getElementById('voice-waveform-canvas');
    if (canvas) {
      const ctx = canvas.getContext('2d');
      const levels = new Uint8Array(audioAnalyser.frequencyBinCount);
      const draw = () => {
        audioAnalyser.getByteFrequencyData(levels);
        ctx.clearRect(0, 0, canvas.width, canvas.height); ctx.fillStyle = '#60a5fa';
        levels.forEach((v, i) => { const height = Math.max(2, v / 255 * canvas.height);
          ctx.fillRect(i * canvas.width / levels.length, (canvas.height - height) / 2, canvas.width / levels.length - 2, height); });
        waveAnimation = requestAnimationFrame(draw);
      };
      draw();
    }
    recorder = new MediaRecorder(audioStream);
    const chunks = [];
    recorder.ondataavailable = event => { if (event.data.size) chunks.push(event.data); };
    const recordingDone = new Promise((resolve, reject) => {
      recorder.onstop = () => resolve(new Blob(chunks, { type: recorder.mimeType }));
      recorder.onerror = () => reject(new Error('Microphone recording failed. Retry.'));
    });
    if (audioContext?.state === 'suspended') await audioContext.resume();
    recorder.start(); orb?.classList.add('recording');
    const microphoneName = audioStream.getAudioTracks?.()[0]?.label;
    status(`Stay quiet for one second: measuring background sound.${microphoneName ? ' Mic: ' + microphoneName : ''}`);
    if (btn) btn.textContent = 'Stay quiet...';
    await new Promise(resolve => setTimeout(resolve, 1000));
    status('Read the short phrase. Tap Finish Recording when done.');
    if (btn) btn.textContent = 'Recording live voice...';
    await new Promise(resolve => {
      let finished = false, maximumTimer, enableTimer;
      const finish = () => {
        if (finished) return;
        finished = true; clearTimeout(maximumTimer); clearTimeout(enableTimer);
        finishVoiceCapture = null;
        if (btn) btn.disabled = true;
        resolve();
      };
      maximumTimer = setTimeout(finish, 9000);
      enableTimer = setTimeout(() => {
        if (finished) return;
        finishVoiceCapture = finish;
        if (btn) { btn.disabled = false; btn.textContent = 'Finish Recording'; }
      }, 2500);
    });
    if (recorder.state === 'recording') recorder.stop();
    const blob = await recordingDone;
    if (waveAnimation) cancelAnimationFrame(waveAnimation);
    waveAnimation = null; stopAudioRecording();
    if (!document.getElementById('view-voice')?.classList.contains('active')) return;
    status('Checking your voice command and live audio...');
    container?.classList.add('voice-state-processing');
    if (btn) btn.textContent = 'Analyzing voice...';
    const audio = await new Promise((resolve, reject) => {
      const reader = new FileReader(); reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('Could not read recorded audio.')); reader.readAsDataURL(blob);
    });
    const user = getActiveUser();
    const enrolling = voiceChallengePurpose === 'ENROLL';
    const res = await fetch(enrolling ? '/api/v1/voice/enroll' : '/api/v1/voice/verify', {
      method: 'POST', headers: voiceHeaders(), body: JSON.stringify({ session_id: currentSessionId,
        user_id: user.id || user.email, challenge_id: voiceChallengeId, audio_data: audio })
    });
    currentVoiceChallenge = null; voiceChallengeId = null;
    const data = await res.json();
    if (!res.ok) {
      const detail = data.detail || {};
      const heard = detail.code === 'PHRASE_MISMATCH' && detail.recognized_command
        ? ` Heard: "${detail.recognized_command}".` : '';
      if (detail.recovery_required) { status((detail.message || 'Voice check failed.') + heard, 'warning'); switchAuthView('voice-recovery'); return; }
      throw new Error((typeof detail === 'string' ? detail : detail.message || 'Voice check failed. Retry the command.') + heard);
    }
    if ((data.status === 'VERIFIED' && data.matched === true) || (data.status === 'ENROLLED' && data.matched === false)) {
      isVoiceVerified = true;
      status(data.status === 'ENROLLED' ? data.message : 'Live voice matched your saved profile.', 'verified');
      if (btn) btn.style.display = 'none';
      if (continueBtn) continueBtn.style.display = 'block';
    } else if (data.status === 'ENROLLING') {
      status(data.message, 'detected');
      await loadVoiceChallenge();
    } else throw new Error('Voice verification was not completed.');
  } catch (error) {
    status(error.name === 'NotAllowedError' ? 'Allow microphone access and retry.' : error.message, 'warning');
    if (btn) btn.textContent = 'Retry Voice Command';
  } finally {
    if (recorder?.state === 'recording') recorder.stop();
    if (waveAnimation) cancelAnimationFrame(waveAnimation);
    stopAudioRecording(); orb?.classList.remove('recording');
    container?.classList.remove('voice-state-processing');
    if (btn) btn.disabled = false;
    voiceBusy = false;
    finishVoiceCapture = null;
  }
}


function initVoiceRecovery() {
  const form = document.getElementById('form-voice-recovery');
  const alertEl = document.getElementById('voice-recovery-alert');
  const codeInput = document.getElementById('input-voice-recovery-code');
  const alternateButton = document.getElementById('btn-voice-recovery-alternate');
  const alternatePanel = document.getElementById('voice-recovery-alternate');
  const alternateSubmit = document.getElementById('btn-voice-recovery-alternate-submit');
  const alternateAlert = document.getElementById('voice-recovery-alternate-alert');
  const showAlternate = (message, ok) => {
    if (!alternateAlert) return;
    alternateAlert.textContent = message;
    alternateAlert.style.color = ok ? '#18a77d' : '#dc5959';
  };
  alternateButton?.addEventListener('click', () => {
    if (!alternatePanel) return;
    alternatePanel.hidden = !alternatePanel.hidden;
    const codeGroup = codeInput?.closest('.form-group');
    if (codeGroup) codeGroup.hidden = !alternatePanel.hidden;
    const codeSubmit = document.getElementById('btn-submit-voice-recovery');
    if (codeSubmit) codeSubmit.hidden = !alternatePanel.hidden;
    if (alertEl) alertEl.style.display = 'none';
    alternateButton.textContent = alternatePanel.hidden ? 'Forgot recovery code? Use Google Authenticator' : 'Use recovery code instead';
  });
  alternateSubmit?.addEventListener('click', async () => {
    const totpCode = document.getElementById('input-voice-recovery-totp')?.value.trim() || '';
    if (!/^\d{6}$/.test(totpCode)) {
      showAlternate('Enter the six-digit Google Authenticator code.', false); return;
    }
    alternateSubmit.disabled = true;
    try {
      const user = getActiveUser();
      const response = await fetch('/api/v1/auth/voice-recovery/alternate/verify', {
        method: 'POST', headers: voiceHeaders(),
        body: JSON.stringify({ session_id: currentSessionId, user_id: user.id || user.email || '', totp_code: totpCode, repair_voice: voiceRepairAvailable })
      });
      const data = await response.json();
      if (response.ok && data.success) {
        if (data.status === 'REPAIR_AUTHORIZED') {
          document.getElementById('input-voice-recovery-totp').value = '';
          isVoiceVerified = false;
          switchAuthView('voice');
          const recordBtn = document.getElementById('btn-start-voice');
          if (recordBtn) { recordBtn.style.display = ''; recordBtn.disabled = false; }
          await loadVoiceChallenge();
          return;
        }
        showAlternate('Verified. Continue with Authenticator MFA.', true);
        document.getElementById('input-voice-recovery-totp').value = '';
        setTimeout(() => switchAuthView('mfa'), 600);
      } else showAlternate(data.detail || 'Verification failed.', false);
    } catch (_) { showAlternate('Recovery verification unavailable. Try again.', false); }
    finally { alternateSubmit.disabled = false; }
  });

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!codeInput || !codeInput.value.trim()) return;

      if (alertEl) alertEl.style.display = 'none';

      const user = getActiveUser();
      try {
        const res = await fetch('/api/v1/auth/voice-recovery/verify', {
          method: 'POST',
          headers: voiceHeaders(),
          body: JSON.stringify({
            session_id: currentSessionId,
            recovery_code: codeInput.value.trim(),
            user_id: user.id || user.email || ''
          })
        });

        const data = await res.json();
        if (res.ok && data.success) {
          if (alertEl) {
            alertEl.className = 'alert-box alert-success';
            alertEl.textContent = data.message || 'Additional verification completed. Continue with Authenticator MFA.';
            alertEl.style.display = 'block';
          }
          setTimeout(() => {
            switchAuthView('mfa');
          }, 800);
        } else {
          const detail = typeof data.detail === 'string' ? data.detail : (data.detail && data.detail.message ? data.detail.message : (data.message || 'Invalid or used recovery code.'));
          if (alertEl) {
            alertEl.className = 'alert-box alert-error';
            alertEl.textContent = detail;
            alertEl.style.display = 'block';
          }
        }
      } catch (err) {
        if (alertEl) {
          alertEl.className = 'alert-box alert-error';
          alertEl.textContent = 'Recovery service unavailable. Please check your network and try again.';
          alertEl.style.display = 'block';
        }
      }
    });
  }
}

function stopAudioRecording() {
  if (animationFrameId) {
    cancelAnimationFrame(animationFrameId);
    animationFrameId = null;
  }
  if (audioStream) {
    audioStream.getTracks().forEach(t => t.stop());
    audioStream = null;
  }
  if (audioContext && audioContext.state !== 'closed') {
    audioContext.close().catch(() => {});
  }
  const orb = document.getElementById('voice-mic-orb');
  if (orb) orb.classList.remove('recording');
}

/* ============================================================
   9. STAGE 4: TWO-STEP AUTHENTICATOR (MFA / TOTP)
   ============================================================ */
async function handleMfaSubmit() {
  const boxes = document.querySelectorAll('#otp-container .otp-box');
  let code = '';
  boxes.forEach(b => code += b.value.trim());

  if (code.length < 6) {
    alert('Please enter all 6 digits of your authenticator code.');
    return;
  }

  const user = getActiveUser();

  try {
    const res = await fetch('/api/v1/mfa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        user_id: user.id || user.email,
        code: code
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      isMfaVerified = true;
      const otpContainer = document.getElementById('otp-container');
      if (otpContainer) otpContainer.classList.add('mfa-success');
      setTimeout(() => {
        switchAuthView('complete');
      }, 500);
    } else {
      alert(data.detail || 'Invalid authentication code. Please enter the current code from Google Authenticator.');
    }
  } catch (err) {
    console.error('MFA validation error:', err);
    alert('Network error verifying authentication code. Please try again.');
  }
}

/* ============================================================
   10. STAGE 5: FINAL ACCESS GRANTED & SESSION FINALIZATION
   ============================================================ */
function initFinalAccessButton() {
  const button = document.getElementById('btn-finalize-dashboard');
  if (!button || button.dataset.finalAccessBound === 'true') return;
  button.dataset.finalAccessBound = 'true';
  button.addEventListener('click', () => window.finalizeAndGoToDashboard());
}

let dashboardFinalizing = false;
window.finalizeAndGoToDashboard = async function() {
  if (dashboardFinalizing) return;
  dashboardFinalizing = true;
  const finalizeBtn = document.getElementById('btn-finalize-dashboard');
  const btnText = document.getElementById('btn-finalize-text');

  if (finalizeBtn) {
    finalizeBtn.disabled = true;
    finalizeBtn.classList.add('auth-pending');
    if (btnText) btnText.textContent = 'VERIFYING ACCESS...';
  }

  try {
    const oauthFlow = sessionStorage.getItem('dt_oauth_params');
    let completed = null;
    if (oauthFlow) {
      try { completed = JSON.parse(sessionStorage.getItem('dt_oauth_completed_access') || 'null'); } catch {}
    }
    let data;
    let res;
    if (completed?.session_id === currentSessionId && completed?.access_token) {
      data = completed; res = {ok:true};
    } else {
    // 1. First, trigger the Risk Engine evaluation to satisfy Zero-Trust rules
    const riskRes = await fetch('/api/v1/risk/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId
      })
    });
    
    if (!riskRes.ok) {
      const riskData = await riskRes.json().catch(() => ({}));
      alert('Risk Engine Error: ' + (riskData.detail || 'Access blocked by Risk Engine.'));
      if (finalizeBtn) finalizeBtn.disabled = false;
      if (btnText) btnText.textContent = 'Continue to Dashboard';
      return;
    }

    // 2. Proceed with Finalize
    res = await fetch('/api/v1/auth/finalize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        verification_token: currentVerificationToken
      })
    });

    data = await res.json();
    }

    if (res.ok && data.success && data.access_token) {
      if (finalizeBtn) {
        finalizeBtn.classList.remove('auth-pending');
        finalizeBtn.classList.add('auth-success');
      }
      const shield = document.querySelector('.final-access-shield');
      if (shield) shield.parentElement.classList.add('final-access-success');
      if (btnText) btnText.textContent = 'ACCESS VERIFIED';

      // Check if OAuth SSO Flow is active (from NovaCare or external application)
      const storedOAuth = sessionStorage.getItem('dt_oauth_params');
      if (storedOAuth) {
        sessionStorage.setItem('dt_oauth_completed_access', JSON.stringify({...data, session_id:currentSessionId}));
        try {
          const oauthParams = JSON.parse(storedOAuth);
          if (btnText) btnText.textContent = 'Redirecting to NovaCare Portal...';

          const authRes = await fetch('/api/v1/oauth/authorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${data.access_token}` },
            body: JSON.stringify({
              client_id: oauthParams.client_id,
              redirect_uri: oauthParams.redirect_uri,
              response_type: 'code',
              state: oauthParams.state,
              code_challenge: oauthParams.code_challenge,
              code_challenge_method: oauthParams.code_challenge_method || 'S256',
              auth_session_id: currentSessionId,
              requested_role: oauthParams.role
            })
          });

          const authData = await authRes.json();
          if (authRes.ok && (authData.code || authData.redirect_url)) {
            sessionStorage.removeItem('dt_oauth_params');
            sessionStorage.removeItem('dt_oauth_completed_access');
            const targetUrl = authData.redirect_url || `${oauthParams.redirect_uri}?code=${encodeURIComponent(authData.code)}&state=${encodeURIComponent(authData.state || oauthParams.state || '')}`;
            window.location.href = targetUrl;
            return;
          }
          throw new Error(authData.detail || authData.error_description || 'Hospital authorization failed. Please restart staff login from the hospital portal.');
        } catch (e) {
          throw new Error(e.message || 'Hospital authorization failed. Please restart staff login from the hospital portal.');
        }
      }

      // Save one consistent token, expiry and user before opening the dashboard.
      if (window.Session && typeof window.Session.save === 'function') {
        window.Session.save(data.access_token, data.user, true);
      }
      if (!window.Session?.getToken()) throw new Error('Could not save your access session. Please allow browser storage.');

      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 800);
    } else {
      alert('Finalize Error: ' + (data.detail || data.message || 'Verification incomplete. Please complete all stages.'));
      if (finalizeBtn) finalizeBtn.disabled = false;
      if (btnText) btnText.textContent = 'Continue to Dashboard';
    }
  } catch (err) {
    console.error('Finalize error:', err);
    finalizeBtn?.classList.remove('auth-success');
    alert('Network/System Error during finalize: ' + err.message);
    if (finalizeBtn) finalizeBtn.disabled = false;
    if (btnText) btnText.textContent = 'Continue to Dashboard';
  } finally {
    dashboardFinalizing = false;
    if (finalizeBtn && !finalizeBtn.classList.contains('auth-success')) {
      finalizeBtn.classList.remove('auth-pending');
      finalizeBtn.disabled = false;
    }
  }
};

/* ============================================================
   11. DEEPTRUST ADMIN REGISTRATION & MFA SETUP ENGINE
   ============================================================ */
let pendingRegisterEmail = '';
let pendingRegisterUserId = '';

function initRegisterUx() {
  const gotoRegisterBtn = document.getElementById('btn-goto-register');
  const backToLoginBtn = document.getElementById('btn-back-to-login');
  const emailVerifyBackBtn = document.getElementById('btn-email-verify-back');
  const resendEmailCodeBtn = document.getElementById('btn-resend-email-code');

  if (gotoRegisterBtn) {
    gotoRegisterBtn.addEventListener('click', (e) => {
      e.preventDefault();
      switchAuthView('admin-register');
    });
  }

  if (backToLoginBtn) {
    backToLoginBtn.addEventListener('click', (e) => {
      e.preventDefault();
      switchAuthView('login');
    });
  }

  if (emailVerifyBackBtn) {
    emailVerifyBackBtn.addEventListener('click', (e) => {
      e.preventDefault();
      switchAuthView('login');
    });
  }

  if (resendEmailCodeBtn) {
    resendEmailCodeBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await handleResendEmailOtp();
    });
  }

  const directMfaBtn = document.getElementById('btn-proceed-mfa-direct');
  if (directMfaBtn) {
    directMfaBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      await startGoogleAuthenticatorSetup();
    });
  }

  initSpecificOtpBoxes('.email-otp-box');
  initSpecificOtpBoxes('.totp-setup-otp-box');
}

function initSpecificOtpBoxes(selector) {
  const boxes = document.querySelectorAll(selector);
  boxes.forEach((box, index) => {
    box.addEventListener('input', (e) => {
      const val = e.target.value;
      if (val && index < boxes.length - 1) {
        boxes[index + 1].focus();
      }
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && index > 0) {
        boxes[index - 1].focus();
      }
    });

    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
      if (/^\d+$/.test(pasteData)) {
        pasteData.split('').forEach((char, i) => {
          if (boxes[i]) boxes[i].value = char;
        });
        if (boxes[boxes.length - 1]) boxes[boxes.length - 1].focus();
      }
    });
  });
}

function initRegisterForms() {
  const registerForm = document.getElementById('form-admin-register');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleAdminRegisterSubmit();
    });
  }

  const emailVerifyForm = document.getElementById('form-email-verify');
  if (emailVerifyForm) {
    emailVerifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleEmailVerifySubmit();
    });
  }

  const mfaSetupForm = document.getElementById('form-mfa-setup-confirm');
  if (mfaSetupForm) {
    mfaSetupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleMfaSetupSubmit();
    });
  }
}

async function handleAdminRegisterSubmit() {
  const fullNameEl = document.getElementById('input-reg-fullname');
  const emailEl = document.getElementById('input-reg-email');
  const passEl = document.getElementById('input-reg-password');
  const confirmPassEl = document.getElementById('input-reg-confirm-password');
  const errorMsgEl = document.getElementById('register-error-msg');
  const submitBtn = document.getElementById('btn-submit-register');
  const btnText = document.getElementById('register-btn-text');

  if (errorMsgEl) {
    errorMsgEl.style.display = 'none';
    errorMsgEl.textContent = '';
  }

  const fullName = fullNameEl ? fullNameEl.value.trim() : '';
  const email = emailEl ? emailEl.value.trim().toLowerCase() : '';
  const password = passEl ? passEl.value : '';
  const confirmPassword = confirmPassEl ? confirmPassEl.value : '';

  if (!fullName || !email || !password || !confirmPassword) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Please fill in all required fields.';
      errorMsgEl.style.display = 'block';
    }
    return;
  }

  if (password !== confirmPassword) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Passwords do not match. Please re-enter passwords.';
      errorMsgEl.style.display = 'block';
    }
    return;
  }

  if (password.length < 8) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Password must be at least 8 characters long.';
      errorMsgEl.style.display = 'block';
    }
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    if (btnText) btnText.textContent = 'Creating Account...';
  }

  try {
    const res = await fetch('/api/v1/admin/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name: fullName,
        email: email,
        password: password,
        confirm_password: confirmPassword
      })
    });

    const data = await res.json();

    if (res.ok) {
      pendingRegisterEmail = email;
      pendingRegisterUserId = data.user_id || email;

      const maskedDisplay = document.getElementById('email-masked-display');
      if (maskedDisplay) {
        maskedDisplay.textContent = data.masked_email || email;
      }

      const directMfaBtn = document.getElementById('btn-proceed-mfa-direct');
      if (directMfaBtn) directMfaBtn.style.display = 'none';
      const deliveryHeading = document.getElementById('email-delivery-heading');
      if (deliveryHeading) deliveryHeading.textContent = data.email_sent === true
        ? 'Verification code sent to:' : 'Verify this email address:';
      const verifyStatusEl = document.getElementById('email-verify-status-msg');
      if (verifyStatusEl) {
        verifyStatusEl.textContent = data.email_sent === true
          ? 'Verification code sent. Check your inbox and spam folder.'
          : (data.email_configured === false ? 'Account created, but email service is not configured.'
            : 'Account created, but the verification email was not sent. Check sender configuration, then use Resend Code.');
        verifyStatusEl.style.display = 'block';
      }

      switchAuthView('email-verify');
    } else {
      if (errorMsgEl) {
        errorMsgEl.textContent = data.detail || data.message || 'Registration failed.';
        errorMsgEl.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Server connection error. Please try again.';
      errorMsgEl.style.display = 'block';
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      if (btnText) btnText.textContent = 'Create Account';
    }
  }
}

async function handleResendEmailOtp() {
  if (!pendingRegisterEmail) {
    alert('Please enter your email on the registration page.');
    return;
  }
  const verifyStatusEl = document.getElementById('email-verify-status-msg');
  const verifyErrorEl = document.getElementById('email-verify-error-msg');
  const deliveryHeading = document.getElementById('email-delivery-heading');
  if (verifyErrorEl) verifyErrorEl.style.display = 'none';
  if (verifyStatusEl) verifyStatusEl.style.display = 'none';
  if (deliveryHeading) deliveryHeading.textContent = 'Verify this email address:';
  try {
    const res = await fetch('/api/v1/auth/email/resend-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: pendingRegisterEmail })
    });
    const data = await res.json();
    if (res.ok && data.success === true && data.email_sent === true) {
      if (deliveryHeading) deliveryHeading.textContent = 'Verification code sent to:';
      if (verifyStatusEl) {
        verifyStatusEl.textContent = 'Verification code re-sent. Check your inbox and spam folder.';
        verifyStatusEl.style.display = 'block';
      }
    } else if (verifyErrorEl) {
      verifyErrorEl.textContent = data.detail || data.message || 'Failed to resend verification code.';
      verifyErrorEl.style.display = 'block';
    }
  } catch (err) {
    if (verifyErrorEl) {
      verifyErrorEl.textContent = 'Server connection error.';
      verifyErrorEl.style.display = 'block';
    }
  }
}

async function handleEmailVerifySubmit() {
  const boxes = document.querySelectorAll('.email-otp-box');
  const errorMsgEl = document.getElementById('email-verify-error-msg');
  const submitBtn = document.getElementById('btn-submit-verify-email');
  const btnText = document.getElementById('verify-email-btn-text');

  if (errorMsgEl) errorMsgEl.style.display = 'none';

  let code = '';
  boxes.forEach(box => { code += box.value.trim(); });

  const verifyStatusEl = document.getElementById('email-verify-status-msg');
  const isEmailUnconfigured = verifyStatusEl && verifyStatusEl.textContent.includes('not configured');

  if (code.length !== 6 && !isEmailUnconfigured) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Please enter the complete 6-digit verification code.';
      errorMsgEl.style.display = 'block';
    }
    return;
  }

  if (!code && isEmailUnconfigured) {
    code = '000000';
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    if (btnText) btnText.textContent = 'Verifying Code...';
  }

  try {
    const res = await fetch('/api/v1/auth/email/verify-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: pendingRegisterEmail,
        code: code
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      await startGoogleAuthenticatorSetup();
    } else {
      if (errorMsgEl) {
        errorMsgEl.textContent = data.detail || data.message || 'Invalid verification code.';
        errorMsgEl.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Server connection error.';
      errorMsgEl.style.display = 'block';
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      if (btnText) btnText.textContent = 'Verify Email';
    }
  }
}

async function startGoogleAuthenticatorSetup() {
  const qrImg = document.getElementById('mfa-qr-code-img');
  const errorMsgEl = document.getElementById('mfa-setup-error-msg');
  if (errorMsgEl) errorMsgEl.style.display = 'none';

  try {
    const res = await fetch('/api/v1/mfa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: pendingRegisterEmail,
        email: pendingRegisterEmail
      })
    });

    const data = await res.json();

    if (res.ok && data.qr_code) {
      if (qrImg) qrImg.src = data.qr_code;
      switchAuthView('mfa-setup');
    } else {
      alert(data.detail || data.message || 'Failed to initialize Google Authenticator setup.');
    }
  } catch (err) {
    alert('Server connection error during MFA setup.');
  }
}

async function handleMfaSetupSubmit() {
  const boxes = document.querySelectorAll('.totp-setup-otp-box');
  const errorMsgEl = document.getElementById('mfa-setup-error-msg');
  const submitBtn = document.getElementById('btn-submit-mfa-setup');
  const btnText = document.getElementById('mfa-setup-btn-text');

  if (errorMsgEl) errorMsgEl.style.display = 'none';

  let code = '';
  boxes.forEach(box => { code += box.value.trim(); });

  if (code.length !== 6) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Please enter the complete 6-digit code shown in Google Authenticator.';
      errorMsgEl.style.display = 'block';
    }
    return;
  }

  if (submitBtn) {
    submitBtn.disabled = true;
    if (btnText) btnText.textContent = 'Verifying TOTP...';
  }

  try {
    const res = await fetch('/api/v1/mfa/totp/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: pendingRegisterEmail,
        email: pendingRegisterEmail,
        code: code
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      alert('✓ DeepTrust Admin Account Activated!\n\nYour account has been fully verified and activated. You can now sign in using your official email address and password.');
      switchAuthView('login');
    } else {
      if (errorMsgEl) {
        errorMsgEl.textContent = data.detail || data.message || 'Invalid Authenticator code. Please check Google Authenticator.';
        errorMsgEl.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorMsgEl) {
      errorMsgEl.textContent = 'Server connection error.';
      errorMsgEl.style.display = 'block';
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      if (btnText) btnText.textContent = 'Verify & Enable Authenticator';
    }
  }
}
