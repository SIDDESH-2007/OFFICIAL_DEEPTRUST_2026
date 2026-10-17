const loginForm = document.getElementById('loginForm');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const rememberMe = document.getElementById('rememberMe');
const roleSelector = document.getElementById('roleSelector');
const togglePasswordBtn = document.getElementById('togglePasswordBtn');
const emailValidation = document.getElementById('emailValidation');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');
const attemptCounter = document.getElementById('attemptCounter');
const loginBtn = document.getElementById('loginBtn');
const loadingState = document.getElementById('loadingState');
const statusBox = document.getElementById('statusBox');
const warningBox = document.getElementById('warningBox');

const ATTEMPT_KEY = 'deeptrust_login_attempts';

function showStatus(message, tone = 'status-green') {
  statusBox.className = `status-box ${tone}`;
  statusBox.textContent = message;
  statusBox.classList.remove('hidden');
}

function showWarning(message) {
  warningBox.className = 'warning-box pulse-warning status-red';
  warningBox.textContent = message;
  warningBox.classList.remove('hidden');
}

function setLoading(isLoading) {
  loadingState.classList.toggle('hidden', !isLoading);
  loginBtn.disabled = isLoading;
}

function estimateDeviceAnomaly() {
  const memFactor = navigator.deviceMemory ? Math.max(0, 8 - navigator.deviceMemory) * 5 : 12;
  const cpuFactor = navigator.hardwareConcurrency ? Math.max(0, 8 - navigator.hardwareConcurrency) * 4 : 14;
  const randomNoise = Math.random() * 12;
  return Math.max(0, Math.min(100, memFactor + cpuFactor + randomNoise));
}

function getDeviceFingerprint() {
  const rawFingerprint = [
    navigator.userAgent,
    navigator.language,
    navigator.platform,
    String(navigator.hardwareConcurrency || 'na'),
    String(navigator.deviceMemory || 'na'),
    `${window.screen.width}x${window.screen.height}`,
    Intl.DateTimeFormat().resolvedOptions().timeZone || 'na',
  ].join('|');

  let hash = 0;
  for (let index = 0; index < rawFingerprint.length; index += 1) {
    hash = (hash << 5) - hash + rawFingerprint.charCodeAt(index);
    hash |= 0;
  }

  return `fp_${Math.abs(hash)}`;
}

function updateAttemptCounter(value = null) {
  const attempts = value ?? Number(localStorage.getItem(ATTEMPT_KEY) || 0);
  attemptCounter.textContent = `Login attempt counter: ${attempts}`;
}

function setEmailValidation() {
  const emailValue = emailInput.value.trim();
  const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailValue);
  if (!emailValue) {
    emailValidation.textContent = '';
    return false;
  }
  emailValidation.textContent = isValid ? 'Email format is valid.' : 'Enter a valid email address.';
  emailValidation.className = isValid ? 'status-green' : 'status-red';
  return isValid;
}

function evaluatePasswordStrength(passwordValue) {
  let score = 0;
  if (passwordValue.length >= 8) score += 25;
  if (/[A-Z]/.test(passwordValue)) score += 20;
  if (/[a-z]/.test(passwordValue)) score += 20;
  if (/[0-9]/.test(passwordValue)) score += 20;
  if (/[^A-Za-z0-9]/.test(passwordValue)) score += 15;

  strengthBar.style.width = `${score}%`;
  strengthBar.className = 'strength-bar';

  if (score >= 80) {
    strengthBar.classList.add('strength-strong');
    strengthText.textContent = 'Password strength: Strong';
  } else if (score >= 50) {
    strengthBar.classList.add('strength-medium');
    strengthText.textContent = 'Password strength: Medium';
  } else {
    strengthBar.classList.add('strength-weak');
    strengthText.textContent = 'Password strength: Weak';
  }
}

togglePasswordBtn.addEventListener('click', () => {
  const isPassword = passwordInput.type === 'password';
  passwordInput.type = isPassword ? 'text' : 'password';
  togglePasswordBtn.textContent = isPassword ? 'Hide' : 'Show';
});

emailInput.addEventListener('input', setEmailValidation);
passwordInput.addEventListener('input', () => evaluatePasswordStrength(passwordInput.value));

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  warningBox.classList.add('hidden');
  statusBox.classList.add('hidden');

  if (!setEmailValidation()) {
    showStatus('Please enter a valid email address.', 'status-orange');
    return;
  }

  setLoading(true);

  const payload = {
    email: emailInput.value.trim(),
    password: passwordInput.value,
    remember_me: rememberMe.checked,
    role: roleSelector.value,
    device_score: estimateDeviceAnomaly(),
    device_fingerprint: getDeviceFingerprint(),
    login_locale: Intl.DateTimeFormat().resolvedOptions().locale || 'unknown-locale',
  };

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const result = await response.json();

    if (!response.ok) {
      const current = Number(localStorage.getItem(ATTEMPT_KEY) || 0) + 1;
      localStorage.setItem(ATTEMPT_KEY, String(current));
      updateAttemptCounter(current);
      showStatus(result.message || 'Authentication failed.', 'status-red');
      showWarning('Suspicious login pattern detected. Additional verification may be required.');
      setLoading(false);
      return;
    }

    localStorage.setItem(ATTEMPT_KEY, '0');
    updateAttemptCounter(0);

    if (result.status === 'face_verification_required') {
      showWarning(result.message);
      showStatus(`Risk Score: ${result.risk_score}. Redirecting to face verification...`, 'status-orange');
      setTimeout(() => {
        window.location.href = result.redirect_url;
      }, 800);
      return;
    }

    showStatus(`Login successful. Risk Score: ${result.risk_score}`, 'status-green');
    window.location.href = result.redirect_url;
  } catch (error) {
    showStatus('Login request failed. Please retry.', 'status-red');
  } finally {
    setLoading(false);
  }
});

updateAttemptCounter();
