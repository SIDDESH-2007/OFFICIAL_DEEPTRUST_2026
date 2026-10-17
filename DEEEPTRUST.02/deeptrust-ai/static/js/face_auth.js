const startFaceCameraBtn = document.getElementById('startFaceCameraBtn');
const captureFaceFrameBtn = document.getElementById('captureFaceFrameBtn');
const completeFaceAuthBtn = document.getElementById('completeFaceAuthBtn');
const faceCameraPreview = document.getElementById('faceCameraPreview');
const faceCaptureCanvas = document.getElementById('faceCaptureCanvas');
const faceVerificationState = document.getElementById('faceVerificationState');
const faceStatusBox = document.getElementById('faceStatusBox');

let faceStream = null;
let capturedFrame = null;

function showFaceStatus(message, tone = 'status-green') {
  faceStatusBox.className = `status-box ${tone}`;
  faceStatusBox.textContent = message;
  faceStatusBox.classList.remove('hidden');
}

startFaceCameraBtn.addEventListener('click', async () => {
  try {
    faceStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
    faceCameraPreview.srcObject = faceStream;
    faceVerificationState.textContent = 'Camera active. Capture a verification frame.';
    showFaceStatus('Face camera channel active.', 'status-green');
  } catch (error) {
    showFaceStatus('Unable to access webcam. Please allow camera access.', 'status-red');
  }
});

captureFaceFrameBtn.addEventListener('click', () => {
  if (!faceStream) {
    showFaceStatus('Start camera first.', 'status-orange');
    return;
  }

  const width = faceCameraPreview.videoWidth || 640;
  const height = faceCameraPreview.videoHeight || 360;
  faceCaptureCanvas.width = width;
  faceCaptureCanvas.height = height;

  const context = faceCaptureCanvas.getContext('2d');
  context.drawImage(faceCameraPreview, 0, 0, width, height);
  capturedFrame = faceCaptureCanvas.toDataURL('image/jpeg', 0.9);

  faceVerificationState.textContent = 'Frame captured. Ready to complete AI verification.';
  showFaceStatus('Live frame captured.', 'status-green');
});

completeFaceAuthBtn.addEventListener('click', async () => {
  if (!capturedFrame) {
    showFaceStatus('Capture frame before submitting.', 'status-orange');
    return;
  }

  showFaceStatus('Running AI verification...', 'status-orange');

  try {
    const response = await fetch('/api/face-auth-complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ live_frame: capturedFrame }),
    });

    const result = await response.json();
    if (!response.ok) {
      showFaceStatus(result.message || 'Face verification failed.', 'status-red');
      return;
    }

    showFaceStatus(`Verification successful. Risk: ${result.risk_score}`, 'status-green');
    window.location.href = result.redirect_url;
  } catch (error) {
    showFaceStatus('Network error during face verification.', 'status-red');
  }
});
