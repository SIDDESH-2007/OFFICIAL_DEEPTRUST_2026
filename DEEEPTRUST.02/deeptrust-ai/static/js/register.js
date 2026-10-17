const registerForm = document.getElementById('registerForm');
const cameraPreview = document.getElementById('cameraPreview');
const startCameraBtn = document.getElementById('startCameraBtn');
const recordVideoBtn = document.getElementById('recordVideoBtn');
const recordStatus = document.getElementById('recordStatus');
const statusBox = document.getElementById('statusBox');

let streamRef = null;
let mediaRecorder = null;
let recordedChunks = [];
let recordedBlob = null;

function showStatus(message, tone = 'status-green') {
  statusBox.className = `status-box ${tone}`;
  statusBox.textContent = message;
  statusBox.classList.remove('hidden');
}

startCameraBtn.addEventListener('click', async () => {
  try {
    streamRef = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
    cameraPreview.srcObject = streamRef;
    recordStatus.textContent = 'Camera active. You can record your 5-second live video.';
  } catch (error) {
    showStatus('Camera access failed. Please allow webcam permissions.', 'status-red');
  }
});

recordVideoBtn.addEventListener('click', async () => {
  if (!streamRef) {
    showStatus('Start camera before recording.', 'status-orange');
    return;
  }

  recordedChunks = [];
  mediaRecorder = new MediaRecorder(streamRef, { mimeType: 'video/webm' });

  mediaRecorder.ondataavailable = (event) => {
    if (event.data.size > 0) recordedChunks.push(event.data);
  };

  mediaRecorder.onstop = () => {
    recordedBlob = new Blob(recordedChunks, { type: 'video/webm' });
    recordStatus.textContent = 'Live video recorded successfully.';
    showStatus('Live video ready for AI verification.', 'status-green');
  };

  mediaRecorder.start();
  recordStatus.textContent = 'Recording... please stay in frame for 5 seconds.';

  setTimeout(() => {
    if (mediaRecorder && mediaRecorder.state === 'recording') {
      mediaRecorder.stop();
    }
  }, 5000);
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (!recordedBlob) {
    showStatus('Record the 5-second live video before registration.', 'status-orange');
    return;
  }

  const formData = new FormData(registerForm);
  formData.append('live_video', recordedBlob, 'live_capture.webm');

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();

    if (!response.ok) {
      const probability = result.deepfake_probability ? ` Deepfake Confidence: ${result.deepfake_probability}%` : '';
      showStatus(`${result.message}${probability}`, 'status-red');
      return;
    }

    showStatus(`${result.message} (Authenticity: ${result.authenticity_score}%)`, 'status-green');
    registerForm.reset();
    recordedBlob = null;
    recordStatus.textContent = 'Live verification video not recorded yet.';
  } catch (error) {
    showStatus('Registration failed. Try again.', 'status-red');
  }
});
