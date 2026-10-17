const uploadForm = document.getElementById('uploadForm');
const uploadStatus = document.getElementById('uploadStatus');
const resultCard = document.getElementById('resultCard');
const resultProbability = document.getElementById('resultProbability');
const resultAuthenticity = document.getElementById('resultAuthenticity');
const resultRisk = document.getElementById('resultRisk');
const resultConfidence = document.getElementById('resultConfidence');
const resultFrames = document.getElementById('resultFrames');

function showStatus(message, tone = 'status-green') {
  uploadStatus.className = `status-box ${tone}`;
  uploadStatus.textContent = message;
  uploadStatus.classList.remove('hidden');
}

uploadForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(uploadForm);

  showStatus('Processing media through AI detector...', 'status-orange');
  resultCard.classList.add('hidden');

  try {
    const response = await fetch('/api/upload-media', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    if (!response.ok) {
      showStatus(result.message || 'Upload failed.', 'status-red');
      return;
    }

    const riskTone = result.risk_level === 'HIGH' ? 'status-red' : result.risk_level === 'MEDIUM' ? 'status-orange' : 'status-green';
    showStatus(`Analysis complete: ${result.status.toUpperCase()}`, riskTone);

    resultProbability.textContent = `Deepfake Probability: ${result.deepfake_probability}%`;
    resultAuthenticity.textContent = `Authenticity Score: ${result.authenticity_score}%`;
    resultRisk.textContent = `Risk Level: ${result.risk_level}`;
    resultConfidence.textContent = `Confidence: ${result.confidence}%`;
    resultFrames.textContent = result.media_type === 'video' ? `Frames Analyzed: ${result.frames_analyzed}` : 'Frames Analyzed: N/A';

    resultCard.classList.remove('hidden');
  } catch (error) {
    showStatus('Network error during media analysis.', 'status-red');
  }
});
