/**
 * ============================================================
 * faceAuth.js — Stage 1A: Face/Webcam Verification Module
 * ============================================================
 * Responsibilities:
 *   - Request webcam access from the browser
 *   - Capture a frame from the video stream
 *   - Run a mock face-verification check
 *   - Return true (verified) or false (failed)
 *
 * In a real system, you would send the captured image to a
 * face-recognition API (e.g. AWS Rekognition, Azure Face API).
 * ============================================================
 */

const FaceAuth = (() => {

  // ── Private state ──────────────────────────────────────────
  let videoStream = null; // holds the MediaStream from the webcam

  // ── DOM helpers ────────────────────────────────────────────

  /**
   * Creates a temporary <video> element, attaches the webcam
   * stream to it, and appends it to the given container.
   *
   * @param {HTMLElement} container - where to mount the video preview
   * @returns {HTMLVideoElement}
   */
  function createVideoElement(container) {
    const video = document.createElement('video');
    video.id = 'face-preview';
    video.autoplay = true;
    video.playsInline = true;
    video.style.cssText = `
      width: 280px;
      height: 210px;
      border-radius: 12px;
      object-fit: cover;
      border: 2px solid var(--accent, #00ffe7);
      display: block;
      margin: 12px auto;
    `;
    container.appendChild(video);
    return video;
  }

  /**
   * Removes the video preview and stops the webcam stream.
   * Always call this after verification to release the camera.
   */
  function cleanup() {
    const preview = document.getElementById('face-preview');
    if (preview) preview.remove();

    if (videoStream) {
      videoStream.getTracks().forEach(track => track.stop());
      videoStream = null;
    }
  }

  // ── Core API ───────────────────────────────────────────────

  /**
   * startWebcam()
   * Requests camera permission and starts the live preview.
   *
   * @param {HTMLElement} container - DOM node to render video into
   * @returns {Promise<HTMLVideoElement>} the live video element
   */
  async function startWebcam(container) {
    try {
      // Ask the browser for camera access
      videoStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'user', width: 280, height: 210 },
        audio: false
      });

      const video = createVideoElement(container);
      video.srcObject = videoStream;

      // Wait until the video is actually playing before resolving
      await new Promise((resolve) => {
        video.onloadedmetadata = () => resolve();
      });

      return video;
    } catch (err) {
      // User denied camera, or no camera found
      throw new Error(`Webcam access denied: ${err.message}`);
    }
  }

  /**
   * captureFrame()
   * Draws the current video frame onto a hidden <canvas> and
   * returns it as a Base64 PNG string (ready to POST to an API).
   *
   * @param {HTMLVideoElement} video
   * @returns {string} Base64-encoded image data
   */
  function captureFrame(video) {
    const canvas = document.createElement('canvas');
    canvas.width  = video.videoWidth  || 280;
    canvas.height = video.videoHeight || 210;

    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    return canvas.toDataURL('image/png'); // "data:image/png;base64,..."
  }

  /**
   * mockVerifyFace()
   * Simulates a server-side face recognition call.
   *
   * Replace this with an actual API call in production:
   *   const res = await fetch('/api/verify-face', {
   *     method: 'POST',
   *     body: JSON.stringify({ image: imageData })
   *   });
   *   return (await res.json()).matched;
   *
   * @param {string} imageData - Base64 PNG from captureFrame()
   * @returns {Promise<boolean>}
   */
  async function mockVerifyFace(imageData) {
    // Simulate network delay (300 – 800 ms)
    await new Promise(r => setTimeout(r, 300 + Math.random() * 500));

    // ⚠️  MOCK: Always returns true for demo purposes.
    // In production: compare imageData against a stored face embedding.
    const mockResult = true;
    return mockResult;
  }

  /**
   * verify()
   * Full face-auth pipeline: start webcam → capture → verify.
   * This is the only function login.js needs to call.
   *
   * @param {HTMLElement} container - where to show the webcam preview
   * @returns {Promise<boolean>} true = face verified, false = failed
   */
  async function verify(container) {
    let video;
    try {
      // Step 1: Open the webcam
      video = await startWebcam(container);

      // Step 2: Give the user 2 seconds to position their face
      await new Promise(r => setTimeout(r, 2000));

      // Step 3: Snap a frame
      const imageData = captureFrame(video);

      // Step 4: Run (mock) face recognition
      const result = await mockVerifyFace(imageData);

      return result; // true or false
    } catch (err) {
      console.error('[FaceAuth] Error during verification:', err);
      return false;
    } finally {
      // Always release the camera when done
      cleanup();
    }
  }

  // ── Public interface ───────────────────────────────────────
  return { verify };

})();
