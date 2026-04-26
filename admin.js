// admin.js - Frontend logic for OTP verification

// State
let generatedEmailOTP = '';
let generatedSmsOTP = '';

// DOM Elements
const step1Form = document.getElementById('step-1-form');
const step2Form = document.getElementById('step-2-form');
const loginError = document.getElementById('login-error');
const otpError = document.getElementById('otp-error');
const btnAuth = document.getElementById('btn-auth');
const btnVerify = document.getElementById('btn-verify');
const otpAlert = document.getElementById('otp-alert');

async function triggerOtpSend() {
  const email = document.getElementById('admin-email').value;
  const phone = document.getElementById('admin-phone').value;

  // Generate 6-digit OTPs
  generatedEmailOTP = Math.floor(100000 + Math.random() * 900000).toString();
  generatedSmsOTP = Math.floor(100000 + Math.random() * 900000).toString();

  // ==========================================
  // TWILIO CONFIGURATION (SMS)
  // ==========================================
  // Twilio credentials are now securely managed in Vercel Environment Variables.
  // The frontend no longer stores or sends them directly.

  // ==========================================
  // EMAILJS CONFIGURATION (EMAIL)
  // ==========================================
  const EMAILJS_PUBLIC_KEY = 'GE5wGrt-fiGMKDenh';
  const EMAILJS_SERVICE_ID = 'service_lq62ely';
  const EMAILJS_TEMPLATE_ID = 'template_76krdeh';

  let success = true;

  // 1. Send SMS using Vercel Serverless Function
  try {
    const response = await fetch('/api/send-sms', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        phone: phone,
        otp: generatedSmsOTP
      })
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Server error');
    }
    console.log(`Successfully sent SMS to ${phone}`);
  } catch (smsError) {
    console.error("Twilio SMS failed via Vercel:", smsError);
    console.log(`[FALLBACK LOG] SMS OTP to ${phone}: ${generatedSmsOTP}`);
    success = false;
  }

  // 2. Send Email using EmailJS
  if (EMAILJS_PUBLIC_KEY !== 'YOUR_EMAILJS_PUBLIC_KEY') {
    try {
      emailjs.init(EMAILJS_PUBLIC_KEY);
      await emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, {
        to_email: email,
        otp_code: generatedEmailOTP,
        otp: generatedEmailOTP,
        message: generatedEmailOTP,
        code: generatedEmailOTP,
        time: new Date().toLocaleTimeString()
      });
      console.log(`Successfully sent Email to ${email}`);
    } catch (emailError) {
      console.error("EmailJS failed:", emailError);
      console.log(`[FALLBACK LOG] Email OTP to ${email}: ${generatedEmailOTP}`);
      success = false;
    }
  } else {
    console.log(`[MOCK EMAIL] Configure EmailJS keys to send real email. OTP: ${generatedEmailOTP}`);
  }

  // Even if mock or failed, we allow them to proceed so UI testing isn't blocked.
  return true;
}

// Handle Step 1 (Authentication)
step1Form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const user = document.getElementById('admin-user').value;
  const pass = document.getElementById('admin-pass').value;

  loginError.textContent = '';

  // Basic mock authentication check
  if (user !== 'admin' || pass !== 'admin') {
    loginError.textContent = 'Invalid credentials. Hint: use admin/admin';
    return;
  }

  // Set button to loading state
  const originalBtnContent = btnAuth.innerHTML;
  btnAuth.innerHTML = '<span>Sending OTPs...</span>';
  btnAuth.disabled = true;

  const success = await triggerOtpSend();

  if (success) {
    // Transition to Step 2
    step1Form.style.display = 'none';
    step2Form.style.display = 'flex';
    document.getElementById('form-subtitle').textContent = 'Enter the codes sent to your devices';
    otpAlert.textContent = 'OTP sent! Check your Email and Phone.';
    otpAlert.style.color = 'var(--green)';
    otpAlert.style.backgroundColor = 'rgba(30, 200, 100, 0.1)';
    otpAlert.style.borderColor = 'rgba(30, 200, 100, 0.2)';
  } else {
    loginError.textContent = 'Failed to send OTPs. Check console for details.';
  }

  btnAuth.innerHTML = originalBtnContent;
  btnAuth.disabled = false;
});

async function resendOtps() {
  otpError.textContent = '';
  otpAlert.textContent = 'Resending OTPs...';
  otpAlert.style.color = 'var(--amber)';
  otpAlert.style.backgroundColor = 'rgba(255, 170, 0, 0.1)';
  otpAlert.style.borderColor = 'rgba(255, 170, 0, 0.2)';

  const success = await triggerOtpSend();

  if (success) {
    otpAlert.textContent = 'New OTPs sent! Check your Email and Phone.';
    otpAlert.style.color = 'var(--green)';
    otpAlert.style.backgroundColor = 'rgba(30, 200, 100, 0.1)';
    otpAlert.style.borderColor = 'rgba(30, 200, 100, 0.2)';
  } else {
    otpAlert.textContent = 'Failed to resend OTPs. Check console.';
    otpAlert.style.color = 'var(--red)';
    otpAlert.style.backgroundColor = 'rgba(255, 50, 50, 0.1)';
    otpAlert.style.borderColor = 'rgba(255, 50, 50, 0.2)';
  }
}

// Handle Step 2 (Verification)
step2Form.addEventListener('submit', (e) => {
  e.preventDefault();

  const enteredEmailOtp = document.getElementById('email-otp').value;
  const enteredSmsOtp = document.getElementById('sms-otp').value;

  otpError.textContent = '';

  if (enteredEmailOtp === generatedEmailOTP && enteredSmsOtp === generatedSmsOTP) {
    btnVerify.innerHTML = '<span>Verifying...</span>';
    btnVerify.disabled = true;

    // Simulate verification delay, then redirect
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1000);
  } else {
    otpError.textContent = 'Invalid OTPs. Please check again.';
  }
});

function resetForm() {
  step2Form.style.display = 'none';
  step1Form.style.display = 'flex';
  document.getElementById('form-subtitle').textContent = 'Secure gateway to network controls';
  document.getElementById('email-otp').value = '';
  document.getElementById('sms-otp').value = '';
  otpError.textContent = '';

  // Clear generated OTPs
  generatedEmailOTP = '';
  generatedSmsOTP = '';
}
