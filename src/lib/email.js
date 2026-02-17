const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const FROM = process.env.MAIL_FROM || process.env.SMTP_USER || 'noreply@svift.com';
const APP_NAME = process.env.APP_NAME || 'Svift';

/**
 * Send OTP code to the given email address.
 * @param {string} toEmail - Recipient email
 * @param {string} code - 6-digit OTP code
 * @param {string} label - e.g. 'Signup', 'Login', 'Signup resend'
 * @returns {Promise<{ sent: boolean, error?: string }>}
 */
async function sendOtpEmail(toEmail, code, label) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn('SMTP not configured (SMTP_USER/SMTP_PASS). OTP logged only:', code);
    return { sent: false, error: 'SMTP not configured' };
  }

  const subject = `${APP_NAME} – Your verification code is ${code}`;
  const html = `
    <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto;">
      <h2 style="color: #111;">${label} – Verification code</h2>
      <p>Use this code to verify your email:</p>
      <p style="font-size: 24px; font-weight: bold; letter-spacing: 4px; color: #111;">${code}</p>
      <p style="color: #666; font-size: 14px;">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>
      <p style="color: #666; font-size: 14px;">– ${APP_NAME}</p>
    </div>
  `;
  const text = `${APP_NAME} – Your verification code is: ${code}. It expires in 10 minutes.`;

  try {
    await transporter.sendMail({
      from: FROM,
      to: toEmail,
      subject,
      text,
      html,
    });
    return { sent: true };
  } catch (err) {
    console.error('Failed to send OTP email:', err.message);
    return { sent: false, error: err.message };
  }
}

module.exports = { sendOtpEmail };
