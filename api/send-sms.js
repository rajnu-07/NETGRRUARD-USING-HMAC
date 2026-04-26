export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { phone, otp } = req.body;

  if (!phone || !otp) {
    return res.status(400).json({ error: 'Phone and OTP are required' });
  }

  // Read Twilio credentials securely from Environment Variables
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

  if (!accountSid || !authToken || !twilioPhone) {
    console.error('Missing Twilio credentials in environment variables.');
    return res.status(500).json({ error: 'Server configuration error: Missing environment variables' });
  }

  const auth = Buffer.from(`${accountSid}:${authToken}`).toString('base64');
  const body = new URLSearchParams({
    To: phone,
    From: twilioPhone,
    Body: `Your NetGuard Admin SMS OTP is: ${otp}`
  });

  try {
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body.toString()
    });

    const data = await response.json();

    if (!response.ok) {
      console.error('Twilio API Error:', data);
      return res.status(response.status).json({ error: data.message || 'Failed to send SMS via Twilio' });
    }

    return res.status(200).json({ success: true, message: 'SMS sent successfully' });
  } catch (error) {
    console.error('Fetch Error:', error);
    return res.status(500).json({ error: 'Internal server error while sending SMS' });
  }
}
