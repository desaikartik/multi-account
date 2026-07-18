'use strict';
// Mailer abstraction. Services call ctx.mailer.send({ to, subject, text }).
//
//  - createCaptureMailer(): test/dev double that records messages in-memory.
//  - createGmailMailer(config): production sender. nodemailer is LAZY-required
//    here so the test suite (which never constructs this) runs with nothing
//    installed. Uses a Gmail app password from the backend env.

// In-memory capture mailer — never sends anything.
function createCaptureMailer() {
  const sent = [];
  return {
    sent,
    async send(msg) {
      sent.push({ ...msg });
      return { messageId: 'capture-' + sent.length };
    },
  };
}

// Real Gmail sender (production). nodemailer required lazily.
function createGmailMailer(config) {
  let transporter = null;
  function getTransporter() {
    if (!transporter) {
      // eslint-disable-next-line global-require
      const nodemailer = require('nodemailer');
      transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: config.gmailUser, pass: config.gmailAppPassword },
      });
    }
    return transporter;
  }
  return {
    async send({ to, subject, text, html }) {
      return getTransporter().sendMail({
        from: config.gmailUser,
        to, subject, text, html,
      });
    },
  };
}

// Console mailer for the local in-memory demo: prints the message (incl. the
// OTP) to stdout so the demo flow is followable without real email.
function createConsoleMailer(logger = console) {
  const sent = [];
  return {
    sent,
    async send(msg) {
      sent.push({ ...msg });
      const line = `\n[email] to=${msg.to} subject="${msg.subject}"\n        ${String(msg.text || '').replace(/\n/g, '\n        ')}\n`;
      if (logger.log) logger.log(line); else if (logger.info) logger.info(line);
      return { messageId: 'console-' + sent.length };
    },
  };
}

module.exports = { createCaptureMailer, createGmailMailer, createConsoleMailer };
