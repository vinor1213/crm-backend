import { Request, Response } from "express";
import Otp from "./model"
import User from "../auth/auth.model";
import { otpSchema } from "./otp.sanitize";

const SibApiV3Sdk = require('sib-api-v3-sdk');

const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;
const emailApi = new SibApiV3Sdk.TransactionalEmailsApi();


export const createOtp = async (req: Request, res: Response) => {
  try {
    
    const { error } = otpSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await Otp.deleteMany({ email, verified: false });

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await Otp.create({ email, otp, expiresAt });

    const emailData = {
      sender: { email: "vinor1213@gmail.com", name: "Vinoth" },
      to: [{ email, name: user.firstname || "User" }],
      subject: "Your OTP Code",
      htmlContent: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>OTP Verification</h2>
          <p>Hello <b>${user.firstname || "User"}</b>,</p>
          <p>Your One-Time Password (OTP) for verification is:</p>
          <h1 style="color:#2563eb; letter-spacing:4px;">${otp}</h1>
          <p>This code is valid for <strong>10 minutes</strong>.</p>
          <p>If you didn’t request this, please ignore this message.</p>
          <hr />
          <p style="font-size: 12px; color: #555;">Sona Institute — Secure Verification</p>
        </div>
      `,
    };

    await emailApi.sendTransacEmail(emailData);

    return res.status(201).json({
      success: true,
      message: "OTP sent successfully to registered email",
      data: { email, expiresAt },
    });
  } catch (err: any) {
    console.error("Error creating OTP:", err.response?.body || err.message || err);
    res.status(500).json({ message: "Internal server error" });
  }
};


export const verifyOtp = async (req: Request, res: Response) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ message: "Email and OTP are required" });
    }

    const otpDoc = await Otp.findOne({ email, otp });

    if (!otpDoc) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (otpDoc.expiresAt < new Date()) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    if (otpDoc.verified) {
      return res.status(400).json({ success: false, message: "OTP already verified" });
    }

    otpDoc.verified = true;
    await otpDoc.save();

    res.status(200).json({
      success: true,
      message: "OTP verified successfully",
    });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ message: "Internal server error" });
  }
};


export const deleteOtpByEmail = async (req: Request, res: Response) => {
  try {
    const { email } = req.params;
    const deleted = await Otp.deleteMany({ email });

    if (!deleted.deletedCount) {
      return res.status(404).json({ message: "No OTPs found for this email" });
    }

    res.status(200).json({
      success: true,
      message: "OTPs deleted successfully",
    });
  } catch (err) {
    console.error("Error deleting OTP:", err);
    res.status(500).json({ message: "Internal server error" });
  }
};
