import { Request, Response } from 'express';
import User from './auth.model';
import LoginHistory from '../login-histroy/model';
import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import dotenv from 'dotenv';
import Joi from 'joi';
import { RegisterDTO } from './auth.types';
import CryptoJS from "crypto-js";

dotenv.config();
const SECRET_KEY = "sonacassecretkey@2025";
export interface AuthRequest extends Request {
  user?: any;
}

const generateToken = (payload: object): string => {
  const secret: Secret = process.env.JWT_SECRET || 'secret';
  const options: SignOptions = {
    expiresIn: (process.env.JWT_EXPIRES || '7d') as jwt.SignOptions['expiresIn'],
  };
  return jwt.sign(payload, secret, options);
};

export const register = async (req: Request, res: Response) => {
  try {
    const schema = Joi.object({
      firstname: Joi.string().required(),
      lastname: Joi.string().required(),
      username: Joi.string().alphanum().min(3).max(30).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      mobileNo: Joi.string()
        .pattern(/^[0-9]{10,15}$/)
        .required()
        .messages({
          'string.pattern.base': 'Mobile number must contain only digits (10–15 characters).',
        }),
      designation: Joi.string().required(),
      role: Joi.string().valid('superadmin', 'admin', 'user').default('user'),
      instituteId: Joi.string().required(),
      status: Joi.string().valid('active', 'inactive').default('inactive'),
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    const existing = await User.findOne({ email: value.email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    const user = await User.create(value as RegisterDTO);

    res.status(201).json({
      message: 'User registered successfully',
      id: user._id,
      name: `${user.firstname} ${user.lastname}`,
      email: user.email,
      role: user.role,
      status: user.status,
    });
  } catch (err: any) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};


export const login = async (req: Request, res: Response) => {
  try {
    // ---------------- Validate Input ----------------
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    // ---------------- Find User ----------------
    const user = await User.findOne({ email: value.email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    let decryptedPassword;

    try {
      const bytes = CryptoJS.AES.decrypt(value.password, SECRET_KEY);
      decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);
    } catch {
      return res.status(400).json({ message: "Invalid password encryption" });
    }

    const isMatch = await user.comparePassword(decryptedPassword);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    if (user.status === "inactive") {
      return res
        .status(403)
        .json({ message: "Your account is inactive. Please contact your administrator." });
    }

    // ---------------- Update last login timestamp ----------------
    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      { $set: { lastLoginTimeDate: new Date() } },
      { new: true }
    );

    // ---------------- Generate JWT ----------------
    const token = generateToken({
      id: user._id,
      role: user.role,
      email: user.email,
      instituteId: user.instituteId,
    });

    // ---------------- Create/Update Login History ----------------
    if (user.role !== "superadmin") {
      // Get start and end of today
      const startOfDay = new Date();
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date();
      endOfDay.setHours(23, 59, 59, 999);

      // Find today's history
      const todayHistory = await LoginHistory.findOne({
        userId: user._id,
        instituteId: user.instituteId,
        lastLoginTime: { $gte: startOfDay, $lte: endOfDay },
      });

      if (todayHistory) {
        // Update lastLoginTime if already exists today
        todayHistory.lastLoginTime = new Date();
        await todayHistory.save();
      } else {
        // Create new history for today
        await LoginHistory.create({
          instituteId: user.instituteId,
          userId: user._id,
          role: user.role,
          lastLoginTime: new Date(),
        });
      }
    }

    // ---------------- Response ----------------
    res.json({
      message: "Login successful",
      user: {
        id: updatedUser?._id,
        firstname: updatedUser?.firstname,
        lastname: updatedUser?.lastname,
        email: updatedUser?.email,
        role: updatedUser?.role,
      },
      token,
    });
  } catch (err: any) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
};


export const listUsers = async (req: AuthRequest, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = (req.query.search as string) || "";
    const status = (req.query.status as string) || "all";
    const roleFilter = (req.query.role as string) || "all";
    const instituteId = (req.query.instituteId as string) || "all";

    const query: any = {};

    const userRole = req.user.role;

    // 🔹 Access Control
    if (userRole === "superadmin") {
      query.role = { $ne: "superadmin" }; // superadmin can see all except other superadmins
    } else if (userRole === "admin") {
      query.instituteId = req.user.instituteId; // admin only sees users from their institute
      query.role = "user";
    } else {
      return res.status(403).json({
        status: false,
        message: "You are not authorized to view this data.",
      });
    }

    // 🔹 Search Filter
    if (search.trim()) {
      query.$or = [
        { firstname: { $regex: search, $options: "i" } },
        { lastname: { $regex: search, $options: "i" } },
        { username: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }

    // 🔹 Status Filter
    if (status !== "all") {
      query.status = status;
    }

    // 🔹 Role Filter
    if (roleFilter !== "all") {
      query.role = roleFilter;
    }

    // 🔹 Institute Filter (for superadmin view)
    if (userRole === "superadmin" && instituteId !== "all") {
      query.instituteId = instituteId;
    }

    // 🔹 Pagination
    const users = await (User as any).paginate(query, {
      page,
      limit,
      sort: { createdAt: -1 },
      select: "-password",
    });

    return res.status(200).json({
      status: true,
      users,
    });
  } catch (err: any) {
    console.error("List Users Error:", err);
    return res.status(500).json({
      status: false,
      message: err.message || "Server error",
    });
  }
};


export const updateUser = async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;

    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        status: false,
        message: "Only superadmin can edit users.",
      });
    }

    const schema = Joi.object({
      firstname: Joi.string(),
      lastname: Joi.string(),
      username: Joi.string().alphanum().min(3).max(30),
      email: Joi.string().email(),
      mobileNo: Joi.string()
        .pattern(/^[0-9]{10,15}$/)
        .messages({
          "string.pattern.base": "Mobile number must contain only digits (10–15 characters).",
        }),
      designation: Joi.string().allow(""),
      role: Joi.string().valid("superadmin", "admin", "user"),
      status: Joi.string().valid("active", "inactive"),
      instituteId: Joi.string(),
    });

    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });


    const user = await User.findByIdAndUpdate(id, { $set: value }, { new: true }).select("-password");

    if (!user) {
      return res.status(404).json({ status: false, message: "User not found." });
    }

    return res.status(200).json({
      status: true,
      message: "User updated successfully.",
      user,
    });
  } catch (err: any) {
    console.error("Update User Error:", err);
    return res.status(500).json({ status: false, message: err.message || "Server error" });
  }
};

export const deleteUser = async (req: AuthRequest, res: Response) => {
  try {
    const { id } = req.params;


    if (req.user.role !== "superadmin") {
      return res.status(403).json({
        status: false,
        message: "Only superadmin can delete users.",
      });
    }

    const deleted = await User.findByIdAndDelete(id);

    if (!deleted) {
      return res.status(404).json({ status: false, message: "User not found." });
    }

    return res.status(200).json({
      status: true,
      message: "User deleted successfully.",
    });
  } catch (err: any) {
    console.error("Delete User Error:", err);
    return res.status(500).json({ status: false, message: err.message || "Server error" });
  }
};


