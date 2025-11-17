import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import axios from "axios";
import { mqClient } from "../lib/mq.js";

const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

const setCookie = (res, token) => {
  res.cookie("token", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    domain: process.env.NODE_ENV === 'production' ? process.env.COOKIE_DOMAIN : undefined,
  });
};

export const signUp = async (req, res) => {
  try {
    const { fullName, email, password, mobile, role } = req.body;

    if (!fullName || !email || !password || !mobile || !role) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already exists" });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    if (!mobile.match(/^[0-9]{10}$/)) {
      return res.status(400).json({ success: false, message: "Invalid mobile number" });
    }

    const user = await User.create({
      fullName,
      email,
      password: passwordHash,
      mobile,
      role,
    });

    const token = generateToken(user);
    setCookie(res, token);

    // Send welcome email via notification service (non-blocking with timeout)
    axios.post(
      `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications/welcome`,
      { email: user.email },
      { timeout: 3000 }
    ).catch(error => {
      console.error("Failed to enqueue welcome email:", error.message);
    });

    // Publish async signup event
    mqClient.publish('user.signup', { email: user.email, userId: user._id, fullName: user.fullName });

    return res.status(201).json({ 
      success: true, 
      message: "User created successfully", 
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        mobile: user.mobile,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const signIn = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "User does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: "Invalid Password" });
    }

    const token = generateToken(user);
    setCookie(res, token);

    return res.status(200).json({
      success: true,
      message: "User signed in successfully",
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        mobile: user.mobile,
        role: user.role
      },
      token,
    });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const signOut = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      path: "/",
    });

    res.cookie("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 0,
      path: "/",
      domain: process.env.NODE_ENV === 'production' ? process.env.COOKIE_DOMAIN : undefined,
    });

    return res.status(200).json({ success: true, message: "User signed out successfully" });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const sendOtp = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "User does not exist" });
    }

    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    user.otp = otp;
    user.isOtpExpired = Date.now() + 5 * 60 * 1000;
    user.isOtpVerified = false;
    await user.save();

    // Send OTP email via notification service
    try {
      const response = await axios.post(`${process.env.NOTIFICATION_SERVICE_URL}/api/notifications/password-reset`, {
        email: user.email,
        otp
      });

      return res.status(200).json({
        success: true,
        message: "OTP sent to email",
        jobId: response.data.jobId,
      });
    } catch (error) {
      console.error("Failed to send OTP email:", error.message);
      return res.status(500).json({
        success: false,
        message: "Failed to send OTP email",
      });
    }
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "User does not exist" });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (user.isOtpExpired < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    user.otp = undefined;
    user.isOtpExpired = undefined;
    user.isOtpVerified = true;
    await user.save();

    return res.status(200).json({ success: true, message: "OTP verified successfully" });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "User does not exist" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    return res.status(200).json({ success: true, message: "Password reset successfully" });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const googleAuth = async (req, res) => {
  try {
    const { email, fullName, mobile, role } = req.body;
    let existingUser = await User.findOne({ email });

    if (!existingUser) {
      existingUser = await User.create({ fullName, email, mobile, role });
    }

    const token = generateToken(existingUser);
    setCookie(res, token);

    return res.status(200).json({
      success: true,
      message: "User signed in successfully",
      user: {
        _id: existingUser._id,
        fullName: existingUser.fullName,
        email: existingUser.email,
        mobile: existingUser.mobile,
        role: existingUser.role
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error: " + error.message,
    });
  }
};

// Get user by ID (for internal service communication)
export const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId).select('-password -otp');
    
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({ success: true, user });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// Update user location (for delivery boys)
export const updateLocation = async (req, res) => {
  try {
    const { userId } = req.params;
    const { longitude, latitude } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      {
        location: {
          type: 'Point',
          coordinates: [longitude, latitude]
        }
      },
      { new: true }
    ).select('-password -otp');

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({ success: true, user });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// Find nearby delivery boys (for order service)
export const findNearbyDeliveryBoys = async (req, res) => {
  try {
    const { longitude, latitude, maxDistance = 5000 } = req.body;

    if (!longitude || !latitude) {
      return res.status(400).json({ 
        success: false, 
        message: "Longitude and latitude are required" 
      });
    }

    const deliveryBoys = await User.find({
      role: "deliveryBoy",
      location: {
        $near: {
          $geometry: { type: "Point", coordinates: [longitude, latitude] },
          $maxDistance: maxDistance,
        },
      },
    }).select('-password -otp');

    return res.status(200).json({ 
      success: true, 
      data: deliveryBoys 
    });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// Update user OTP (for delivery confirmation)
export const updateUserOtp = async (req, res) => {
  try {
    const { userId, otp, expiresIn } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({ 
        success: false, 
        message: "userId and otp are required" 
      });
    }

    const user = await User.findByIdAndUpdate(
      userId,
      {
        otp: otp,
        isOtpExpired: Date.now() + (expiresIn || 10 * 60 * 1000) // Default 10 minutes
      },
      { new: true }
    ).select('-password');

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({ 
      success: true, 
      message: "OTP updated successfully" 
    });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// Verify delivery OTP
export const verifyDeliveryOtp = async (req, res) => {
  try {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
      return res.status(400).json({ 
        success: false, 
        message: "userId and otp are required" 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    if (user.isOtpExpired < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }

    // Clear OTP after successful verification
    user.otp = undefined;
    user.isOtpExpired = undefined;
    await user.save();

    return res.status(200).json({ 
      success: true, 
      message: "OTP verified successfully" 
    });
  } catch (error) {
    console.error(error.message || error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};
