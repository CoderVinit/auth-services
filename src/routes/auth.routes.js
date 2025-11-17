import express from "express";
import {
  signUp,
  signIn,
  signOut,
  sendOtp,
  verifyOtp,
  resetPassword,
  googleAuth,
  getUserById,
  updateLocation,
  findNearbyDeliveryBoys,
  updateUserOtp,
  verifyDeliveryOtp
} from "../controllers/auth.controller.js";

const router = express.Router();

// Simple ping for gateway proxy diagnostics
router.get('/ping', (req, res) => {
  res.json({ ok: true, service: 'auth', timestamp: new Date().toISOString() });
});

router.post("/signup", signUp);
router.post("/signin", signIn);
router.post("/signout", signOut);
router.post("/send-otp", sendOtp);
router.post("/verify-otp", verifyOtp);
router.post("/reset-password", resetPassword);
router.post("/google-auth", googleAuth);

// Internal routes for service-to-service communication
router.get("/user/:userId", getUserById);
router.patch("/users/:userId/location", updateLocation);
router.post("/nearby-delivery-boys", findNearbyDeliveryBoys);
router.post("/update-otp", updateUserOtp);
router.post("/verify-delivery-otp", verifyDeliveryOtp);

export default router;
