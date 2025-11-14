import express from "express";
import { createOtp, verifyOtp, deleteOtpByEmail } from "./controller";

const router = express.Router();

router.post("/create", createOtp);
router.post("/verify", verifyOtp);
router.delete("/:email", deleteOtpByEmail);

export default router;
