import Joi from "joi";

export const otpSchema = Joi.object({
  email: Joi.string().email().required(),
  // otp: Joi.string().min(4).max(10).required(),
});
