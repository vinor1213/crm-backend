import Joi from 'joi';

export const passwordSchema = Joi.string().min(6).max(128).required();
export const emailSchema = Joi.string().email().required();
