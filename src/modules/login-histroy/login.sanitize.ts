import Joi from 'joi';

export const createLoginHistorySchema = Joi.object({
  instituteId: Joi.string().required(), 
  userId: Joi.string().required(),      
  role: Joi.string().required(),
  lastLoginTime: Joi.date().optional(), 
});
