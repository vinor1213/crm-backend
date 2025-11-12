import Joi from 'joi';

export const createLeadSchema = Joi.object({
  instituteId: Joi.string().required(), 
  program: Joi.string().required(),
  candidateName: Joi.string().required(),
  ugDegree: Joi.string().optional(),
  phoneNumber: Joi.string().optional(),
  dateOfBirth: Joi.date().optional(),
  country: Joi.string().optional(),
  state: Joi.string().optional(),
  city: Joi.string().optional(),
  status: Joi.string().optional(),
  communication: Joi.string().optional(),
  followUpDate: Joi.date().optional(),
  description: Joi.string().optional(),
});
