import Joi from 'joi'

export const createApplicationSchema = Joi.object({
  instituteId: Joi.string().required().messages({
    'any.required': 'Institute ID is required',
    'string.empty': 'Institute ID cannot be empty'
  }),
  program: Joi.string().required().messages({
    'any.required': 'Program is required',
    'string.empty': 'Program cannot be empty',
  }),
  academicYear: Joi.string().required().messages({
    'any.required': 'Academic year is required'
  }),

  personalData: Joi.object().required().messages({
    'object.base': 'Personal data must be an object',
    'any.required': 'Personal data is required'
  }),

  educationData: Joi.object().optional().messages({
    'object.base': 'Education data must be an object'
  }),

  status: Joi.string().valid('Pending', 'Approved', 'Rejected').optional(),

  submittedAt: Joi.date().optional()
})
