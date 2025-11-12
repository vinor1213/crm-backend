import Joi from 'joi'

export const fieldSchema = Joi.object({
  fieldType: Joi.string().required(),
  maxLength: Joi.number().allow(null, '').optional(),
  fieldName: Joi.string().required(),
  fieldFor: Joi.string().valid('Personal', 'Education').required(),
  sectionName: Joi.string().allow(''),
  visibility: Joi.string().valid('Yes', 'No').default('Yes'),
  required: Joi.boolean().default(false),
  options: Joi.array().items(Joi.string()).optional()
})

export const createFormManagerSchema = Joi.object({
  instituteId: Joi.string().required(),
  personalFields: Joi.array().items(fieldSchema).default([]),
  educationFields: Joi.array().items(fieldSchema).default([])
})
