import Joi from 'joi';

export const settingsSchema = Joi.object({
  instituteId: Joi.string().required().messages({
    'any.required': 'Institute ID is required',
    'string.empty': 'Institute ID cannot be empty',
  }),

  logo: Joi.string()
    .pattern(/^data:image\/(png|jpg|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/)
    .optional()
    .messages({
      'string.pattern.base':
        'Logo must be a valid Base64-encoded image (png, jpg, jpeg, gif, webp)',
    }),

  courses: Joi.array().items(Joi.string()).optional().messages({
    'array.base': 'Courses must be an array of strings',
  }),

  merchantId: Joi.string().optional(),
  apiKey: Joi.string().optional(),
  authToken: Joi.string().optional(),

  contactEmail: Joi.string().email().optional().messages({
    'string.email': 'Contact email must be a valid email address',
  }),

  contactNumber: Joi.string()
    .pattern(/^[0-9+\-\s()]{7,20}$/)
    .optional()
    .messages({
      'string.pattern.base': 'Contact number must be valid',
    }),

  address: Joi.string().optional(),
});
