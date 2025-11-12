import Joi from 'joi';

export const createInstitutionSchema = Joi.object({
  name: Joi.string().required(),
  country: Joi.string().required(),
  state: Joi.string().optional(),
  location: Joi.string().optional(),
  contactPerson: Joi.string().optional(),
  email: Joi.string().email().optional(),
  phoneNo: Joi.string().optional(),
  instituteType: Joi.string().optional(),
  status: Joi.string().valid('active', 'inactive').default('active'),
});
