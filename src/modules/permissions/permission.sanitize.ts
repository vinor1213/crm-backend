import Joi from "joi";

export const createOrUpdatePermissionSchema = Joi.object({
  instituteId: Joi.string().required().messages({
    "any.required": "Institute ID is required",
  }),

  role: Joi.string()
    .valid("admin", "user")
    .required()
    .messages({
      "any.only": "Role must be either Admin or User",
      "any.required": "Role is required",
    }),

  permissions: Joi.array()
    .items(
      Joi.object({
        moduleName: Joi.string().required().messages({
          "any.required": "Module name is required",
        }),
        view: Joi.boolean().default(false),
        create: Joi.boolean().default(false),
        edit: Joi.boolean().default(false),
        delete: Joi.boolean().default(false),
        filter: Joi.boolean().default(false),
        download: Joi.boolean().default(false),
      })
    )
    .required()
    .messages({
      "array.base": "Permissions must be an array",
      "any.required": "Permissions are required",
    }),
});
