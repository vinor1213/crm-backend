import mongoose, { Document, Schema } from "mongoose";

export interface IPermission extends Document {
  instituteId: string;
  role: "admin" | "user";
  permissions: {
    moduleName: string;
    view: boolean;
    create: boolean;
    edit: boolean;
    delete: boolean;
    filter: boolean;
    download: boolean;
  }[];
}

const PermissionSchema = new Schema<IPermission>(
  {
    instituteId: { type: String, required: true },
    role: { type: String, required: true, enum: ["admin", "user"] },
    permissions: [
      {
        moduleName: { type: String, required: true },
        view: { type: Boolean, default: false },
        create: { type: Boolean, default: false },
        edit: { type: Boolean, default: false },
        delete: { type: Boolean, default: false },
        filter: { type: Boolean, default: false },
        download: { type: Boolean, default: false },
      },
    ],
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ✅ Each institute has only one permission set per role
PermissionSchema.index({ instituteId: 1, role: 1 }, { unique: true });

const Permission =
  mongoose.models.Permission ||
  mongoose.model<IPermission>("Permission", PermissionSchema);

export default Permission;
