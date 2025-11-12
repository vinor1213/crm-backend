import mongoose, { Document, Schema } from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";
import crypto from "crypto";

export interface IApplication extends Document {
  applicationId: string;
  instituteId: string;
  program: string;
  userId?: string;
  leadId?: string;
  academicYear: string;
  personalData: Record<string, any>;
  educationData: Record<string, any>;
  applicantName: string;
  courseCode: string;
  paymentStatus: "Paid" | "Unpaid" | "Partially";
  status: "Pending" | "Approved" | "Rejected";
  submittedAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

const ApplicationSchema = new Schema<IApplication>(
  {
    applicationId: { type: String, unique: true, index: true },
    instituteId: { type: String, required: true },
    program: { type: String, required: true },
    userId: { type: String },
    leadId: { type: String },
    academicYear: { type: String, required: true },
    personalData: { type: Schema.Types.Mixed, default: {} },
    educationData: { type: Schema.Types.Mixed, default: {} },
    applicantName: { type: String, required: true },
    courseCode: { type: String, },
    paymentStatus: {
      type: String,
      enum: ["Paid", "Unpaid", "Partially"],
      default: "Unpaid",
    },
    status: {
      type: String,
      enum: ["Pending", "Approved", "Rejected"],
      default: "Pending",
    },
    submittedAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual: Populate institute info
ApplicationSchema.virtual("institute", {
  ref: "Institution",
  localField: "instituteId",
  foreignField: "instituteId",
  justOne: true,
});

/** 
 * 🔹 Pre-save hook to auto-generate unique applicationId
 * Format: <instituteId>-APP-<randomString>
 */
ApplicationSchema.pre<IApplication>("save", async function (next) {
  if (!this.applicationId) {
    const randomStr = crypto.randomBytes(3).toString("hex").toUpperCase(); // e.g. 3FA9B2
    this.applicationId = `${this.instituteId}-APP-${randomStr}`;

    // Ensure uniqueness (rare collisions)
    const existing = await mongoose.models.Application.findOne({
      applicationId: this.applicationId,
    });
    if (existing) {
      this.applicationId = `${this.instituteId}-APP-${crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase()}`;
    }
  }
  next();
});

// Add pagination plugin
ApplicationSchema.plugin(mongoosePaginate);

// Export typed model
export interface IApplicationModel
  extends mongoose.PaginateModel<IApplication> { }

const Application = mongoose.model<IApplication, IApplicationModel>(
  "Application",
  ApplicationSchema
);

export default Application;
