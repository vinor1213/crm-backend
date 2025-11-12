import mongoose, { Document, Schema } from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";
import crypto from "crypto";

export interface ILead extends Document {
  leadId: string;
  instituteId: string;
  applicationId?: string;
  program: string;
  candidateName: string;
  ugDegree?: string;
  phoneNumber?: string;
  dateOfBirth?: Date;
  country?: string;
  state?: string;
  city?: string;
  status?: string;
  communication?: string;
  followUpDate?: Date;
  description?: string;
  createdBy: mongoose.Types.ObjectId;
}

const LeadSchema = new Schema<ILead>(
  {
    leadId: { type: String, unique: true, index: true },
    instituteId: { type: String, required: true },
    program: { type: String, required: true },
    candidateName: { type: String, required: true },
    ugDegree: { type: String },
    applicationId: { type: String },
    phoneNumber: { type: String },
    dateOfBirth: { type: Date },
    country: { type: String },
    state: { type: String },
    city: { type: String },
    status: { type: String, default: "New" },
    communication: { type: String },
    followUpDate: { type: Date },
    description: { type: String },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

LeadSchema.virtual("creator", {
  ref: "User",
  localField: "createdBy",
  foreignField: "_id",
  justOne: true,
});

LeadSchema.pre<ILead>("save", async function (next) {
  if (!this.leadId) {

    const randomStr = crypto.randomBytes(3).toString("hex").toUpperCase(); // e.g. "2F9C7A"

    this.leadId = `${this.instituteId}-LE-${randomStr}`;


    const existing = await mongoose.models.Lead.findOne({ leadId: this.leadId });
    if (existing) {

      this.leadId = `${this.instituteId}-LE-${crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase()}`;
    }
  }
  next();
});

LeadSchema.plugin(mongoosePaginate);

export default mongoose.model<ILead, mongoose.PaginateModel<ILead>>("Lead", LeadSchema);
