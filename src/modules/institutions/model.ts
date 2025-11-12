import mongoose, { Document, Schema } from "mongoose";
import { nanoid } from "nanoid";
import mongoosePaginate from "mongoose-paginate-v2";

export interface IInstitution extends Document {
  instituteId: string;
  name: string;
  country: string;
  state?: string;
  location?: string;
  contactPerson?: string;
  email?: string;
  phoneNo?: string;
  instituteType?: string;
  status: "active" | "inactive";
  createdBy: mongoose.Types.ObjectId;
}

const InstitutionSchema = new Schema<IInstitution>(
  {
    instituteId: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    country: { type: String, required: true },
    state: { type: String },
    location: { type: String },
    contactPerson: { type: String },
    email: { type: String },
    phoneNo: { type: String },
    instituteType: { type: String },
    status: {
      type: String,
      enum: ["active", "inactive"],
      default: "inactive",
    },
    createdBy: { type: Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
  
);


InstitutionSchema.pre("validate", async function (next) {
  if (this.isNew && !this.instituteId) {
    this.instituteId = `INS-${nanoid(8).toUpperCase()}`;
  }
  next();
});


InstitutionSchema.plugin(mongoosePaginate);


const Institution = mongoose.model<IInstitution, mongoose.PaginateModel<IInstitution>>(
  "Institution",
  InstitutionSchema
);

export default Institution;
