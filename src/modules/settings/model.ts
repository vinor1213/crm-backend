import mongoose, { Document, Schema } from 'mongoose';

export interface ISettings extends Document {
  instituteId: string;
  logo?: string; // Base64 string for institute logo
  courses?: string[]; // Array of course names or IDs
  merchantId?: string;
  apiKey?: string;
  authToken?: string;
  contactEmail?: string;
  contactNumber?: string;
  address?: string;
}

const SettingsSchema = new Schema<ISettings>(
  {
    instituteId: { type: String, required: true, unique: true },
    logo: { type: String }, // Base64 encoded logo
    courses: [{ type: String }], // Multiple courses or course IDs
    merchantId: { type: String },
    apiKey: { type: String },
    authToken: { type: String },
    contactEmail: { type: String },
    contactNumber: { type: String },
    address: { type: String },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

const Settings = mongoose.model<ISettings>('Settings', SettingsSchema);

export default Settings;
