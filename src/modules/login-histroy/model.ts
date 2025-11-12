import mongoose, { Document, Schema } from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2';

export interface ILoginHistory extends Document {
  instituteId: string;
  userId: mongoose.Types.ObjectId;
  role: string;
  lastLoginTime: Date;
}

const LoginHistorySchema = new Schema<ILoginHistory>(
  {
    instituteId: { type: String, required: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, required: true },
    lastLoginTime: { type: Date, required: true },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Virtual to populate user details
LoginHistorySchema.virtual('user', {
  ref: 'User',
  localField: 'userId',
  foreignField: '_id',
  justOne: true,
});

// Add pagination plugin
LoginHistorySchema.plugin(mongoosePaginate);

const LoginHistory = mongoose.model<ILoginHistory, mongoose.PaginateModel<ILoginHistory>>(
  'LoginHistory',
  LoginHistorySchema
);

export default LoginHistory;
