import mongoose, { Document, Schema } from 'mongoose'

export interface IFormField {
  fieldType: string
  maxLength?: number
  fieldName: string
  fieldFor: 'Personal' | 'Education'
  sectionName?: string
  visibility: 'Yes' | 'No'
  required: boolean
  options?: string[]
}

export interface IFormManager extends Document {
  instituteId: string
  personalFields: IFormField[]
  educationFields: IFormField[]
}

const FieldSchema = new Schema<IFormField>(
  {
    fieldType: { type: String, required: true },
    maxLength: { type: Number },
    fieldName: { type: String, required: true },
    fieldFor: { type: String, enum: ['Personal', 'Education'], required: true },
    sectionName: { type: String },
    visibility: { type: String, enum: ['Yes', 'No'], default: 'Yes' },
    required: { type: Boolean, default: false },
    options: [{ type: String }]
  },
  { _id: false }
)

const FormManagerSchema = new Schema<IFormManager>(
  {
    instituteId: { type: String, required: true },
    personalFields: [FieldSchema],
    educationFields: [FieldSchema]
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
)

FormManagerSchema.virtual('institute', {
  ref: 'Institute',
  localField: 'instituteId',
  foreignField: '_id',
  justOne: true
})

export default mongoose.model<IFormManager>('FormManager', FormManagerSchema)
