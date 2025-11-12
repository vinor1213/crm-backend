import { Request, Response } from 'express'
import FormManager from './model' // <-- your FormManager model file
import { AuthRequest } from '../../middlewares/auth' // adjust path as needed
import { createFormManagerSchema } from './form.sanitize'

/**
 * @desc Create or update form configuration for an institute
 * @route POST /api/form-manager
 * @access Admin / Superadmin
 */
export const createOrUpdateFormManager = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) {
      return res.status(401).json({ success: false, message: 'Not authorized' })
    }

    // ✅ Validate input
    const { error, value } = createFormManagerSchema.validate(req.body, { allowUnknown: true })
    if (error) {
      return res.status(400).json({ success: false, message: error.message })
    }

    const { instituteId, personalFields, educationFields } = value

    if (!instituteId) {
      return res.status(400).json({ success: false, message: 'Institute ID is required' })
    }

    // ✅ Check if a record already exists for this institute
    const existingForm = await FormManager.findOne({ instituteId })

    let form
    if (existingForm) {

      existingForm.personalFields = personalFields
      existingForm.educationFields = educationFields
      form = await existingForm.save()
    } else {

      form = await FormManager.create({
        instituteId,
        personalFields,
        educationFields
      })
    }

    return res.status(200).json({
      success: true,
      message: existingForm
        ? 'Form configuration updated successfully'
        : 'Form configuration created successfully',
      data: form
    })
  } catch (error: any) {
    console.error('Error saving form configuration:', error)
    return res.status(500).json({
      success: false,
      message: 'Server error while saving form configuration',
      error: error.message
    })
  }
}

/**
 * @desc Get form configuration (per institute)
 * @route GET /api/form-manager
 * @access Admin / Superadmin / User
 */
export const listFormManagers = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) return res.status(401).json({ message: 'Not authorized' })

    const { instituteId } = req.query
    const filter: any = {}

    if (user.role === 'superadmin') {
      if (instituteId) filter.instituteId = instituteId
    } else {
      // Admins / Users can only see their institute
      filter.instituteId = user.instituteId
    }

    const forms = await FormManager.find(filter).sort({ createdAt: -1 })

    res.status(200).json({
      success: true,
      count: forms.length,
      data: forms
    })
  } catch (error: any) {
    console.error('Error fetching form managers:', error)
    res.status(500).json({
      success: false,
      message: 'Server error while fetching forms',
      error: error.message
    })
  }
}

export const getFormManagerByInstituteId = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) return res.status(401).json({ success: false, message: 'Not authorized' })

    const { instituteId } = req.params

    if (!instituteId) {
      return res.status(400).json({ success: false, message: 'Institute ID is required' })
    }

  
    if (user.role !== 'superadmin' && user.instituteId !== instituteId) {
      return res.status(403).json({ success: false, message: 'Access denied' })
    }

    const form = await FormManager.findOne({ instituteId })

    if (!form) {
      return res.status(404).json({ success: false, message: 'Form configuration not found' })
    }

    return res.status(200).json({
      success: true,
      data: form
    })
  } catch (error: any) {
    console.error('Error fetching form configuration by instituteId:', error)
    return res.status(500).json({
      success: false,
      message: 'Server error while fetching form configuration',
      error: error.message
    })
  }
}

/**
 * @desc Delete a form configuration (if needed)
 * @route DELETE /api/form-manager/:id
 * @access Superadmin / Admin
 */
export const deleteFormManager = async (req: AuthRequest, res: Response) => {
  try {
    const user = req.user
    if (!user) return res.status(401).json({ message: 'Not authorized' })

    const { id } = req.params

    const deleted = await FormManager.findByIdAndDelete(id)

    if (!deleted) {
      return res.status(404).json({ success: false, message: 'Form configuration not found' })
    }

    res.status(200).json({
      success: true,
      message: 'Form configuration deleted successfully'
    })
  } catch (error: any) {
    console.error('Error deleting form manager:', error)
    res.status(500).json({
      success: false,
      message: 'Server error while deleting form configuration',
      error: error.message
    })
  }
}
